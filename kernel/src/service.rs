// SPDX-License-Identifier: Apache-2.0
//! The services an unprivileged program is given, and nothing more.
//!
//! A program in ring 3 can do three things by itself: compute, touch its own
//! memory, and make a system call. Everything else — printing a character,
//! reading a name from a filesystem — belongs to something else, and it gets
//! there by asking, over IPC, through a capability it was given.
//!
//! These are those somethings. Each is a kernel thread sitting in `recv` on an
//! endpoint, answering one message at a time.
//!
//! # Why they are in the kernel, for now
//!
//! `docs/architecture.md` §2 says a service should be able to run in the
//! kernel or in its own domain, chosen at build time, and that the interface
//! must not know which. These run in the kernel because there is no way to
//! start a second user-mode program yet. What keeps that honest is that the
//! *interface* is already the one a separate domain would use: a capability,
//! an endpoint, and four registers. Moving them out later changes where the
//! thread is spawned and nothing about what a caller does.
//!
//! # No pointer crosses the boundary
//!
//! Every byte travels in message registers, sixteen at a time. That is slow,
//! and it means the kernel never dereferences an address a caller chose — so
//! nothing here can be talked into reading or writing memory on a caller's
//! behalf. When shared memory arrives, that property has to be reargued
//! rather than assumed; today it is free.
//!
//! # One caller at a time, and it is a real limit
//!
//! Each service is a single thread. While the console service is blocked
//! waiting for someone to type, it is not answering writes — which is correct
//! with one shell and would deadlock two. Sessions are keyed by badge and
//! bounded at [`MAX_SESSIONS`], so a second caller is refused rather than
//! quietly given the first one's open file.

use bhaskix_abi::{Chunk, fs, outcome, with_outcome};
pub use bhaskix_service::{Reply, Request, Service, StartError};
use bhaskix_service_console::{Console, Ports};

use crate::{ipc, sched, ustar, vfs};

/// Callers the filesystem service will keep state for.
///
/// Two, so that "another caller is refused" is reachable in a test rather than
/// theoretical. A real system's limit is a resource envelope; this is a
/// service that has not needed one yet and says so.
pub const MAX_SESSIONS: usize = 2;

/// Longest path a caller may accumulate.
pub const MAX_PATH: usize = 64;

/// Where the console service's endpoint is, once created.
static CONSOLE_ENDPOINT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);
/// Where the filesystem service's endpoint is.
static FS_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Bytes the console service has written and read on behalf of callers.
static WRITTEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static READ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Requests the filesystem service has answered.
static REQUESTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Callers it turned away for want of a session.
static REFUSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// What the services have done: written, read, requests, callers refused.
#[must_use]
pub fn statistics() -> (u64, u64, u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (
        WRITTEN.load(Relaxed),
        READ.load(Relaxed),
        REQUESTS.load(Relaxed),
        REFUSED.load(Relaxed),
    )
}

/// The endpoint a caller reaches the console through.
#[must_use]
pub fn console_endpoint() -> Option<ipc::EndpointId> {
    let raw = CONSOLE_ENDPOINT.load(core::sync::atomic::Ordering::Acquire);
    (raw != u64::MAX).then(|| ipc::EndpointId::from_u32(raw as u32))
}

/// The endpoint a caller reaches the filesystem through.
#[must_use]
pub fn filesystem_endpoint() -> Option<ipc::EndpointId> {
    let raw = FS_ENDPOINT.load(core::sync::atomic::Ordering::Acquire);
    (raw != u64::MAX).then(|| ipc::EndpointId::from_u32(raw as u32))
}

/// Creates both endpoints and spawns both services.
///
/// The console service is pinned to `cpu`, which must be the CPU the serial
/// interrupt is routed to: it is the thread that blocks in `input::read`, and
/// `input`'s wake-up argument depends on the reader and the handler sharing a
/// processor.
///
/// # Errors
///
/// Returns `Err` if an endpoint or a thread could not be created.
pub fn start(cpu: u32, hhdm_base: u64) -> Result<(), &'static str> {
    let console = ipc::create().map_err(|_| "no endpoint for the console")?;
    let filesystem = ipc::create().map_err(|_| "no endpoint for the filesystem")?;

    use core::sync::atomic::Ordering::Release;
    CONSOLE_ENDPOINT.store(u64::from(console.as_u32()), Release);
    FS_ENDPOINT.store(u64::from(filesystem.as_u32()), Release);

    let pinned = sched::SpawnOptions::new().pinned();
    sched::spawn_on_with(cpu, "console", console_service, 0, hhdm_base, pinned)
        .map_err(|_| "the console service would not spawn")?;
    // The filesystem service is not pinned: it blocks on nothing but its own
    // endpoint, so it may run wherever there is room.
    sched::spawn("fs", filesystem_service, 0, hhdm_base)
        .map_err(|_| "the filesystem service would not spawn")?;

    // Named with their placement, because the placement is the claim. Step 3
    // is the first time one of these says something other than `nucleus` --
    // so a line that never changes would be a line worth distrusting.
    crate::println!(
        "    placement      {}={PLACEMENT} {}={PLACEMENT}, dispatched by message",
        Console::NAME,
        Filesystem::NAME
    );
    Ok(())
}

/// Where the services in this build run.
///
/// Both are in the nucleus, which is what `services.toml` says. It stays a
/// constant here and not a generated one: a build script that read the table
/// and produced this string would make the boot line agree with the table by
/// construction, and a line that cannot disagree cannot report anything. The
/// table is checked against the crates by `tools/check-placements.sh`; this
/// line is checked against reality by being printed.
pub const PLACEMENT: &str = "nucleus";

/// What the filesystem may reach.
///
/// The direct map base, for the bulk path, and nothing else. This is the one
/// field a domain placement will not have, which makes it the field to watch:
/// a service that reaches for it outside a bulk path has stopped being
/// relocatable, and `services.toml` records — in the file, not in a comment —
/// that this service has not been moved out of the kernel yet because of it.
#[derive(Clone, Copy)]
pub struct Direct {
    /// Where physical memory is mapped.
    pub hhdm: u64,
}

/// Runs a service in the nucleus placement, for ever.
///
/// Dispatch is through IPC and not by direct call, which RFC 0013 decided on
/// acceptance: a direct call is faster and is also the door through which "no
/// direct calls" erodes, and a design that starts with the fast path never
/// gets the slow one back. So the two placements differ in *placement* and not
/// in *shape*, which is the whole claim being made.
fn run<S: Service>(endpoint: ipc::EndpointId, context: S::Context) -> ! {
    let Ok(mut state) = S::start(context) else {
        sched::exit()
    };

    loop {
        let Ok((message, caller)) = ipc::recv(endpoint) else {
            sched::exit()
        };
        REQUESTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let reply = S::handle(
            &mut state,
            &context,
            Request {
                method: message.method,
                args: &message.args,
                badge: message.badge,
                caller,
            },
        );

        // The method comes back so a caller can tell replies apart; the badge
        // does not, because a reply's badge would be the service claiming an
        // identity rather than reporting one.
        let _ = ipc::reply(
            caller,
            ipc::Message {
                method: message.method,
                args: reply.args,
                badge: 0,
            },
        );
    }
}

/// Answers the console endpoint, for ever.
extern "C" fn console_service(_argument: u64) -> ! {
    let Some(endpoint) = console_endpoint() else {
        sched::exit()
    };
    run::<Console>(endpoint, console_ports())
}

/// What the console gets to reach, built out of the kernel's own routines.
///
/// The whole of the nucleus placement for this service: four functions. In a
/// domain these become calls out to a driver, and the console itself does not
/// change — which is the claim RFC 0013 makes, and the reason the console is
/// the first service to be compiled apart from the kernel.
fn console_ports() -> Ports {
    use core::sync::atomic::Ordering::Relaxed;
    Ports {
        put: |character| crate::print!("{character}"),
        read: crate::input::read,
        try_read: crate::input::try_read,
        counted: |written, read| {
            WRITTEN.fetch_add(written, Relaxed);
            READ.fetch_add(read, Relaxed);
        },
    }
}

/// What one caller of the filesystem service is in the middle of.
///
/// Public because it is the filesystem's `Service::State`, and a service's
/// state is part of its interface: the placement holds it.
#[derive(Clone, Copy)]
pub struct Session {
    /// The badge on the capability this caller used, or zero for a free slot.
    badge: u64,
    path: [u8; MAX_PATH],
    path_length: usize,
    /// Set when the path was longer than [`MAX_PATH`].
    path_overflowed: bool,
    open: Option<vfs::File>,
    /// How many entries of the current listing have been returned.
    listed: usize,
    /// How much of the current entry's name has been returned.
    name_offset: usize,
    listing: bool,
}

impl Session {
    const fn empty() -> Self {
        Self {
            badge: 0,
            path: [0; MAX_PATH],
            path_length: 0,
            path_overflowed: false,
            open: None,
            listed: 0,
            name_offset: 0,
            listing: false,
        }
    }

    /// Forgets everything about this caller, including that it exists.
    ///
    /// Releasing the slot rather than only the state is what makes
    /// [`MAX_SESSIONS`] a limit on *concurrent* callers rather than on callers
    /// ever. The first version kept the badge, so the boot self-test's two
    /// test callers held both slots for the rest of the machine's life and the
    /// shell was refused before it started — which is exactly the failure a
    /// service with no idea when a caller has finished will always have.
    fn release(&mut self) {
        *self = Self::empty();
    }

    /// Forgets the path, the open file and the listing, keeping the session.
    fn reset(&mut self) {
        let badge = self.badge;
        *self = Self::empty();
        self.badge = badge;
    }
}

/// The filesystem: a session per caller, and a file open in each.
pub struct Filesystem;

impl Service for Filesystem {
    /// One session per caller. Not a static: there is one service, so there is
    /// no second holder and nothing to lock -- and a static would be a claim
    /// that something else might touch it. Under the trait it is also the
    /// thing that makes the domain placement possible, because state that
    /// hangs off the service moves with it and a static does not.
    type State = [Session; MAX_SESSIONS];
    const NAME: &'static str = "vfs";

    type Context = Direct;

    fn start(_direct: Self::Context) -> Result<Self::State, StartError> {
        Ok([Session::empty(); MAX_SESSIONS])
    }

    fn handle(sessions: &mut Self::State, _direct: &Self::Context, request: Request<'_>) -> Reply {
        // A caller with no badge cannot be told apart from any other, and a
        // service that gave them all one session would let a second program
        // read the first one's open file. Zero is also the free-slot sentinel
        // below, so accepting it would hand out a slot that everything else
        // still considers free -- the kind of aliasing that shows up as a file
        // handle changing under a caller who did nothing.
        if request.badge == 0 {
            return Reply::new([with_outcome(0, outcome::UNIDENTIFIED), 0, 0, 0]);
        }
        match session_for(sessions, request.badge) {
            Some(session) => {
                Reply::new(serve(session, request.caller, request.method, request.args))
            }
            None => {
                REFUSED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                Reply::new([with_outcome(0, outcome::BUSY), 0, 0, 0])
            }
        }
    }
}

/// Answers the filesystem endpoint, for ever.
extern "C" fn filesystem_service(_argument: u64) -> ! {
    let Some(endpoint) = filesystem_endpoint() else {
        sched::exit()
    };
    run::<Filesystem>(
        endpoint,
        Direct {
            hhdm: crate::shared::hhdm(),
        },
    )
}

/// Finds this caller's session, or claims a free one.
///
/// Keyed by badge, which is the only thing about a caller the service can
/// trust: the sender does not choose it, the kernel copies it from the
/// capability that was used (`docs/security.md` §2). A caller cannot reach
/// another's open file by claiming to be them, because it cannot say who it
/// is at all.
///
/// `badge` must not be zero — the caller checks, because zero is this table's
/// "free slot" marker and a zero-badged caller would be handed a slot that
/// every other caller still considers free.
fn session_for(sessions: &mut [Session; MAX_SESSIONS], badge: u64) -> Option<&mut Session> {
    if let Some(index) = sessions.iter().position(|session| session.badge == badge) {
        return Some(&mut sessions[index]);
    }
    let index = sessions.iter().position(|session| session.badge == 0)?;
    sessions[index] = Session::empty();
    sessions[index].badge = badge;
    Some(&mut sessions[index])
}

fn serve(session: &mut Session, caller: u32, method: u64, args: &[u64; 4]) -> [u64; 4] {
    match method {
        fs::PATH => {
            let chunk = Chunk::unpack(args);
            for byte in chunk.bytes() {
                if session.path_length == MAX_PATH {
                    // Recorded, not truncated silently: a path that was cut
                    // short still names *something*, and opening whatever that
                    // turned out to be is how a caller ends up reading a file
                    // it did not ask for.
                    session.path_overflowed = true;
                    break;
                }
                session.path[session.path_length] = *byte;
                session.path_length += 1;
            }
            [with_outcome(chunk.len() as u64, outcome::OK), 0, 0, 0]
        }

        fs::OPEN => {
            if session.path_overflowed {
                session.reset();
                return [with_outcome(0, outcome::BAD_PATH), 0, 0, 0];
            }
            let path = &session.path[..session.path_length];
            match vfs::open(path) {
                Ok(file) => {
                    let size = file.len() as u64;
                    session.open = Some(file);
                    session.path_length = 0;
                    [with_outcome(0, outcome::OK), 0, 0, size]
                }
                Err(error) => {
                    session.reset();
                    [with_outcome(0, reason(error)), 0, 0, 0]
                }
            }
        }

        fs::READ => {
            let Some(file) = session.open.as_mut() else {
                return [with_outcome(0, outcome::NOTHING_OPEN), 0, 0, 0];
            };
            let mut bytes = [0u8; bhaskix_abi::CHUNK_BYTES];
            let read = file.read(&mut bytes);
            let (chunk, _) = Chunk::take(&bytes[..read]);
            chunk.pack(0)
        }

        fs::READ_INTO => {
            let Some(file) = session.open.as_mut() else {
                return [with_outcome(0, outcome::NOTHING_OPEN), 0, 0, 0];
            };

            // The caller names a slot in **its own** CSpace, not an object
            // identity. Naming an identity would be a caller asserting what it
            // may reach; naming a slot is a caller pointing at authority it
            // already holds, which the service then checks -- the same shape
            // the capability syscalls use, and the reason this cannot be used
            // to read into somebody else's memory.
            let Some(object) = crate::shared::caller_object(caller, args[0]) else {
                return [with_outcome(0, outcome::NOT_YOURS), 0, 0, 0];
            };

            let limit = args[1] as usize;
            match crate::shared::fill_from(object, limit, |bytes| file.read(bytes)) {
                Some(written) => [with_outcome(written as u64, outcome::OK), 0, 0, 0],
                None => [with_outcome(0, outcome::NOT_YOURS), 0, 0, 0],
            }
        }

        fs::LIST => {
            if session.path_overflowed {
                session.reset();
                return [with_outcome(0, outcome::BAD_PATH), 0, 0, 0];
            }
            session.listing = true;
            list_entry(session)
        }

        // Releases the session, not just its state: this is the only signal a
        // caller gives that it is done. Nothing tells the service that a
        // caller has *died*, so a program that stops without a reset holds a
        // slot until the machine restarts. That is a real limitation and the
        // fix is a mechanism that does not exist yet -- an endpoint that
        // reports when the capability reaching it is revoked.
        fs::RESET => {
            session.release();
            [with_outcome(0, outcome::OK), 0, 0, 0]
        }

        _ => [with_outcome(0, outcome::WRONG_KIND), 0, 0, 0],
    }
}

/// Returns the next piece of the listing.
///
/// One entry per call, and a long name across several. The whole archive is
/// walked each time, which is quadratic in the number of entries and is
/// exactly as fast as it needs to be for a directory listing on a ramdisk —
/// but it is quadratic, and a filesystem with a real directory index should
/// not inherit this shape.
fn list_entry(session: &mut Session) -> [u64; 4] {
    let path = &session.path[..session.path_length];

    let mut wanted = session.listed;
    let mut found: Option<([u8; MAX_PATH], usize, u64, bool)> = None;
    vfs::list(path, |name, kind, size| {
        if found.is_some() {
            return;
        }
        if wanted > 0 {
            wanted -= 1;
            return;
        }
        let mut buffer = [0u8; MAX_PATH];
        let length = name.len().min(MAX_PATH);
        buffer[..length].copy_from_slice(&name[..length]);
        found = Some((
            buffer,
            length,
            size as u64,
            kind == ustar::EntryKind::Directory,
        ));
    });

    let Some((name, length, size, directory)) = found else {
        // End of the listing: no bytes and nothing to follow.
        session.listing = false;
        session.listed = 0;
        session.name_offset = 0;
        return [with_outcome(0, outcome::OK), 0, 0, 0];
    };

    let (chunk, rest) = Chunk::take(&name[session.name_offset..length]);
    if rest.is_empty() {
        session.listed += 1;
        session.name_offset = 0;
    } else {
        session.name_offset += chunk.len();
    }

    let metadata = bhaskix_abi::entry_metadata(size, directory);
    chunk.pack(metadata)
}

fn reason(error: vfs::VfsError) -> u64 {
    match error {
        vfs::VfsError::NotFound | vfs::VfsError::NotMounted => outcome::NOT_FOUND,
        vfs::VfsError::BadPath => outcome::BAD_PATH,
        vfs::VfsError::NotAFile => outcome::WRONG_KIND,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhaskix_abi::outcome_of;

    #[test]
    fn a_service_answers_a_method_it_does_not_know() {
        // RFC 0013's fourth rule, and the one a trait can actually enforce: a
        // malformed request is a *reply*, not an unwind. Runnable on the host
        // with no machine underneath it, which is most of the point of putting
        // a service's logic behind a trait.
        let args = [0u64; 4];
        let reply = Console::handle(
            &mut (),
            &console_ports(),
            Request {
                method: 0xdead_beef,
                args: &args,
                badge: 1,
                caller: 0,
            },
        );
        assert_eq!(outcome_of(reply.args[0]), outcome::WRONG_KIND);
    }

    #[test]
    fn the_filesystem_refuses_a_caller_it_cannot_tell_apart() {
        // Badge zero is both "no identity" and the free-slot sentinel, so
        // accepting it would hand out a session everything else still
        // considers free.
        let mut sessions = [Session::empty(); MAX_SESSIONS];
        let args = [0u64; 4];
        let reply = Filesystem::handle(
            &mut sessions,
            &Direct { hhdm: 0 },
            Request {
                method: fs::PATH,
                args: &args,
                badge: 0,
                caller: 0,
            },
        );
        assert_eq!(outcome_of(reply.args[0]), outcome::UNIDENTIFIED);
    }

    #[test]
    fn a_service_names_itself_for_the_placement_table() {
        // Step 2's table is keyed by these, so a rename is a build failure
        // rather than a service that quietly stops being placed.
        assert_eq!(Console::NAME, "console");
        assert_eq!(Filesystem::NAME, "vfs");
    }
}
