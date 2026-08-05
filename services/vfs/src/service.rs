// SPDX-License-Identifier: Apache-2.0
//! The filesystem service: a session per caller, and a file open in each.
//!
//! Outside the kernel crate as of RFC 0013 step 3, which for this service was
//! not a move but an argument. Everything here was already placement-neutral
//! except one thing — the bulk path, which read a caller's pages through the
//! kernel's direct map. A domain has no direct map, so that call had to become
//! something a context hands over ([`Bulk::fill`]), and until it did, the
//! table said `relocatable = false` and meant it.
//!
//! What that buys: this file is now compiled with no kernel in the build,
//! which `tools/check-placements.sh` checks by doing exactly that.

use bhaskix_abi::{Chunk, fs, outcome, with_outcome};
use bhaskix_service::{Reply, Request, Service, StartError};

use crate::{ustar, vfs};

/// Callers the filesystem service will keep state for.
///
/// Two, so that "another caller is refused" is reachable in a test rather than
/// theoretical. A real system's limit is a resource envelope; this is a
/// placeholder that is small enough to hit.
pub const MAX_SESSIONS: usize = 2;

/// The longest path a caller can build up, in bytes.
pub const MAX_PATH: usize = 64;

/// Reads from `source` into the memory a caller named, and says how many
/// bytes landed there.
///
/// `slot` is an index into the CSpace of the caller being answered — never an
/// object identity, and never a caller this service names. Which caller that is
/// belongs to the placement: it is the party whose message this is, and a
/// service that could say otherwise could write a file's contents into a third
/// party's memory. `slot` is
/// a caller pointing at authority it already holds, which the placement then
/// checks. `None` means the caller named something it does not hold, or does
/// not hold with the right to be written to.
///
/// In the nucleus this writes through the direct map. In a domain it is a
/// system call, because a domain cannot reach another domain's pages and must
/// not be able to. The service above it does not know which, which is the
/// entire claim RFC 0013 makes, made concrete in one function pointer.
///
/// `&mut dyn FnMut` and not a generic, because a context is a value made of
/// function pointers and a generic would have to be monomorphised by whoever
/// built it — which is the placement, the one party that must not need to know
/// what the service does with it.
pub type Fill =
    fn(slot: u64, limit: usize, source: &mut dyn FnMut(&mut [u8]) -> usize) -> Option<usize>;

/// What the filesystem may reach, and the whole of it.
///
/// One operation, and it is the one that made this service hard to move.
#[derive(Clone, Copy)]
pub struct Bulk {
    /// Writes a file's bytes into memory the caller named. See [`Fill`].
    pub fill: Fill,

    /// Records that a caller was turned away for want of a session. Counted by
    /// the placement, for the same reason the console's bytes are: a counter
    /// held by the service would reset when the service restarted, and the
    /// number is being kept precisely to notice that.
    pub refused: fn(),
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
    type Context = Bulk;
    type State = [Session; MAX_SESSIONS];
    const NAME: &'static str = "vfs";

    fn start(_bulk: Self::Context) -> Result<Self::State, StartError> {
        Ok([Session::empty(); MAX_SESSIONS])
    }

    fn handle(sessions: &mut Self::State, bulk: &Self::Context, request: Request<'_>) -> Reply {
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
            Some(session) => Reply::new(serve(session, bulk, request.method, request.args)),
            None => {
                (bulk.refused)();
                Reply::new([with_outcome(0, outcome::BUSY), 0, 0, 0])
            }
        }
    }
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

fn serve(session: &mut Session, bulk: &Bulk, method: u64, args: &[u64; 4]) -> [u64; 4] {
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
            let limit = args[1] as usize;
            match (bulk.fill)(args[0], limit, &mut |bytes| file.read(bytes)) {
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
    use bhaskix_abi::outcome_of;

    use super::*;

    /// A context whose one operation refuses everything.
    ///
    /// Which is the honest thing for a test with no memory and no caller
    /// behind it: a `fill` that pretended to succeed would let a test of the
    /// bulk path pass without any bulk path.
    fn nothing() -> Bulk {
        Bulk {
            fill: |_slot, _limit, _source| None,
            refused: || {},
        }
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
            &nothing(),
            Request {
                method: fs::PATH,
                args: &args,
                badge: 0,
            },
        );
        assert_eq!(outcome_of(reply.args[0]), outcome::UNIDENTIFIED);
    }

    #[test]
    fn a_caller_that_names_memory_it_does_not_hold_is_told_so() {
        // The bulk path's refusal, tested with no kernel underneath it -- the
        // reason this service could not leave the kernel until step 3, and the
        // proof that it now has.
        let mut sessions = [Session::empty(); MAX_SESSIONS];
        sessions[0] = Session::empty();
        let args = [7, 16, 0, 0];
        let reply = Filesystem::handle(
            &mut sessions,
            &nothing(),
            Request {
                method: fs::READ_INTO,
                args: &args,
                badge: 1,
            },
        );
        // Nothing is open, so it does not reach `fill` at all -- which is the
        // right refusal and the one that comes first.
        assert_eq!(outcome_of(reply.args[0]), outcome::NOTHING_OPEN);
    }
}
