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

pub use bhaskix_service::{Reply, Request, Service, StartError};
use bhaskix_service_console::Console;
#[cfg(not(console_in_domain))]
use bhaskix_service_console::Ports;
pub use bhaskix_service_vfs::{Bulk, Filesystem, MAX_PATH, MAX_SESSIONS};

use crate::ipc;
// Only the nucleus placement's run loop needs the scheduler; a build where
// every service is in a domain does not spawn a service thread at all.
#[cfg(any(not(console_in_domain), not(vfs_in_domain)))]
use crate::sched;

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

    // The console, wherever the table put it.
    #[cfg(not(console_in_domain))]
    {
        let pinned = sched::SpawnOptions::new().pinned();
        sched::spawn_on_with(cpu, "console", console_service, 0, hhdm_base, pinned)
            .map_err(|_| "the console service would not spawn")?;
    }
    #[cfg(console_in_domain)]
    crate::start_console_domain(cpu, hhdm_base)?;
    // The filesystem, wherever `services.toml` put it. One of these two lines
    // is compiled and the other is not, which is what makes the table a
    // decision rather than a description.
    #[cfg(not(vfs_in_domain))]
    // Pinned, since RFC 0013 step 5 measured what leaving it free costs: a
    // round trip to an unpinned service took **six times** longer than to a
    // pinned one, 66k cycles against 11k, reproducibly and at the minimum
    // rather than in the tail. It was unpinned because it blocks on nothing
    // but its own endpoint and could therefore run wherever there was room --
    // which was true, and turned every call into a wait for another CPU to
    // notice. The measurement is the whole reason this line changed; without
    // it the old comment was perfectly reasonable.
    sched::spawn_on_with(
        cpu,
        "fs",
        filesystem_service,
        0,
        hhdm_base,
        sched::SpawnOptions::new().pinned(),
    )
    .map_err(|_| "the filesystem service would not spawn")?;
    #[cfg(vfs_in_domain)]
    crate::start_vfs_domain(cpu, hhdm_base)?;

    // Reported from what was actually done, not from the table. A line
    // generated from the same file the build read would agree with it whatever
    // the machine did; `tests/qemu/boot-test.sh` compares this against
    // `services.toml`, and that comparison is only worth making because the two
    // could differ.
    crate::println!(
        "    placement      {}={} {}={}, dispatched by message",
        Console::NAME,
        CONSOLE_PLACEMENT,
        Filesystem::NAME,
        VFS_PLACEMENT
    );
    Ok(())
}

/// Where the console runs in this build.
///
/// In a domain it holds a `Console` capability: put a character, take a byte,
/// and nothing else. The driver stays in the kernel — moving *that* out is
/// step 6 — so what this placement buys is not a smaller kernel but a smaller
/// blast radius, which is the half worth having first.
#[cfg(console_in_domain)]
pub const CONSOLE_PLACEMENT: &str = "domain";
/// Where the console runs in this build.
#[cfg(not(console_in_domain))]
pub const CONSOLE_PLACEMENT: &str = "nucleus";

/// Where the filesystem runs in this build.
///
/// Two constants either side of a `cfg`, and not one string from the build
/// script, because this is what the kernel *did*: the same `cfg` chose between
/// spawning a thread and loading a program, and a service that failed to start
/// says so on its own line.
#[cfg(vfs_in_domain)]
pub const VFS_PLACEMENT: &str = "domain";
/// Where the filesystem runs in this build.
#[cfg(not(vfs_in_domain))]
pub const VFS_PLACEMENT: &str = "nucleus";

/// Runs a service in the nucleus placement, for ever.
///
/// Compiled out when every service is in a domain, which is a build where the
/// nucleus runs no service at all — the state RFC 0013 is aiming at, reached
/// here for the first time.
#[cfg(any(not(console_in_domain), not(vfs_in_domain)))]
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
#[cfg(not(console_in_domain))]
extern "C" fn console_service(_argument: u64) -> ! {
    let Some(endpoint) = console_endpoint() else {
        sched::exit()
    };
    run::<Console>(endpoint, console_ports())
}

/// Answers the filesystem endpoint, for ever.
#[cfg(not(vfs_in_domain))]
extern "C" fn filesystem_service(_argument: u64) -> ! {
    let Some(endpoint) = filesystem_endpoint() else {
        sched::exit()
    };
    run::<Filesystem>(endpoint, filesystem_bulk())
}

/// The nucleus placement of the filesystem's one context operation.
///
/// This is the direct map, reached the way only something inside the kernel
/// can reach it. The domain placement of the same function is a system call,
/// and the service above it cannot tell which it got — which is the claim RFC
/// 0013 makes, and the reason this function exists rather than the service
/// calling `shared::fill_from` itself.
#[cfg(not(vfs_in_domain))]
fn filesystem_bulk() -> Bulk {
    Bulk {
        fill: |slot, limit, source| {
            // Whose CSpace: the caller this thread is answering, which the
            // kernel knows and the service cannot say. Reading rather than
            // taking -- the answer is still owed, and is sent below.
            let caller = crate::sched::current_thread_id().and_then(crate::sched::reply_target)?;
            // The caller names a slot in **its own** CSpace, not an object
            // identity. Naming an identity would be a caller asserting what it
            // may reach; naming a slot is a caller pointing at authority it
            // already holds, which the kernel then checks -- the same shape
            // the capability syscalls use, and the reason this cannot be used
            // to read into somebody else's memory.
            let object = crate::shared::caller_object(caller, slot)?;
            // Offset zero, and no loop: this placement has the object in front
            // of it and `fill_from` spans every frame of it in one call. The
            // domain placement cannot -- it copies through a buffer of its own
            // and has to say where each piece goes. That asymmetry is the
            // placement's business and not the service's, which is why `Fill`
            // takes no offset: a service that had to know would be a service
            // that knows where it runs.
            crate::shared::fill_from(object, 0, limit, source)
        },
        refused: || {
            REFUSED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        },
    }
}

/// What the console gets to reach, built out of the kernel's own routines.
///
/// The whole of the nucleus placement for this service: four functions. In a
/// domain these become calls out to a driver, and the console itself does not
/// change — which is the claim RFC 0013 makes, and the reason the console is
/// the first service to be compiled apart from the kernel.
#[cfg(not(console_in_domain))]
fn console_ports() -> Ports {
    Ports {
        put: |character| {
            crate::print!("{character}");
            counted(1, 0);
        },
        read: || {
            let byte = crate::input::read();
            counted(0, 1);
            byte
        },
        record_size: || crate::console::recorded().0,
        record_at: crate::console::recorded_at,
        // RFC 0051, and the same packing the nucleus method uses -- reading the
        // counters directly here rather than through a system call, because in
        // this placement the service *is* the thing keeping them.
        input_stats: |which| {
            let (serial_in, serial_lost, keys_in, keys_lost) = crate::input::per_source();
            let (_, _, interrupts) = crate::input::statistics();
            let scancodes = crate::keyboard::scancodes();
            let pair = |high: u64, low: u64| {
                (u64::from(u32::try_from(high).unwrap_or(u32::MAX)) << 32)
                    | u64::from(u32::try_from(low).unwrap_or(u32::MAX))
            };
            match which {
                0 => pair(serial_in, serial_lost),
                1 => pair(keys_in, keys_lost),
                2 => pair(scancodes, interrupts),
                _ => 0,
            }
        },
        try_read: || {
            let byte = crate::input::try_read();
            if byte.is_some() {
                counted(0, 1);
            }
            byte
        },
    }
}

/// Records what the console moved, wherever the service that asked for it runs.
///
/// Counted by the placement and not by the service, because these are things
/// the placement *does*: in the nucleus it is the three functions above, and in
/// a domain it is the three system calls behind the console capability. Either
/// way the number means the same, which a counter inside the service could not
/// have managed without a fourth system call for bookkeeping.
pub fn counted(written: u64, read: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    WRITTEN.fetch_add(written, Relaxed);
    READ.fetch_add(read, Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // The trait's fourth rule -- a malformed request is a reply, not an
    // unwind -- was tested here against the nucleus placement's ports. It has
    // moved to the console crate, where it runs against fake ports and is
    // therefore true of *both* placements. A test that only compiles when a
    // service is in the nucleus is a test that stops running exactly when the
    // service starts being somewhere new.

    #[test]
    fn a_service_names_itself_for_the_placement_table() {
        // Step 2's table is keyed by these, so a rename is a build failure
        // rather than a service that quietly stops being placed.
        assert_eq!(Console::NAME, "console");
        assert_eq!(Filesystem::NAME, "vfs");
    }
}
