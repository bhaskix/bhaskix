// SPDX-License-Identifier: Apache-2.0
//! The shape a service has, in either placement.
//!
//! This crate is deliberately small and deliberately ignorant: it names no
//! kernel type, and it cannot, because it does not depend on the kernel. That
//! is not tidiness. A service that is compiled against this crate and nothing
//! else is a service that *provably* has no way to reach into the nucleus —
//! not by convention, not by review, but because the names are not in scope.
//!
//! [RFC 0013](../../../docs/rfc/0013-service-framework.md). The placement
//! table lives in `services.toml`, and `tools/check-placements.sh` is what
//! makes the paragraph above true rather than merely intended.
#![no_std]

/// One request, as it arrived.
pub struct Request<'a> {
    /// Which operation.
    pub method: u64,
    /// Four registers. Anything larger travels as a `Memory` capability.
    pub args: &'a [u64; 4],
    /// Who is calling, from the capability they used — never from anything
    /// they said.
    pub badge: u64,
}

// There is deliberately no caller identity here.
//
// An earlier version carried one, as an opaque number a service handed back to
// its context. It was removed when the domain placement was built: the caller
// arrived in a register, which meant a service could hand back a *different*
// one, and a placement that trusted it would act for a caller this service was
// never speaking to. The placement already knows who is being answered — it is
// the party whose message this is — so the service does not need to be told,
// and being unable to say is the property worth having.

/// One reply.
///
/// A value rather than a message: the method and the badge belong to the
/// placement, not to the service, and a service that could set them could
/// claim to be answering a different question, or claim an identity.
pub struct Reply {
    /// Four registers back.
    pub args: [u64; 4],
}

impl Reply {
    /// The ordinary case.
    #[must_use]
    pub const fn new(args: [u64; 4]) -> Self {
        Self { args }
    }
}

/// Why a service would not start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartError {
    /// The context did not carry something the service needs.
    MissingCapability,
}

/// A service: a context, some state, a message handler, and nothing else.
///
/// The four rules `architecture.md` §2 states are shaped into this trait
/// rather than asked for in prose:
///
/// - **No global mutable state**, because the state is [`Service::State`] and
///   arrives by reference.
/// - **No direct hardware access**, because the only way to reach anything is
///   [`Service::Context`], and a placement hands over exactly what it means to.
/// - **No blocking**, because [`Service::handle`] returns a [`Reply`] and
///   there is nowhere to wait. A service that must wait answers, and is
///   re-entered when the thing it waited for happens.
/// - **No panics on input**, because a malformed request is a `Reply` and not
///   an unwind.
///
/// A service is constrained by the **intersection** of both placements, not
/// the union, and the constraint that binds is nearly always the nucleus one:
/// it is the placement with the fewest walls.
pub trait Service {
    /// Everything this service may reach.
    ///
    /// A value, deliberately, rather than an ambient: whatever is not in here,
    /// the service does not have. It is an associated type and not one shared
    /// struct because what a console needs and what a filesystem needs have
    /// nothing in common, and a context wide enough for both would hand each
    /// of them the other's reach.
    ///
    /// In the nucleus placement the kernel builds it out of its own functions;
    /// in a domain placement it is built from the domain's CSpace. The two
    /// must carry the same names for the same things, or the code above them
    /// cannot be the same code.
    type Context: Copy;

    /// Everything the service knows.
    type State;

    /// What it is called, in `services.toml` and in the boot log.
    const NAME: &'static str;

    /// Built once, from what the placement handed over.
    ///
    /// # Errors
    ///
    /// [`StartError`] if the context is missing something required.
    fn start(context: Self::Context) -> Result<Self::State, StartError>;

    /// One request in, one reply out.
    fn handle(state: &mut Self::State, context: &Self::Context, request: Request<'_>) -> Reply;
}
