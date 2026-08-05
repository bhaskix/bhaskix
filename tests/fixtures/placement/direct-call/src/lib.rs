// SPDX-License-Identifier: Apache-2.0
//! A service that calls into the kernel instead of asking its context.
//!
//! Not built, not shipped, and not correct — this exists so that
//! `tools/check-placements.sh` can be watched rejecting something. See the
//! comment in `Cargo.toml`.
#![no_std]

use bhaskix_service::{Reply, Request, Service, StartError};

/// The offending service.
pub struct DirectCall;

impl Service for DirectCall {
    type Context = ();
    type State = ();

    const NAME: &'static str = "direct-call";

    fn start((): Self::Context) -> Result<Self::State, StartError> {
        Ok(())
    }

    fn handle((): &mut Self::State, (): &Self::Context, _request: Request<'_>) -> Reply {
        // This is the whole point of the fixture. A service in a domain has no
        // kernel to call, so this line is the difference between a service
        // that can be moved and one that only looks like it can — and the
        // check finds it by the dependency that makes the name reachable at
        // all, not by reading the line.
        Reply::new([bhaskix_kernel::service::requests(), 0, 0, 0])
    }
}
