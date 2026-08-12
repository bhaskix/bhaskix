// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the DHCP offer parser.
//!
//! The one parser here whose input arrives from **whoever answers first**. A
//! client with no address broadcasts and believes what comes back; there is no
//! prior exchange to bind the answer to, and nothing at this layer that can
//! tell a server from anything else on the segment that felt like replying.
//!
//! # The options walk is the whole risk
//!
//! Everything before it is fixed offsets in a 236-byte header. The options are
//! a length-prefixed walk over attacker-chosen bytes, which is the shape that
//! runs off the end — a length reaching past the message, a pad byte treated as
//! though it carried a length, an option claiming 255 bytes with four left.
//!
//! So this target feeds mutated messages *with the fixed part intact* as well
//! as wholly random bytes: a campaign that only ever produced random input
//! would be refused at the operation byte and never reach the walk at all,
//! which is the same doorway problem `DMAR` taught this project.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal: random bytes are not an
//! offer, and refusing them is correct. What must never happen is a read past
//! the message, or a walk that does not terminate.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run dhcp_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{addr::MacAddr, dhcp};

fuzz_target!(|data: &[u8]| {
    // As given. Most inputs die at the operation byte or the cookie, which is
    // the refusal path and worth covering.
    let _ = dhcp::parse_offer(data);

    // And with a well-formed head, so the options walk is reachable. Without
    // this the campaign never gets past the doorway and reports a clean run
    // over the two checks in front of it.
    let mut shaped = [0u8; 1024];
    let length = data.len().min(shaped.len());
    shaped[..length].copy_from_slice(&data[..length]);
    if length >= dhcp::MINIMUM {
        shaped[0] = 2; // BOOTREPLY
        shaped[dhcp::FIXED..dhcp::MINIMUM].copy_from_slice(&dhcp::MAGIC.to_be_bytes());
    }
    if let Ok(offer) = dhcp::parse_offer(&shaped[..length]) {
        // The address is read from a fixed offset inside the header, so a
        // parse that succeeded cannot have taken it from beyond the message.
        // Asserting it keeps that true after the next change to the walk.
        let _ = offer.address;
        let _ = offer.server;
        assert!(length >= dhcp::MINIMUM);
    }

    // The writer, driven from the same bytes: its own output must never parse
    // as an offer, because it is a request. A writer that set the wrong
    // operation byte would round-trip happily and be wrong on the wire.
    let mut out = [0u8; 512];
    let mut mac = [0u8; 6];
    for (index, octet) in mac.iter_mut().enumerate() {
        *octet = data.get(index).copied().unwrap_or(0);
    }
    if let Ok(written) = dhcp::write_discover(&mut out, MacAddr(mac), length as u32) {
        assert!(dhcp::parse_offer(&out[..written]).is_err());
    }
});
