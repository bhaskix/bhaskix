// SPDX-License-Identifier: Apache-2.0
//! LACP — IEEE 802.3ad link aggregation, as arithmetic over a byte slice.
//!
//! [RFC 0073](../../docs/rfc/0073-speaking-lacp-so-the-switch-will-listen.md).
//! A switch running 802.3ad keeps a member port *unselected* until the host
//! speaks the protocol, and an unselected member carries control frames and no
//! data. That is why the SR550's X722 has never been handed a frame: not a
//! defect in the driver, a wire whose data plane is closed.
//!
//! This is the protocol and none of the machinery around it: no device, no
//! timer, no domain. A caller supplies the bytes that arrived and how much
//! time has passed, and gets back what to believe and what to send. The split
//! is the one [RFC 0020](../../docs/rfc/0020-tcp.md) used for TCP, for the same
//! reason: a state machine a host test can drive in microseconds is one that
//! gets tested, and a protocol that needs a switch to exercise is one that does
//! not.
//!
//! # What is deliberately not here
//!
//! **The selection logic across several links.** One member is what RFC 0073
//! starts with, and choosing *which* of four links to aggregate is a decision
//! with no second link to make it against yet. [`Machine`] describes one port;
//! an aggregator over several is the caller's, later.

use crate::{NetError, addr::MacAddr, be16};

/// The Slow Protocols EtherType — IEEE 802.3 Clause 57, which LACP rides on.
pub const ETHERTYPE: u16 = 0x8809;

/// The Slow Protocols multicast address, `01:80:C2:00:00:02`.
///
/// A reserved group address: a bridge terminates it rather than forwarding it,
/// which is why getting one delivered to a host queue needs the device's
/// control-packet filter rather than an ordinary MAC filter.
pub const GROUP_ADDRESS: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]);

/// The LACP subtype within slow protocols.
pub const SUBTYPE: u8 = 0x01;
/// The version this speaks.
pub const VERSION: u8 = 0x01;

/// An LACPDU's length, not counting the Ethernet header.
///
/// Two bytes of subtype and version, three
/// type-length-value blocks and a terminator: 1 + 1 + 20 + 20 + 16 + 2 + 50.
pub const PDU: usize = 110;

/// TLV type for the actor's own information.
const TLV_ACTOR: u8 = 0x01;
/// TLV type for what the sender believes about its partner.
const TLV_PARTNER: u8 = 0x02;
/// TLV type for the collector.
const TLV_COLLECTOR: u8 = 0x03;
/// The terminator, which has no length.
const TLV_TERMINATOR: u8 = 0x00;
/// Both information TLVs are twenty bytes.
const TLV_INFORMATION_LENGTH: u8 = 20;
/// The collector TLV is sixteen.
const TLV_COLLECTOR_LENGTH: u8 = 16;

/// Where each field sits, by the standard's layout.
const ACTOR_AT: usize = 2;
const PARTNER_AT: usize = 22;
const COLLECTOR_AT: usize = 42;
const TERMINATOR_AT: usize = 58;

/// The collector's maximum delay, in tens of microseconds. Zero is legal and
/// says this station imposes no delay of its own.
const COLLECTOR_MAX_DELAY: u16 = 0;

/// How long to keep a partner's information when it stops arriving.
///
/// The standard's rule: three intervals. A link that goes quiet must not stay
/// `Distributing`, because a station that claims to distribute into a link
/// that is gone black-holes the traffic sent over it.
pub const EXPIRY_INTERVALS: u32 = 3;

/// One station's view of itself or of its partner — 802.3ad's
/// *Actor/Partner Information*.
///
/// The same shape describes both because the protocol is symmetric: what we
/// send about ourselves is what the partner records about us, and the test of
/// agreement is whether the partner's *partner* fields equal our *actor*
/// fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Actor {
    /// System priority; lower wins when two systems disagree.
    pub system_priority: u16,
    /// The system's identifier, conventionally a MAC address it owns.
    pub system: MacAddr,
    /// The aggregation key. Ports sharing a key may aggregate together.
    pub key: u16,
    /// Port priority; lower wins.
    pub port_priority: u16,
    /// The port number within the system, one-based by convention.
    pub port: u16,
    /// The eight state flags.
    pub state: State,
}

impl Actor {
    /// A partner that has never been heard from.
    ///
    /// All zeroes, which is what the standard has a station send when it has
    /// no partner information — and what tells the other end it is not yet
    /// recorded. There is no `Default` because [`MacAddr`] has none, and an
    /// address of `00:00:00:00:00:00` is worth naming rather than defaulting
    /// into.
    pub const UNKNOWN: Self = Self {
        system_priority: 0,
        system: MacAddr([0; 6]),
        key: 0,
        port_priority: 0,
        port: 0,
        state: State(0),
    };

    /// Twenty bytes: two of priority, six of system, two of key, two of port
    /// priority, two of port, one of state, three reserved.
    pub const BYTES: usize = 20;

    /// Reads one information block, whose TLV type and length the caller has
    /// already checked.
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            system_priority: be16(bytes, 2)?,
            system: MacAddr([
                *bytes.get(4)?,
                *bytes.get(5)?,
                *bytes.get(6)?,
                *bytes.get(7)?,
                *bytes.get(8)?,
                *bytes.get(9)?,
            ]),
            key: be16(bytes, 10)?,
            port_priority: be16(bytes, 12)?,
            port: be16(bytes, 14)?,
            state: State(*bytes.get(16)?),
        })
    }

    /// Writes one information block with its TLV header.
    fn write(&self, out: &mut [u8], tlv: u8) -> Option<()> {
        let block = out.get_mut(..Self::BYTES)?;
        block.fill(0);
        block[0] = tlv;
        block[1] = TLV_INFORMATION_LENGTH;
        block[2..4].copy_from_slice(&self.system_priority.to_be_bytes());
        block[4..10].copy_from_slice(&self.system.octets());
        block[10..12].copy_from_slice(&self.key.to_be_bytes());
        block[12..14].copy_from_slice(&self.port_priority.to_be_bytes());
        block[14..16].copy_from_slice(&self.port.to_be_bytes());
        block[16] = self.state.0;
        Some(())
    }

    /// Whether this describes the same port as `other`, ignoring state.
    ///
    /// **The test the protocol turns on.** A partner has recorded us when the
    /// partner fields it sends back name our system, key and port; its opinion
    /// of our *state* is not part of that, because state is what changes.
    #[must_use]
    pub fn same_port_as(&self, other: &Self) -> bool {
        self.system == other.system && self.key == other.key && self.port == other.port
    }
}

/// The eight LACP state flags, named.
///
/// A bare byte with a comment is how these get read wrong; the named
/// predicates below are what the state machine is written in terms of.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State(pub u8);

impl State {
    /// Bit 0: this station sends LACPDUs rather than only answering them.
    pub const ACTIVITY: u8 = 1 << 0;
    /// Bit 1: the short timeout is wanted — one second rather than thirty.
    pub const TIMEOUT: u8 = 1 << 1;
    /// Bit 2: this link may be aggregated rather than standing alone.
    pub const AGGREGATION: u8 = 1 << 2;
    /// Bit 3: the partner's view of this station is correct.
    pub const SYNCHRONIZATION: u8 = 1 << 3;
    /// Bit 4: incoming frames on this link are being taken.
    pub const COLLECTING: u8 = 1 << 4;
    /// Bit 5: outgoing frames are being sent over this link.
    pub const DISTRIBUTING: u8 = 1 << 5;
    /// Bit 6: the partner's information is made up rather than received.
    pub const DEFAULTED: u8 = 1 << 6;
    /// Bit 7: the partner's information has aged out.
    pub const EXPIRED: u8 = 1 << 7;

    /// Whether every flag in `mask` is set.
    #[must_use]
    pub const fn has(&self, mask: u8) -> bool {
        self.0 & mask == mask
    }

    /// The same, with the flag set.
    #[must_use]
    pub const fn with(self, mask: u8) -> Self {
        Self(self.0 | mask)
    }

    /// The same, with the flag cleared.
    #[must_use]
    pub const fn without(self, mask: u8) -> Self {
        Self(self.0 & !mask)
    }

    /// Whether this link is carrying data in both directions.
    #[must_use]
    pub const fn is_up(&self) -> bool {
        self.has(Self::SYNCHRONIZATION | Self::COLLECTING | Self::DISTRIBUTING)
    }

    /// How long between LACPDUs, in seconds, as the timeout flag asks.
    #[must_use]
    pub const fn interval_seconds(&self) -> u32 {
        if self.has(Self::TIMEOUT) { 1 } else { 30 }
    }
}

/// A parsed LACPDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pdu {
    /// What the sender says about itself.
    pub actor: Actor,
    /// What the sender believes about us.
    pub partner: Actor,
}

impl Pdu {
    /// Reads an LACPDU from the bytes after the Ethernet header.
    ///
    /// **Refuses rather than trusts.** This is untrusted input off a segment
    /// the threat model already assumes is hostile, so a wrong subtype, a
    /// wrong version or a TLV that does not say what the standard says it must
    /// is a refusal — a partner cannot be allowed to advance a state machine
    /// with a malformed frame.
    ///
    /// # Errors
    ///
    /// [`NetError::Truncated`] if the slice is shorter than [`PDU`], or
    /// [`NetError::Malformed`] if a field is not what the standard requires.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetError> {
        let pdu = bytes.get(..PDU).ok_or(NetError::Truncated {
            need: PDU,
            have: bytes.len(),
        })?;
        if pdu[0] != SUBTYPE {
            return Err(NetError::Unsupported {
                field: "LACP subtype",
                value: u32::from(pdu[0]),
            });
        }
        if pdu[1] != VERSION {
            return Err(NetError::Unsupported {
                field: "LACP version",
                value: u32::from(pdu[1]),
            });
        }
        if pdu[ACTOR_AT] != TLV_ACTOR || pdu[ACTOR_AT + 1] != TLV_INFORMATION_LENGTH {
            return Err(NetError::Unsupported {
                field: "actor TLV",
                value: u32::from(pdu[ACTOR_AT]) << 8 | u32::from(pdu[ACTOR_AT + 1]),
            });
        }
        if pdu[PARTNER_AT] != TLV_PARTNER || pdu[PARTNER_AT + 1] != TLV_INFORMATION_LENGTH {
            return Err(NetError::Unsupported {
                field: "partner TLV",
                value: u32::from(pdu[PARTNER_AT]) << 8 | u32::from(pdu[PARTNER_AT + 1]),
            });
        }
        if pdu[COLLECTOR_AT] != TLV_COLLECTOR || pdu[COLLECTOR_AT + 1] != TLV_COLLECTOR_LENGTH {
            return Err(NetError::Unsupported {
                field: "collector TLV",
                value: u32::from(pdu[COLLECTOR_AT]) << 8 | u32::from(pdu[COLLECTOR_AT + 1]),
            });
        }
        if pdu[TERMINATOR_AT] != TLV_TERMINATOR {
            return Err(NetError::Unsupported {
                field: "LACP terminator",
                value: u32::from(pdu[TERMINATOR_AT]),
            });
        }
        Ok(Self {
            actor: Actor::parse(&pdu[ACTOR_AT..]).ok_or(NetError::Truncated {
                need: PDU,
                have: bytes.len(),
            })?,
            partner: Actor::parse(&pdu[PARTNER_AT..]).ok_or(NetError::Truncated {
                need: PDU,
                have: bytes.len(),
            })?,
        })
    }

    /// Writes this LACPDU into `out`, returning the bytes written.
    ///
    /// # Errors
    ///
    /// [`NetError::Truncated`] if `out` cannot hold [`PDU`] bytes.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, NetError> {
        let available = out.len();
        let pdu = out.get_mut(..PDU).ok_or(NetError::Truncated {
            need: PDU,
            have: available,
        })?;
        pdu.fill(0);
        pdu[0] = SUBTYPE;
        pdu[1] = VERSION;
        self.actor
            .write(&mut pdu[ACTOR_AT..], TLV_ACTOR)
            .ok_or(NetError::Truncated {
                need: PDU,
                have: available,
            })?;
        self.partner
            .write(&mut pdu[PARTNER_AT..], TLV_PARTNER)
            .ok_or(NetError::Truncated {
                need: PDU,
                have: available,
            })?;
        pdu[COLLECTOR_AT] = TLV_COLLECTOR;
        pdu[COLLECTOR_AT + 1] = TLV_COLLECTOR_LENGTH;
        pdu[COLLECTOR_AT + 2..COLLECTOR_AT + 4].copy_from_slice(&COLLECTOR_MAX_DELAY.to_be_bytes());
        // The terminator's type and length are both zero, and the fifty bytes
        // after it are already zeroed by the fill above.
        Ok(PDU)
    }
}

/// What one port believes, and what it should do next.
///
/// **No clock and no device.** [`Machine::received`] is given a frame,
/// [`Machine::elapsed`] is given seconds, and neither reads a register or a
/// timer. That is what lets the whole protocol be exercised by a host test.
#[derive(Clone, Copy, Debug)]
pub struct Machine {
    /// What this port says about itself.
    pub actor: Actor,
    /// What the partner last said about itself, if it has ever spoken.
    pub partner: Option<Actor>,
    /// Seconds since the partner was last heard from.
    pub silent_for: u32,
    /// Seconds since this port last sent an LACPDU.
    pub since_sent: u32,
    /// LACPDUs refused as malformed, which a partner should not be able to
    /// hide by sending more of them.
    pub refused: u32,
}

impl Machine {
    /// A port that has heard nothing yet.
    ///
    /// It starts **active and aggregatable** — active because a switch
    /// configured passive will never speak first, and a port that waits for a
    /// passive partner waits forever. That is not hypothetical: it is one of
    /// the two readings of why the SR550's wire looks silent.
    #[must_use]
    pub fn new(system: MacAddr, key: u16, port: u16) -> Self {
        Self {
            actor: Actor {
                system_priority: 0x8000,
                system,
                key,
                port_priority: 0x8000,
                port,
                state: State(State::ACTIVITY | State::AGGREGATION),
            },
            partner: None,
            silent_for: 0,
            since_sent: u32::MAX,
            refused: 0,
        }
    }

    /// Takes a frame's LACPDU bytes and updates what this port believes.
    ///
    /// Returns whether the frame was accepted. A refusal is counted and
    /// changes nothing else.
    pub fn received(&mut self, bytes: &[u8]) -> bool {
        let Ok(pdu) = Pdu::parse(bytes) else {
            self.refused += 1;
            return false;
        };
        self.partner = Some(pdu.actor);
        self.silent_for = 0;
        self.actor.state = self.actor.state.without(State::EXPIRED | State::DEFAULTED);

        // **Synchronised when the partner has us right.** Its partner fields
        // are its record of us; if they name this port, it is talking to us
        // and not to whoever held the link before.
        if pdu.partner.same_port_as(&self.actor) {
            self.actor.state = self.actor.state.with(State::SYNCHRONIZATION);
        } else {
            self.actor.state = self
                .actor
                .state
                .without(State::SYNCHRONIZATION | State::COLLECTING | State::DISTRIBUTING);
        }

        // **Collecting and distributing only when both sides are synchronised.**
        // Claiming to distribute into a link the partner has not agreed to is
        // how traffic disappears.
        if self.actor.state.has(State::SYNCHRONIZATION)
            && pdu.actor.state.has(State::SYNCHRONIZATION)
        {
            self.actor.state = self
                .actor
                .state
                .with(State::COLLECTING | State::DISTRIBUTING);
        }

        // The partner's timeout preference is the partner's to set.
        self.actor.state = if pdu.actor.state.has(State::TIMEOUT) {
            self.actor.state.with(State::TIMEOUT)
        } else {
            self.actor.state.without(State::TIMEOUT)
        };
        true
    }

    /// Advances the clock by `seconds`, expiring a partner that has gone quiet.
    pub fn elapsed(&mut self, seconds: u32) {
        self.silent_for = self.silent_for.saturating_add(seconds);
        self.since_sent = self.since_sent.saturating_add(seconds);
        if self.partner.is_none() {
            return;
        }
        let interval = self.actor.state.interval_seconds();
        if self.silent_for >= interval * EXPIRY_INTERVALS {
            // **Stop claiming to carry traffic before forgetting who the
            // partner was.** The order matters: a link whose partner has aged
            // out must not be left distributing while the state is tidied up.
            self.actor.state = self
                .actor
                .state
                .without(State::SYNCHRONIZATION | State::COLLECTING | State::DISTRIBUTING)
                .with(State::EXPIRED);
            self.partner = None;
        }
    }

    /// Whether an LACPDU is due.
    #[must_use]
    pub fn should_send(&self) -> bool {
        self.since_sent >= self.actor.state.interval_seconds()
    }

    /// The LACPDU to send now, and the fact that it was sent.
    ///
    /// The partner block carries what this port last heard, or zeroes if it
    /// has heard nothing — which is what tells a partner it is not yet
    /// recorded.
    pub fn sending(&mut self) -> Pdu {
        self.since_sent = 0;
        Pdu {
            actor: self.actor,
            partner: self.partner.unwrap_or(Actor::UNKNOWN),
        }
    }

    /// Whether this link is carrying data in both directions.
    #[must_use]
    pub const fn aggregated(&self) -> bool {
        self.actor.state.is_up()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: MacAddr = MacAddr([0x08, 0x94, 0xef, 0x7a, 0xfc, 0x8e]);
    const SWITCH: MacAddr = MacAddr([0x00, 0x1b, 0x2a, 0x3c, 0x4d, 0x5e]);

    /// A partner that has us recorded, in the state the switch would send.
    fn partner_pdu(sees_us: Option<Actor>, state: u8) -> [u8; PDU] {
        let mut bytes = [0u8; PDU];
        Pdu {
            actor: Actor {
                system_priority: 0x8000,
                system: SWITCH,
                key: 7,
                port_priority: 0x8000,
                port: 42,
                state: State(state),
            },
            partner: sees_us.unwrap_or(Actor::UNKNOWN),
        }
        .write(&mut bytes)
        .expect("the buffer is exactly a PDU");
        bytes
    }

    /// The layout, against the standard's field offsets.
    #[test]
    fn a_pdu_round_trips_through_the_standards_layout() {
        let original = Pdu {
            actor: Actor {
                system_priority: 0x8000,
                system: US,
                key: 3,
                port_priority: 0x1234,
                port: 1,
                state: State(State::ACTIVITY | State::AGGREGATION),
            },
            partner: Actor {
                system_priority: 1,
                system: SWITCH,
                key: 7,
                port_priority: 2,
                port: 42,
                state: State(State::SYNCHRONIZATION),
            },
        };
        let mut bytes = [0u8; PDU];
        assert_eq!(original.write(&mut bytes).expect("writes"), PDU);

        // The bytes the standard names, checked rather than assumed.
        assert_eq!(bytes[0], SUBTYPE);
        assert_eq!(bytes[1], VERSION);
        assert_eq!(bytes[ACTOR_AT], TLV_ACTOR);
        assert_eq!(bytes[ACTOR_AT + 1], TLV_INFORMATION_LENGTH);
        assert_eq!(&bytes[ACTOR_AT + 4..ACTOR_AT + 10], &US.octets());
        assert_eq!(bytes[PARTNER_AT], TLV_PARTNER);
        assert_eq!(&bytes[PARTNER_AT + 4..PARTNER_AT + 10], &SWITCH.octets());
        assert_eq!(bytes[COLLECTOR_AT], TLV_COLLECTOR);
        assert_eq!(bytes[COLLECTOR_AT + 1], TLV_COLLECTOR_LENGTH);
        assert_eq!(bytes[TERMINATOR_AT], TLV_TERMINATOR);

        assert_eq!(Pdu::parse(&bytes).expect("parses"), original);
    }

    /// Malformed input is refused, not accommodated.
    #[test]
    fn a_malformed_pdu_cannot_advance_anything() {
        let good = partner_pdu(None, State::ACTIVITY);
        assert!(Pdu::parse(&good).is_ok());

        assert!(matches!(
            Pdu::parse(&good[..PDU - 1]),
            Err(NetError::Truncated { .. })
        ));

        for (offset, what) in [
            (0, "subtype"),
            (1, "version"),
            (ACTOR_AT, "actor TLV type"),
            (ACTOR_AT + 1, "actor TLV length"),
            (PARTNER_AT, "partner TLV type"),
            (COLLECTOR_AT, "collector TLV type"),
            (TERMINATOR_AT, "terminator"),
        ] {
            let mut bad = good;
            bad[offset] = bad[offset].wrapping_add(1);
            assert!(
                matches!(Pdu::parse(&bad), Err(NetError::Unsupported { .. })),
                "a wrong {what} must be refused"
            );
        }

        // And a refusal reaches the machine as a count, not as state.
        let mut machine = Machine::new(US, 3, 1);
        let before = machine.actor.state;
        let mut bad = good;
        bad[0] = 0xff;
        assert!(!machine.received(&bad));
        assert_eq!(machine.refused, 1);
        assert_eq!(machine.actor.state, before, "a bad frame changed the state");
        assert!(machine.partner.is_none());
    }

    /// The exchange that brings a link up, in the order it happens.
    #[test]
    fn a_link_comes_up_only_once_both_sides_agree() {
        let mut machine = Machine::new(US, 3, 1);
        assert!(machine.should_send(), "a fresh port speaks first");
        assert!(!machine.aggregated());
        assert!(
            machine.actor.state.has(State::ACTIVITY),
            "active, because a passive partner never speaks first"
        );

        // First the partner answers without having recorded us: its partner
        // block is empty, so we are not synchronised.
        assert!(machine.received(&partner_pdu(None, State::ACTIVITY)));
        assert!(machine.partner.is_some());
        assert!(!machine.actor.state.has(State::SYNCHRONIZATION));
        assert!(!machine.aggregated());

        // Then it names us, but is not itself in sync yet.
        let us = machine.actor;
        assert!(machine.received(&partner_pdu(Some(us), State::ACTIVITY)));
        assert!(machine.actor.state.has(State::SYNCHRONIZATION));
        assert!(
            !machine.aggregated(),
            "one side in sync is not an aggregated link"
        );

        // Then it is, and the link carries data.
        assert!(machine.received(&partner_pdu(
            Some(us),
            State::ACTIVITY | State::SYNCHRONIZATION
        )));
        assert!(machine.aggregated());
        assert!(machine.actor.state.has(State::COLLECTING));
        assert!(machine.actor.state.has(State::DISTRIBUTING));
    }

    /// A partner that names the wrong port is not us, and must not sync.
    #[test]
    fn a_partner_naming_another_port_does_not_synchronise_this_one() {
        let mut machine = Machine::new(US, 3, 1);
        let someone_else = Actor {
            port: 2,
            ..machine.actor
        };
        assert!(machine.received(&partner_pdu(
            Some(someone_else),
            State::ACTIVITY | State::SYNCHRONIZATION
        )));
        assert!(
            !machine.actor.state.has(State::SYNCHRONIZATION),
            "the partner is talking about a different port"
        );
        assert!(!machine.aggregated());
    }

    /// A link whose partner goes quiet must stop claiming to carry traffic.
    #[test]
    fn a_silent_partner_expires_before_it_can_black_hole_traffic() {
        let mut machine = Machine::new(US, 3, 1);
        let us = machine.actor;
        machine.received(&partner_pdu(
            Some(us),
            State::ACTIVITY | State::SYNCHRONIZATION,
        ));
        assert!(machine.aggregated());
        assert_eq!(
            machine.actor.state.interval_seconds(),
            30,
            "the partner asked for the long timeout"
        );

        // Two intervals of silence is not yet expiry.
        machine.elapsed(59);
        assert!(machine.aggregated(), "expired an interval too early");

        machine.elapsed(31);
        assert!(!machine.aggregated(), "a quiet link kept distributing");
        assert!(machine.actor.state.has(State::EXPIRED));
        assert!(machine.partner.is_none());
        assert!(!machine.actor.state.has(State::DISTRIBUTING));
    }

    /// The partner's timeout preference sets the sending interval.
    #[test]
    fn the_partner_chooses_how_often_this_port_speaks() {
        let mut machine = Machine::new(US, 3, 1);
        assert_eq!(machine.actor.state.interval_seconds(), 30);

        machine.received(&partner_pdu(None, State::ACTIVITY | State::TIMEOUT));
        assert_eq!(machine.actor.state.interval_seconds(), 1, "asked for fast");

        machine.sending();
        assert!(!machine.should_send());
        machine.elapsed(1);
        assert!(machine.should_send());

        machine.received(&partner_pdu(None, State::ACTIVITY));
        assert_eq!(machine.actor.state.interval_seconds(), 30, "back to slow");
    }

    /// What goes on the wire carries what we last heard.
    #[test]
    fn the_pdu_sent_reports_the_partner_it_last_heard() {
        let mut machine = Machine::new(US, 3, 1);
        let first = machine.sending();
        assert_eq!(
            first.partner,
            Actor::UNKNOWN,
            "a port that has heard nothing says so"
        );
        assert_eq!(first.actor.system, US);
        assert!(!machine.should_send(), "sending resets the interval");

        machine.received(&partner_pdu(None, State::ACTIVITY));
        let second = machine.sending();
        assert_eq!(second.partner.system, SWITCH);
        assert_eq!(second.partner.port, 42);
    }
}
