// SPDX-License-Identifier: Apache-2.0
//! The protocol service, in a domain with no device.
//!
//! [RFC 0018](../../../docs/rfc/0018-networking.md) step 3. It takes frames
//! from `bin/netd` through a shared ring and, for now, counts them. ARP and
//! IPv4 are step 4; keeping them out is what makes this step a test of the
//! *ring* rather than of a ring and a parser at once.
//!
//! # What it does not hold, which is the whole argument
//!
//! No device. No DMA window. No interrupt. No configuration space. Two
//! capabilities: the ring it reads and a page it writes findings into.
//!
//! That asymmetry is why RFC 0018 splits the stack across two domains. Every
//! byte this program will eventually parse arrives from whoever can reach the
//! wire, continuously, at line rate — and a parser bug here cannot be turned
//! into a device pointed anywhere, because there is no device within reach.
//!
//! # The ring is `abi::ring`, and this is its first caller
//!
//! That module was written for RFC 0009 step 5 and had no user until now. Its
//! shape carries a rule worth restating: **copy out, validate the copy, use the
//! copy.** `Cursor` is built from numbers rather than from the region, so a
//! reader physically cannot validate one value and then use a different one
//! that the writer changed in between. The producer is another domain and can
//! write whatever it likes into the header; nothing here may be trusted twice.
#![no_std]
#![no_main]

use bhaskix_abi::{method, rights, ring, socket, status, syscall};
use bhaskix_net::{
    Address, ArpOp, ArpPacket, EthFrame, EtherType, Ipv4Addr, Ipv4Header, Ipv6Addr, Ipv6Header,
    MacAddr, NeighbourCache, NextHeader, Port, Protocol, UdpDatagram, arp, eth, icmp, icmpv6, ipv4,
    ipv6, udp,
};

/// Slot: the ring `bin/netd` writes frames into.
const RING: u64 = 0;
/// Slot: the page this program leaves its findings in.
const REPORT: u64 = 1;
/// Slot: the ring this program hands frames back to `bin/netd` through.
const BACK: u64 = 2;
/// Slot: what this interface is, read-only, written by the kernel.
const CONFIG: u64 = 3;
/// Slot: the endpoint this service answers on.
///
/// Unbadged, because it is this program's own. Every socket handed out is a
/// *badged, weaker* capability to this same endpoint — which is why RFC 0018
/// step 5 needs no new kernel object kind, and why the kernel gained nothing
/// for this step.
const ENDPOINT: u64 = 4;
/// Slot: the doorbell that wakes `bin/netd`.
///
/// **RFC 0010 step 6.** A frame published into the return ring is invisible to
/// a driver asleep on its interrupt, and until 2026-08-13 nothing in this
/// system could wake another domain: the kernel poked `bin/netd` twice a second
/// on this program's behalf. RFC 0018 step 7 measured what that cost — 122 to
/// 234 microseconds a round trip against 10 to 16 with the two domains folded
/// into one, which is four orders of magnitude more than the copies the
/// networking RFC blamed.
///
/// Write only, and the badge is the kernel's. This capability cannot be waited
/// on, so a bug here cannot eat the wake the driver is asleep for, and its bit
/// was not chosen here, so the driver can trust the word to say who rang.
const DOORBELL: u64 = 5;
/// Slot: the notification `bin/netd` rings when a frame has arrived.
///
/// **RFC 0010 question 1, answered 2026-08-13.** This program has to answer
/// socket calls on its endpoint *and* notice frames it did not ask for. Until
/// now it could not wait for both — there is no second thread to spare and no
/// timed wait — so it polled, about thirty-seven looks at the ring per frame.
///
/// Bound to this thread, so `receive` wakes for a caller or a frame, whichever
/// comes first, and says which.
const INBOX: u64 = 6;
/// Slot: the ring this program forwards TCP segments into.
///
/// **RFC 0020 step 4.** `bin/tcpd` is on the other end. What crosses is not a
/// frame: it is eight bytes of addresses — source, destination — and then the
/// TCP segment, because the pseudo-header needs the addresses and `tcpd`
/// deliberately parses no IP. This program stays the only parser of the IPv4
/// header, exactly as the RFC's diagram draws it.
const TCP_FWD: u64 = 7;
/// Slot: the ring `bin/tcpd` hands segments back through.
const TCP_BACK: u64 = 8;
/// Slot: the doorbell that wakes `bin/tcpd`.
const TCP_BELL: u64 = 9;
/// The bell rung when a datagram is delivered to a UDP socket — RFC 0058.
///
/// Write-only here, and `bin/linuxd` holds the same notification with `READ`:
/// the adapter may wait for a datagram and may not claim one arrived. Unchecked
/// when it rings, exactly as [`DOORBELL`] is: a machine that granted none has
/// an empty slot, the invocation is refused, and a bell nobody hung is not an
/// error — it is a poller that will have to ask again instead of being told.
const DATAGRAM_BELL: u64 = 10;

/// Rings the datagram bell. Called wherever a datagram becomes readable.
fn ring_datagram_bell() {
    DATAGRAMS_ANNOUNCED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    call(syscall::INVOKE, DATAGRAM_BELL, method::SIGNAL, [0; 4]);
}

/// How many times the datagram bell has been rung.
static DATAGRAMS_ANNOUNCED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where this program maps what it holds.
const RING_AT: u64 = 0x2100_0000;
const REPORT_AT: u64 = 0x2110_0000;
const BACK_AT: u64 = 0x2120_0000;
const CONFIG_AT: u64 = 0x2130_0000;
const TCP_FWD_AT: u64 = 0x2140_0000;
const TCP_BACK_AT: u64 = 0x2150_0000;

/// Bytes in the ring, matching what the kernel granted.
const RING_BYTES: usize = 16 * 4096;

/// The largest frame this program will take out of the ring.
///
/// A length is a number the *other side* wrote, so it is bounded here before
/// it is used for anything. Without this a producer could name a length that
/// reached past the ring, and the bound is what makes that a refusal rather
/// than a read of whatever follows.
const MAX_FRAME: usize = 2048;

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3154_5052_4450_4931;

/// How many words the report page carries.
///
/// **Named once, because the two sides drifted silently.** `write_report` took
/// a `[u64; 32]` while the kernel had grown to read 34, so two words it printed
/// from were never written -- and unwritten page memory is zero, which is a
/// legitimate value for both of them. The boot report then stated, in a full
/// sentence, that the switch recorded no partner: a conclusion drawn entirely
/// from memory nobody had assigned. The array literal that feeds this function
/// must have exactly this many entries, and the compiler now says so.
const REPORT_WORDS: usize = 51;

/// **And tied to the machines behind its last four words.** Those four are
/// written out one per line, because an array literal is what `write_report`
/// takes -- so a fifth LACP machine would be a fifth address with nowhere to
/// go, and the total would still add up. This is what says it would not.
const _: () = assert!(REPORT_WORDS == 39 + 3 * LACP_MACHINES);

/// The last word, written with a sentinel so a reader can prove the page was
/// written to its full length rather than trusting that it was.
///
/// The marker at word 0 says *a* report is here; this says *this* report is,
/// all of it. Without the pair, a kernel that reads further than the service
/// writes cannot tell a zero it was given from a zero it invented.
const REPORT_TAIL: u64 = 0x4c49_4154_4450_4931;

/// This port's LACP machine, and what it has learned.
///
/// **Responsive rather than periodic, and that is a deliberate limit.** The
/// standard sends an LACPDU every one or thirty seconds, and this service has
/// no clock -- its cycle counter was retired at RFC 0026 step 5 and its loop
/// blocks in `receive` until a frame or a call arrives. So it sends when it
/// wakes and has something to say: a bounded burst at startup so an early
/// frame cannot be lost to a peer that is not up yet, and a reply to every
/// LACPDU that arrives. Two active peers converge in three exchanges that way.
///
/// What that does **not** do is expire a partner that goes quiet, which needs
/// the timer. `bhaskix_net::lacp::Machine` implements the expiry and a service
/// with a clock will drive it; nothing here pretends to.
/// Reads the interface the kernel published, if it has published one yet.
///
/// **Called from the serve loop as well as the demonstration**, because a
/// service that starts before its configuration arrives must still pick it up.
/// This was read only during the demonstration until 2026-09-06, and on a link
/// with no gateway that phase finishes before `bin/netd` has read the device's
/// address -- so `me` stayed unspecified for the life of the boot and nothing
/// this service might have sent was ever built. Two guests on a private link
/// is exactly that shape, and it is how the gap was found.
///
/// Sets the VLAN and the interface shape for the report as a side effect,
/// because both are derived from this page and neither has another source.
fn read_interface() -> Option<(MacAddr, Ipv4Addr)> {
    // SAFETY: the configuration page, mapped read-only by this program.
    let (marker, mac, address, vlan, mtu, ports, bond_lacp, peer) = unsafe {
        (
            core::ptr::read_volatile(CONFIG_AT as *const u64),
            core::ptr::read_volatile((CONFIG_AT + 8) as *const u64),
            core::ptr::read_volatile((CONFIG_AT + 16) as *const u64),
            core::ptr::read_volatile((CONFIG_AT + 24) as *const u64),
            core::ptr::read_volatile((CONFIG_AT + 32) as *const u64),
            core::ptr::read_volatile((CONFIG_AT + 40) as *const u64),
            core::ptr::read_volatile((CONFIG_AT + 48) as *const u64),
            core::ptr::read_volatile((CONFIG_AT + 56) as *const u64),
        )
    };
    let lacp_wanted = bond_lacp != 0;
    if marker != CONFIG_MARKER {
        return None;
    }
    // **The peer to ask about**, read only once the marker says the page is
    // true. Zero means the kernel named none and the default stands.
    GATEWAY_WORD.store(peer as u32, core::sync::atomic::Ordering::Relaxed);
    // **What each member is called**, words 7 onward, read only once the marker
    // says the page is true. Word 1 above is the *bond's* address, which is
    // what every datagram leaves under; these are the links' own, and an
    // LACPDU's source is the individual address of the link it goes out of.
    let mut members = [MacAddr::UNSPECIFIED; LACP_MACHINES];
    for (index, member) in members.iter_mut().enumerate() {
        // SAFETY: the same page, one word per member past the interface's own
        // seven -- `NETD_MEMBER_COUNT` of them, which is `LACP_MACHINES`.
        let word = unsafe {
            core::ptr::read_volatile((CONFIG_AT + CONFIG_MEMBERS + index as u64 * 8) as *const u64)
        };
        MEMBER_ADDRESSES[index].store(word, core::sync::atomic::Ordering::Relaxed);
        *member = mac_of(word);
    }
    let octets = mac_of(mac).0;
    // **RFC 0074: an address lives on an interface.** One port is a port;
    // several are a bond over them, and the address goes on the bond. Only the
    // first is driven -- `bin/netd` holds one device -- so the rest are
    // members whose link is down, which is what a real bond looks like when a
    // member's cable is out, and active-backup picks the live one.
    let mtu = if mtu == 0 { 1500 } else { mtu as u16 };
    let mut faces = bhaskix_net::interface::Interfaces::new();
    if let Ok(first) = faces.add_physical(0, MacAddr(octets), mtu) {
        faces.set_link(first, true);
        let mut on = first;
        // **The mode the boot asked for.** Active-backup needs nothing from the
        // switch and is the right default; a switch-side port-channel needs
        // 802.3ad, and on such a wire active-backup is not merely worse but
        // wrong -- the switch will not forward data to a member it has not
        // bundled. The SR550's four ports are one such channel.
        let mode = if lacp_wanted {
            bhaskix_net::interface::BondMode::Lacp
        } else {
            bhaskix_net::interface::BondMode::ActiveBackup
        };
        if ports > 1
            && let Ok(bond) = faces.add_bond(mode)
        {
            let mut joined = faces.enslave(bond, first).is_ok();
            for port in 1..ports.min(u64::from(u8::MAX)) {
                // **The member's own address, where the kernel published one.**
                // This was `MacAddr([0; 6])` with a comment saying the service
                // could not know it, and that was true until `bin/netd` began
                // reading every port's address and passing it up. A member the
                // driver never reached still has none, and zero still says so.
                let own = usize::try_from(port)
                    .ok()
                    .and_then(|index| members.get(index).copied())
                    .unwrap_or(MacAddr::UNSPECIFIED);
                if let Ok(other) = faces.add_physical(port as u16, own, mtu) {
                    joined |= faces.enslave(bond, other).is_ok();
                }
            }
            if joined {
                on = bond;
                BOND_MODE_LACP.store(
                    matches!(mode, bhaskix_net::interface::BondMode::Lacp),
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
        if vlan != 0
            && let Ok(tagged) = faces.add_vlan(on, vlan as u16)
        {
            on = tagged;
        }
        BOUND_VLAN.store(
            faces.egress_tag(on).map_or(NO_VLAN, u32::from),
            core::sync::atomic::Ordering::Relaxed,
        );
        // High half: the ports the kernel said there were. Low half: the
        // members the interface ended up with. Both, because "the address is
        // on a port" has two causes and one number cannot tell them apart.
        // **Count the members of what actually has members.** A VLAN sits
        // *over* an interface and has a parent, not members, so reading the
        // count off `on` reports zero the moment a tag is configured -- and the
        // boot then says "the address is on a port directly" about a bond that
        // was built correctly underneath. Measured on the SR550, 2026-09-08.
        let beneath = match faces.get(on).map(|face| face.kind) {
            Some(bhaskix_net::interface::Kind::Vlan { parent, .. }) => parent,
            _ => on,
        };
        BOUND_SHAPE.store(
            (ports << 32) | faces.get(beneath).map_or(0, |f| f.member_count() as u64),
            core::sync::atomic::Ordering::Relaxed,
        );
    }
    Some((MacAddr(octets), Ipv4Addr(address as u32)))
}

/// How many unsolicited LACPDUs to send before waiting to be spoken to.
///
/// A peer whose driver is not up yet drops the first frames, and with no timer
/// there is no second chance -- so there are a few first chances instead.
const LACP_OPENINGS: u32 = 8;

/// How many members this service will run a machine for.
///
/// Four, because `bin/netd`'s member array is four and the length prefix
/// carries the index in four bits. A bond with more members than this would
/// run machines for the first four and leave the rest unaggregated, which is
/// wrong rather than merely limited -- so the count is asserted against
/// `bin/netd`'s below.
const LACP_MACHINES: usize = 4;

const _: () = assert!(LACP_MACHINES as u32 <= ring::MEMBER_MASK >> ring::MEMBER_SHIFT);

/// **One 802.3ad state machine per link, which is what the standard says.**
///
/// This service ran a single machine until 2026-09-08, and duplicated its PDU
/// onto both members of the bond. A switch that sees two links claim one
/// `Actor_Port` has no aggregation it can form: the two frames describe one
/// port that cannot be in two places, so it answers each and synchronises
/// neither. The SR550 said exactly that -- state `0x05`, ACTIVITY and
/// AGGREGATION with no SYNC, on both links, for the whole boot.
///
/// So each member gets its own machine, with `Actor_Port = index + 1`, its own
/// partner, and its own PDU marked for the member it speaks for. The key is
/// shared, because the key is what says these links may aggregate together.
struct Bundle {
    each: [Option<bhaskix_net::lacp::Machine>; LACP_MACHINES],
    /// **The address each machine's frames leave under.**
    ///
    /// Not the system id, which is `Machine::actor.system` and is shared:
    /// 802.3ad says the links of one aggregation carry one system id, and that
    /// is what makes them aggregatable at all. This is the Ethernet header's
    /// source, which 802.1AX gives as *the individual MAC address of the port*
    /// -- a different field with a different rule, and both were the bond's
    /// address until 2026-09-10.
    source: [MacAddr; LACP_MACHINES],
}

impl Bundle {
    const fn new() -> Self {
        Self {
            each: [const { None }; LACP_MACHINES],
            source: [MacAddr::UNSPECIFIED; LACP_MACHINES],
        }
    }

    /// Starts a machine per member, once this service knows its own address.
    ///
    /// `members` is what the bond is made of; zero means the address sits
    /// straight on a port, which is one link and so one machine. `own` is what
    /// each of those links is called, as the kernel published it.
    fn arm(&mut self, me: MacAddr, members: usize, own: [MacAddr; LACP_MACHINES]) {
        for index in 0..members.clamp(1, LACP_MACHINES) {
            // **Set every pass, not only when the machine is created.** The
            // configuration page is read from the serve loop and a member's
            // address arrives when its port has been brought up, which can be
            // after this service has already started speaking for it. A source
            // fixed at creation would keep the fallback for the life of the
            // boot and nothing would say so.
            //
            // A member with no address of its own falls back to the bond's,
            // which is where this service was before there were any: worse than
            // the port's, and better than a frame with no source at all.
            let own = own[index];
            self.source[index] = if own == MacAddr::UNSPECIFIED { me } else { own };
            SPEAKING_AS[index].store(
                word_of(self.source[index]),
                core::sync::atomic::Ordering::Relaxed,
            );
            self.each[index].get_or_insert_with(|| {
                // The port id is what distinguishes the links. Numbered from
                // one because 802.3ad reserves zero for "no port".
                let mut fresh = bhaskix_net::lacp::Machine::new(me, 1, (index + 1) as u16);
                // Ask for the short timeout: a peer that honours it answers
                // promptly, which is what a boot-length gate needs.
                fresh.actor.state = fresh.actor.state.with(bhaskix_net::lacp::State::TIMEOUT);
                fresh
            });
        }
    }

    /// The machine speaking for `member`, if one is running, and the address it
    /// speaks under.
    fn member(&mut self, member: usize) -> Option<(u8, MacAddr, &mut bhaskix_net::lacp::Machine)> {
        let index = if member < LACP_MACHINES { member } else { 0 };
        let source = self.source[index];
        self.each[index]
            .as_mut()
            .map(|machine| (index as u8, source, machine))
    }

    /// Whether every running machine has aggregated.
    fn aggregated(&self) -> bool {
        self.each
            .iter()
            .flatten()
            .fold(None, |all: Option<bool>, m| {
                Some(all.unwrap_or(true) && m.aggregated())
            })
            .unwrap_or(false)
    }
}

/// What the machines have reached, for the report: the partner's key in the
/// high half and our own state flags in the low, or zero before one is running.
static LACP_STATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// **The partner's own flags**, one byte per link, as `LACP_STATE`'s low half
/// holds ours.
///
/// This is how a host with no access to the switch reads the switch's LACP
/// configuration: bit 0 of a partner's state is ACTIVITY, and a switch
/// configured *passive* advertises it clear. Every LACPDU carries it, and this
/// service was parsing it and throwing it away.
///
/// **Bits 32..35 say which links have heard a partner at all**, because a
/// partner's flags may legitimately be `0x00` and a zero byte would otherwise
/// be indistinguishable from silence.
static LACP_PARTNER_STATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// **Which VLANs the switch tags on each link**, up to four per link.
///
/// Four slots of sixteen bits: the id in bits 0-11 and bit 15 as *this slot
/// holds one*, so a VLAN of zero is distinguishable from an empty slot.
///
/// **The tag was being thrown away by the code that named it.**
/// `EthFrame::parse_on` refuses a foreign tag with `Unsupported { field:
/// "802.1Q tag for another VLAN", value: id }` -- the id is right there in the
/// refusal -- and `refuse` recorded only the reason. A trunk's whole character
/// is which VLANs it carries, and this service was discarding that on every
/// frame it declined.
///
/// Per link, because the question is what the switch sends *on those ports* and
/// four ports need not be configured alike.
static VLANS_SEEN: [core::sync::atomic::AtomicU64; LACP_MACHINES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; LACP_MACHINES];

/// Records a VLAN seen on a link, if there is a slot free and it is new.
///
/// This service runs one loop on one thread, so a plain read-modify-write is
/// the whole of it; a race here would cost a duplicate slot and nothing else.
fn saw_vlan(member: Option<u8>, id: u16) {
    use core::sync::atomic::Ordering::Relaxed;
    let link = member.map_or(0, usize::from).min(LACP_MACHINES - 1);
    let held = VLANS_SEEN[link].load(Relaxed);
    let tagged = 1u64 << 15;
    let entry = u64::from(id & 0xfff) | tagged;
    let mut free = None;
    for slot in 0..4 {
        let at = slot * 16;
        let seen = held >> at & 0xffff;
        if seen == entry {
            return;
        }
        if seen == 0 && free.is_none() {
            free = Some(at);
        }
    }
    if let Some(at) = free {
        VLANS_SEEN[link].store(held | entry << at, Relaxed);
    }
}

/// **What the neighbour says it is**, from its LLDP frames.
///
/// The switch has been describing itself on every boot and this service refused
/// the frames -- `last refusal reason 2, on a frame of 171 bytes with ethertype
/// 0x88cc`. RFC 0076 spent a week asking what the switch thinks of a
/// port-channel this host has no login to, with 171 bytes of its own account
/// arriving every thirty seconds.
///
/// An **inventory rather than a reading**: which TLV types it sends, how many,
/// and the first organizationally specific TLV's OUI and subtype. Only what the
/// C620 datasheet grounds is decoded -- see `bhaskix_net::lldp`. What the switch
/// actually sends decides what is worth decoding next, which is a question for
/// evidence rather than for recall.
///
/// Bits 0-31 the type bitmap, 32-39 the count, 40-47 the organizationally
/// specific count, 48 whether the walk ended cleanly, 49 whether any frame was
/// seen at all.
static LLDP_SEEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The neighbour's port id **per member**: its subtype in bits 48-55 and its
/// first six octets below, or zero before one has arrived on that link.
///
/// **The port id is the half that names the switch's own port**, which is what
/// a question about a port-channel is ultimately about -- and one global was
/// the wrong shape for it. LLDP arrives on all four members and the first
/// version of this kept whichever frame landed last, so a bond facing four
/// switch ports reported one of them and could not have shown otherwise. Four
/// links reaching one port and four links reaching four are the two answers
/// that matter, and a single word cannot tell them apart.
static LLDP_PORT: [core::sync::atomic::AtomicU64; LACP_MACHINES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; LACP_MACHINES];

/// The first organizationally specific TLV's OUI in bits 0-23 and subtype in
/// 24-31.
static LLDP_ORGANISATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// **Where the neighbour says it can be reached** -- its management address TLV,
/// family in bits 0-7, length in 8-15, the first four octets above them, and
/// bit 56 set when one was seen at all.
///
/// The switch has sent nine TLVs on every frame since the first boot and this
/// service decoded four of them. One of the five it passed over is the address
/// of the one machine whose configuration this work cannot otherwise read --
/// six hypotheses were raised and killed about a host that turns out to be
/// emitting correct frames, and the switch was saying where to go and look the
/// whole time.
static LLDP_MANAGEMENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// And what it calls itself -- the system name TLV, eight bytes, first on the
/// wire in the low byte.
static LLDP_NAME: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// **Where the ARP request stopped, when it stopped.** Tries at 19:0, frames it
/// could not build at 39:20, sends the ring refused at 59:40.
///
/// A single zero for *asked none* is compatible with never reaching the block,
/// with failing to build the frame, and with the ring refusing it, and those
/// are three different faults. Hardware reported `asked 0 time(s)` beside a
/// rising `built` and none of them could be told apart.
///
/// **A static because this report is built in two places** -- `refresh` and
/// `report` -- and only one of them can see the loop's locals. Every other
/// value that crosses that boundary here is a static for the same reason; a
/// parameter would have been the third attempt at the same lesson.
static ASK_STALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Packs the three counts the way [`ASK_STALLS`] carries them.
fn ask_stalls(tries: u64, unbuilt: u64, unsent: u64) -> u64 {
    tries.min(0xf_ffff) | (unbuilt.min(0xf_ffff) << 20) | (unsent.min(0xf_ffff) << 40)
}

/// **What the partner records as its own partner** -- what the switch believes
/// is at our end of link 0.
///
/// Its key in bits 0..15, its port in bits 16..31, and bit 32 set once any
/// record has been heard. `lacp::Machine::received` synchronises only when this
/// names *this* port -- same system, same key, same port -- so a link stuck
/// unsynchronised is explained by this word and by nothing else in the report:
/// a switch that names another port and a switch that names nothing look
/// identical from our own flags.
static LACP_RECORDED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Publishes what the bundle believes, so the boot report can say it.
///
/// **One byte per link, not one number for the bundle.** The first version of
/// this function published the bitwise AND of every machine's flags, on the
/// reasoning that a bundle is up only when each link is synchronised -- which
/// is true, and which made the report unable to say anything else. `0x05` then
/// meant *either* "neither link synchronised" *or* "one did and one did not",
/// and on the SR550, where the switch bundles four ports and this kernel drives
/// two, those are completely different findings. A boot cannot be re-read; a
/// number that cannot distinguish them throws the distinction away.
///
/// So each machine's flags go in their own byte, machine `n` at bit `8 * n`,
/// and the kernel derives the verdict from all of them. A byte of zero is *no
/// machine*: a running one always has ACTIVITY set, so zero is unambiguous.
/// Machine 0 keeps the low byte, which is where the single-machine version put
/// it, so a reader of the old shape still reads a true thing.
///
/// The partner key is the first one learned; the links are meant to report the
/// same key, and a switch that gave two would not aggregate them anyway.
fn lacp_publish(bundle: &Bundle) {
    let mut links = 0u64;
    let mut partner = 0;
    for (index, machine) in bundle.each.iter().enumerate() {
        let Some(machine) = machine else {
            continue;
        };
        links |= u64::from(machine.actor.state.0) << (8 * index);
        if partner == 0 {
            partner = machine.partner.map_or(0, |p| u64::from(p.key) | 1 << 16);
        }
    }
    LACP_STATE.store(
        (partner << 32) | links,
        core::sync::atomic::Ordering::Relaxed,
    );

    // **The other side of the same PDU.** Their flags per link, and their
    // record of us on link 0 -- the two things that say whether the switch is
    // active and whether it has us right.
    //
    // **A heard bit per link, separate from the flags.** Our own byte can use
    // zero to mean "no machine", because a running machine always has ACTIVITY
    // set. A *partner's* byte cannot: `0x00` is a legitimate advertisement --
    // passive, individual, unsynchronised -- and the first version of this word
    // treated it as absence, so the one boot that measured it could not say
    // whether the switch had answered with all flags clear or had not answered
    // at all. Those are opposite conclusions.
    let mut theirs = 0u64;
    for (index, machine) in bundle.each.iter().enumerate() {
        if let Some(partner) = machine.as_ref().and_then(|m| m.partner) {
            theirs |= u64::from(partner.state.0) << (8 * index);
            theirs |= 1 << (32 + index);
        }
    }
    LACP_PARTNER_STATE.store(theirs, core::sync::atomic::Ordering::Relaxed);

    let recorded = bundle.each[0]
        .as_ref()
        .and_then(|machine| machine.recorded)
        .map_or(0, |them| {
            u64::from(them.key) | u64::from(them.port) << 16 | 1 << 32
        });
    LACP_RECORDED.store(recorded, core::sync::atomic::Ordering::Relaxed);
}

/// LACPDUs this service has put on the wire, and slow-protocol frames that have
/// come back.
///
/// **So that "the switch did not answer" is a measurement.** Without these, a
/// boot that sends nothing and a boot whose partner is silent produce the same
/// report -- and this session has already twice mistaken the first for the
/// second. Sent in the high half, received in the low.
static LACP_TRAFFIC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Counts one LACPDU sent.
fn lacp_sent() {
    LACP_TRAFFIC.fetch_add(1 << 32, core::sync::atomic::Ordering::Relaxed);
}

/// Counts one slow-protocol frame received.
fn lacp_heard() {
    LACP_TRAFFIC.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Which bond the interface was actually built as, for the report.
///
/// **Not what was asked for -- what exists.** The boot report said
/// "active-backup" as a hardcoded word, so it would have printed that for an
/// 802.3ad bond too, and no reader could have told. A report that states
/// something it never read is worse than one that says nothing.
static BOND_MODE_LACP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// What the bound interface is made of, for the report: the number of members
/// under it, or zero when the address sits straight on a port.
///
/// The gates read this to say whether the stack is running over a bond, which
/// is the whole of RFC 0074 step 6's claim.
static BOUND_SHAPE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The VLAN the bound interface carries, or `NO_VLAN`.
///
/// A static because the receive path is two calls below where the interface
/// table lives, and this file already carries its cross-function state this
/// way rather than threading a parameter through signatures that are near
/// clippy's limit. Written once, when the kernel says what this interface is.
static BOUND_VLAN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(NO_VLAN);

/// What [`BOUND_VLAN`] holds before an interface is known, and for an untagged
/// one. Both mean the same thing to `EthFrame::parse_on`: take untagged frames
/// and refuse tagged ones.
const NO_VLAN: u32 = u32::MAX;

/// The VLAN to parse arriving frames for.
fn bound_vlan() -> Option<u16> {
    match BOUND_VLAN.load(core::sync::atomic::Ordering::Relaxed) {
        NO_VLAN => None,
        id => Some(id as u16),
    }
}

/// The marker the kernel writes before this program's configuration is true.
const CONFIG_MARKER: u64 = 0x3146_4e43_5049_5f4e;

/// Byte offset on that page of the members' own station addresses.
///
/// Eight words in, after the interface's own: the marker, the bond's address,
/// the protocol address, the VLAN, the MTU, the port count, the bond mode and
/// the peer to ask about. The kernel's `NETD_MEMBER_COUNT` addresses follow,
/// and that number is this program's [`LACP_MACHINES`] -- four in three places,
/// which is the width of the interface between them.
const CONFIG_MEMBERS: u64 = 8 * 8;

/// A station address as the configuration page carries it.
///
/// Six octets in the low 48 bits, most significant first, which is the order a
/// MAC is written in. Named because the members' addresses would otherwise have
/// been the second place in this file writing that shift out, and the pair with
/// [`word_of`] is what says the two directions agree.
fn mac_of(word: u64) -> MacAddr {
    let mut octets = [0u8; 6];
    for (index, octet) in octets.iter_mut().enumerate() {
        *octet = (word >> (40 - index * 8)) as u8;
    }
    MacAddr(octets)
}

/// Each bond member's **own** station address, as the kernel last published it.
///
/// Static because the page is read in one place and the addresses are wanted in
/// another: `read_interface` runs from the serve loop, and the LACP machines are
/// armed beside it.
static MEMBER_ADDRESSES: [core::sync::atomic::AtomicU64; LACP_MACHINES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; LACP_MACHINES];

/// Them, as addresses.
fn member_addresses() -> [MacAddr; LACP_MACHINES] {
    core::array::from_fn(|index| {
        mac_of(MEMBER_ADDRESSES[index].load(core::sync::atomic::Ordering::Relaxed))
    })
}

/// A station address as one word -- [`mac_of`] the other way about.
fn word_of(address: MacAddr) -> u64 {
    address
        .0
        .iter()
        .fold(0u64, |word, octet| (word << 8) | u64::from(*octet))
}

/// **What each LACP machine's frames actually leave under**, for the report.
///
/// Distinct from [`MEMBER_ADDRESSES`], which is what the kernel published: a
/// member the driver never read an address for falls back to the bond's, and
/// this is the address after that fallback. The report carries this one,
/// because "four links, four addresses" is the claim being made and the
/// published half cannot prove it.
static SPEAKING_AS: [core::sync::atomic::AtomicU64; LACP_MACHINES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; LACP_MACHINES];

/// The address this program asks about, to prove it can send.
///
/// **Deliberately not the one `bin/netd`'s probe asks for.** The driver asks
/// for `10.0.2.2`; this asks for `10.0.2.3`, so a request for `.3` on the wire
/// is a frame that can only have been built here, crossed the return ring, and
/// been transmitted by a program that cannot parse it. One byte of difference
/// is what makes the two distinguishable to a test.
const ASK_ABOUT: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);

/// What an ARP request actually asks about.
///
/// **The third emulator constant in this pair of files, and the one that
/// decided the answer.** [`ASK_ABOUT`] is deliberately a different address from
/// the ping's target so a test can tell an ARP request from an echo request --
/// sound under QEMU, and it means every SR550 boot asked the wire about
/// `10.0.2.3` while the report said `0 arp mappings learned`.
///
/// When the kernel names a peer, that is the address worth resolving, so both
/// follow it. The QEMU lanes name none and keep the two distinct addresses the
/// test relies on.
fn ask_about() -> Ipv4Addr {
    let told = GATEWAY_WORD.load(core::sync::atomic::Ordering::Relaxed);
    if told == 0 { ASK_ABOUT } else { Ipv4Addr(told) }
}

/// The address this program asks about and pings, when the kernel names none.
///
/// QEMU's built-in network answers an echo request to its gateway, which makes
/// a *sent* ping the demonstrable half of ICMP here. Answering one is written
/// and untestable on that network: nothing has a reason to ping us.
///
/// **On hardware it is a question nobody can answer.** `10.0.2.2` is what slirp
/// replies at; on a real wire an ARP request for it resolves nothing, and every
/// SR550 boot reported `0 arp mappings learned` while that was read as evidence
/// about the segment rather than about the address being asked for.
///
/// The twin of the interface's own address, which was corrected first -- and
/// the peer a host *asks about* is as much an emulator constant as the address
/// it *claims*. `bhaskix.gw=<a.b.c.d>` sets it, through the configuration page.
const GATEWAY_DEFAULT: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

/// What the kernel said to ask about, or [`GATEWAY_DEFAULT`].
static GATEWAY_WORD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The peer to ask about and ping.
///
/// Named for what it is rather than `gateway`, which is already a local binding
/// for the *resolved MAC* of this address in two places -- and a function
/// shadowed by a variable of the same name is a compile error today and a
/// confusion for ever after.
fn peer_address() -> Ipv4Addr {
    let told = GATEWAY_WORD.load(core::sync::atomic::Ordering::Relaxed);
    if told == 0 {
        GATEWAY_DEFAULT
    } else {
        Ipv4Addr(told)
    }
}

/// What this program puts in an echo request, and expects back unchanged.
const PING_PAYLOAD: [u8; 17] = *b"bhaskix-icmp-0001";

/// The v6 face of the same host: slirp answers at `fec0::2` on its default
/// prefix, the way `10.0.2.2` answers on the v4 side.
const HOST6: Ipv6Addr = Ipv6Addr::new([0xfec0, 0, 0, 0, 0, 0, 0, 2]);

/// The v6 demonstration ping's identifier. Distinct from the v4 ping's and
/// from [`BURST_ID`], because the identifier is how replies are told apart.
const PING6_ID: u16 = 0xbe59;

/// `::1`. Self-addressed traffic never touches a wire on a correct stack;
/// a datagram sent here is delivered to the matching socket directly.
const LOOPBACK6: Ipv6Addr = Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

/// RFC 0018 step 7: the burst that prices the two-domain split.
///
/// Every packet in this burst crosses the boundary twice — once from `bin/netd`
/// into this program, once back — and each crossing is a copy. The RFC claims
/// that costs "two copies and two domain crossings per packet"; this is the
/// traffic that makes the claim checkable, and `COPIES` is what checks it.
///
/// ICMP echo because it is the only flow QEMU's gateway answers. The identifier
/// is this program's own and differs from the single demonstration ping above,
/// so the gate that asserts *that* ping came back unchanged still means what it
/// meant before.
const BURST: u32 = 256;
/// Payload sizes: the smallest worth sending, and near a full frame.
const BURST_SMALL: usize = 16;
const BURST_LARGE: usize = 1400;
/// Whose replies these are.
const BURST_ID: u16 = 0xbe58;
/// Requests a pipelined phase keeps in flight at once.
///
/// **Not unbounded, and the bound is the point.** "Pipelined" first meant "send
/// all 256 without waiting", which for 1400-byte packets is 369 KiB pushed at a
/// 64 KiB ring: the ring overran, frames were dropped at both ends, the phase
/// never collected its replies and `bin/ipd` went quiet and left for `serve`
/// with the measurement half done. A sender that overruns its own ring is
/// measuring drops, not throughput.
///
/// Sixteen frames is 23 KiB at the largest payload — comfortably inside a ring
/// — and is still sixteen times the serialised phase's one.
const BURST_WINDOW: u32 = 16;
/// Passes to wait for a phase's replies before giving up on it. Bounded because
/// a burst that never finishes would keep this program out of `serve`, and the
/// shell, the DHCP client and every socket wait behind that.
///
/// **The pipelined 1400-byte phase needs this and does not reach 256 replies.**
/// Two hundred and fifty-six frames of 1442 bytes is 369 KiB, and each ring is
/// 64 KiB, so a sender that does not wait overruns the ring and frames are
/// dropped at both ends. That is a real property of this boundary — the rings
/// are a fixed size and a fixed size refuses — and the phase reports how many
/// replies it actually got rather than pretending to a round number.
const BURST_PATIENCE: u32 = 20_000;

/// How many burst phases have finished. The kernel stamps the clock when this
/// moves, which is how a program with no clock gets timed.
static BURST_PHASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Replies counted in the phase now running.
static BURST_PONGS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Requests sent in the phase now running.
static BURST_SENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Times `receive` came back because a frame arrived rather than a caller.
///
/// The number that says RFC 0010 question 1's answer is **used** rather than
/// merely wired. Zero here would mean the binding never fired and any speed-up
/// came from somewhere else.
static NOTIFIED_WAKES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Passes round the demonstration loop that found the ring empty.
///
/// **Measured before anything is changed.** RFC 0010 step 2 gave `bin/ipd` a
/// doorbell to `bin/netd` and the round-trip latency did not move, which leaves
/// the other direction as the standing hypothesis: `netd` cannot tell this
/// program a frame has arrived, so this program polls, and every look that
/// finds nothing is a `YIELD` and a scheduling round trip.
///
/// If that is where the time goes, these counters are large. If this program
/// takes a frame within a look or two of it being published, the polling is not
/// the cost and the hypothesis is wrong. A change made before this is measured
/// would be a guess with a diff attached.
static EMPTY_POLLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The longest run of empty looks between two frames.
static LONGEST_WAIT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Replies the phase that just finished actually got.
///
/// Kept separately because the running counters reset when a phase ends, and
/// the kernel reads the page after the edge rather than on it. Without this a
/// phase that answered 61 of 64 would be indistinguishable from one that
/// answered all of them.
static BURST_RESULT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How long a learned mapping is believed, in **frames handled**.
///
/// This program has no clock — `bhaskix-net` takes time as an argument
/// precisely so it does not need one — so what is passed in is a monotonic
/// count of frames rather than nanoseconds. A lie of units and not of ordering:
/// entries still expire in the order they were learned, which is the property
/// the cache's own tests check.
///
/// It was a count of *loop passes* first, which runs at the speed of a spin, so
/// a thousand of them elapsed in milliseconds and the cache always read empty.
/// A clock has to tick at the rate of the thing it is timing.
const ARP_LIFETIME: u64 = 1_000;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the kernel
    // can see it beats carrying on with a ring in an unknown state.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let mut value = args[0];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as an
    // output because the kernel writes the whole frame back on the way out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            inlateout("r10") args[1] => _,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// Blocks until a request arrives, and returns `(status, badge, method, args)`.
///
/// The caller is not returned, because the kernel remembers it: a service that
/// could name its own reply target could answer a question nobody asked it.
///
/// **This is a real sleep**, and it is what turns this program from a poll loop
/// into a service. Until step 5 it spun on the ring and stopped when quiet,
/// because it had nothing to wait on; an endpoint is something to wait on.
fn receive() -> (u64, u64, u64, [u64; 4]) {
    let status: u64;
    let mut badge = ENDPOINT;
    let mut method = 0u64;
    let (mut a0, mut a1, mut a2, mut a3) = (0u64, 0u64, 0u64, 0u64);
    // SAFETY: the system call convention from RFC 0008. Every argument register
    // is an output because the kernel writes the whole frame back.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") syscall::RECV => status,
            inlateout("rdi") badge,
            inlateout("rsi") method,
            inlateout("rdx") a0,
            inlateout("r10") a1,
            inlateout("r8") a2,
            inlateout("r9") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, badge, method, [a0, a1, a2, a3])
}

/// Answers the caller this thread received from, and nobody else.
fn reply(outcome: u64, a1: u64, a2: u64) {
    let _ = call(syscall::REPLY, 0, 0, [outcome, a1, a2, 0]);
}

/// Maps a capability at an address, and says whether it worked.
fn attach(slot: u64, at: u64, writable: u64) -> bool {
    call(syscall::INVOKE, slot, method::ATTACH, [at, writable, 0, 0]).0 == status::OK
}

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Whether this EtherType is a frame the *wire* carries rather than a VLAN.
///
/// **On a trunk port these go untagged, both ways.** LACP is how a switch
/// decides whether a link is in its aggregate at all, and LLDP is how it says
/// what it is; both are scoped to the physical link and neither belongs to any
/// VLAN on it. Tagging them would hide them from the switch, and refusing the
/// untagged ones on receive would make this service deaf to exactly the
/// traffic that brings a bundle up.
fn is_link_control(ethertype: EtherType) -> bool {
    /// 802.1AB LLDP.
    const LLDP: u16 = 0x88cc;
    ethertype.0 == bhaskix_net::lacp::ETHERTYPE || ethertype.0 == LLDP
}

/// Hands one frame to `bin/netd` to put on the wire, **tagged if this
/// interface is**.
///
/// **The tag goes on here and nowhere else.** An interface's VLAN is a property
/// of leaving it -- `Interface::egress_tag` says exactly that -- so every frame
/// this program builds is built untagged and tagged once, at the door. The
/// alternative was to teach twenty-one call sites that a header is sometimes
/// eighteen bytes instead of fourteen, which is twenty-one chances to get an
/// offset wrong for one behaviour.
///
/// **This is why nothing on the SR550 ever answered.** Its four ports are a
/// switch-side trunk carrying tagged VLANs; every frame this project put on
/// that wire was untagged, and an untagged frame on a trunk port reaches none
/// of them. `bin/ipd` has parsed *for* its bound VLAN since RFC 0074 and has
/// never sent one.
///
/// # Safety
///
/// The return ring must be mapped writable at [`BACK_AT`].
unsafe fn send(frame: &[u8]) -> bool {
    if let Some(id) = bound_vlan()
        && frame.len() >= eth::HEADER
        && !is_link_control(EtherType(u16::from_be_bytes([frame[12], frame[13]])))
    {
        let vlan = eth::Vlan::id(id);
        // Addresses, then the tag, then the EtherType the payload really is and
        // everything after it. `write_tagged_header` lays the first eighteen
        // bytes out; the rest is the frame from its EtherType on.
        let mut tagged = [0u8; MAX_FRAME + eth::Vlan::BYTES];
        let (Ok(destination), Ok(source)) = (
            <[u8; 6]>::try_from(&frame[0..6]),
            <[u8; 6]>::try_from(&frame[6..12]),
        ) else {
            return false;
        };
        let ethertype = EtherType(u16::from_be_bytes([frame[12], frame[13]]));
        let body = &frame[eth::HEADER..];
        let total = eth::HEADER + eth::Vlan::BYTES + body.len();
        if total <= tagged.len()
            && eth::write_tagged_header(
                &mut tagged,
                MacAddr(destination),
                MacAddr(source),
                vlan,
                ethertype,
            )
            .is_ok()
        {
            tagged[eth::HEADER + eth::Vlan::BYTES..total].copy_from_slice(body);
            // SAFETY: the caller's obligation, unchanged.
            return unsafe { send_untagged(&tagged[..total]) };
        }
        return false;
    }
    // SAFETY: the caller's obligation.
    unsafe { send_untagged(frame) }
}

/// Puts `frame` on the ring exactly as given.
///
/// # Safety
///
/// As [`send`].
unsafe fn send_untagged(frame: &[u8]) -> bool {
    // SAFETY: the caller's obligation.
    // Ordinary traffic is switched normally: it is addressed to somebody the
    // internal switch can route to, and the wire is where that lands anyway.
    unsafe { send_from(frame, None, false) }
}

/// The same, naming the **member** the frame must leave by.
///
/// `None` means whichever member carries traffic, which is every frame but an
/// LACPDU. An LACPDU speaks for one link and carries that link's port id, so it
/// names the member its machine belongs to.
///
/// `uplink` says the frame must reach the wire rather than the device's own
/// switch -- see [`ring::UPLINK`]. Only this service can say so: the driver
/// holds DMA and may not read a frame, so it cannot tell a control frame from a
/// datagram, and an X722's internal switch eats the former unless told.
///
/// # Safety
///
/// As [`send`].
unsafe fn send_from(frame: &[u8], member: Option<u8>, uplink: bool) -> bool {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return false;
    };
    // SAFETY: the ring's header, in the region this program mapped. Volatile
    // because the consumer is another domain and takes no lock.
    let (head, tail) = unsafe {
        (
            core::ptr::read_volatile((BACK_AT + ring::HEAD_OFFSET as u64) as *const u64),
            core::ptr::read_volatile((BACK_AT + ring::TAIL_OFFSET as u64) as *const u64),
        )
    };
    // Where the frame goes, from `abi::ring` rather than from arithmetic
    // written here. See `frame_to_write`.
    let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
        return false;
    };
    let Some(framed) = ring::frame_to_write(layout, cursor, frame.len()) else {
        return false;
    };
    // The length, and the mark that says where it goes. `bin/netd` reads an
    // index and never the frame -- see `ring::mark`.
    let prefix = ring::mark(frame.len() as u32, member, uplink).to_le_bytes();
    // SAFETY: every offset is `abi::ring`'s, inside the region this program
    // mapped writable, and `frame` is a slice it owns.
    unsafe {
        write_runs(BACK_AT, prefix.as_ptr(), framed.prefix);
        write_runs(BACK_AT, frame.as_ptr(), framed.payload);
    }
    // Outbound, copy one of two: this program's frame into the return ring.
    copied();
    // The bytes, then a fence, then the index that publishes them. The reader
    // is another domain on another CPU and takes no lock.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (BACK_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    // **Then ring the doorbell.** Index first, wake second: a driver woken
    // before the index was published would look, find nothing, and go back to
    // sleep holding a frame that had already been written. The same ordering
    // the bytes and the index have, for the same reason, one level up.
    //
    // Unchecked, deliberately. On a machine with no interrupt to delegate there
    // is no notification and this slot is empty, which is a refusal rather than
    // a fault — and a driver that cannot be woken is one that is not asleep.
    call(syscall::INVOKE, DOORBELL, method::SIGNAL, [0; 4]);
    true
}

/// Builds an Ethernet frame carrying `payload` as `ethertype`.
///
/// Returns how many bytes of `into` were used. Every byte of this comes from
/// `bhaskix-net`, which is the point: the framing is the same code the parser
/// on the other side of the wire is tested against.
fn frame(
    into: &mut [u8],
    destination: MacAddr,
    source: MacAddr,
    ethertype: EtherType,
    payload: &[u8],
) -> Option<usize> {
    eth::write_header(into, destination, source, ethertype).ok()?;
    let end = eth::HEADER + payload.len();
    into.get_mut(eth::HEADER..end)?.copy_from_slice(payload);
    Some(end)
}

/// Builds an Ethernet + IPv6 frame around an ICMPv6 message.
///
/// Returns how many bytes of `into` were used. `hop` is 255 for neighbour
/// discovery — the specification's proof-of-no-router — and an ordinary 64
/// for echo.
#[allow(clippy::too_many_arguments)]
fn frame6(
    into: &mut [u8],
    destination_mac: MacAddr,
    source_mac: MacAddr,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    hop: u8,
    message: &[u8],
) -> Option<usize> {
    eth::write_header(into, destination_mac, source_mac, EtherType::IPV6).ok()?;
    ipv6::write_header(
        &mut into[eth::HEADER..],
        source,
        destination,
        NextHeader::ICMPV6,
        hop,
        message.len(),
    )
    .ok()?;
    let at = eth::HEADER + ipv6::HEADER;
    let end = at + message.len();
    into.get_mut(at..end)?.copy_from_slice(message);
    Some(end)
}

/// What this program was able to do, as bits.
///
/// Bit 2 is whether the TCP rings attached, which cannot be a one-shot answer:
/// the kernel installs them after this program starts, so the bit may be clear
/// on an early report and set on a later one — and a final report with it
/// still clear is the finding that matters.
fn state(can_send: bool, mac: MacAddr, can_tcp: bool) -> u64 {
    u64::from(can_send)
        | (u64::from(mac != MacAddr::UNSPECIFIED) << 1)
        | (u64::from(can_tcp) << 2)
        | (u64::from(SERVING_NOW.load(core::sync::atomic::Ordering::Relaxed)) << 3)
}

/// Copies `source` into a ring mapped at `base`, at the offsets `runs` names.
///
/// It hardcoded the return ring until RFC 0020 step 4 gave this program a
/// second ring it produces into, and one reviewed copy routine beats two that
/// agree by inspection.
///
/// # Safety
///
/// `runs` must be offsets `abi::ring` computed for the region mapped writable
/// at `base`, and `source` readable for their combined length.
unsafe fn write_runs(base: u64, source: *const u8, runs: (ring::Run, ring::Run)) {
    let (first, second) = runs;
    // SAFETY: the caller's obligation; a wrap's two halves do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source,
            (base + first.offset as u64) as *mut u8,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                source.add(first.length),
                (base + second.offset as u64) as *mut u8,
                second.length,
            );
        }
    }
}

/// Copies out of a ring mapped at `base` at the offsets `runs` names.
///
/// # Safety
///
/// `runs` must be offsets `abi::ring` computed for the region mapped at
/// `base`, and `into` writable for their combined length.
unsafe fn read_runs(base: u64, into: *mut u8, runs: (ring::Run, ring::Run)) {
    let (first, second) = runs;
    // SAFETY: as above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (base + first.offset as u64) as *const u8,
            into,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                (base + second.offset as u64) as *const u8,
                into.add(first.length),
                second.length,
            );
        }
    }
}

/// Builds and hands over one UDP datagram.
///
/// Every layer of it comes from `bhaskix-net`: the same code the parser on the
/// other side of the wire is tested against, and the reason this program can
/// send a correct packet without knowing how to drive anything.
/// Builds and sends one v6 datagram: UDP over IPv6 over Ethernet, every
/// byte from `bhaskix-net`, everything routed via `via` — the router's
/// link address, the same one-road discipline the v4 path has with its
/// gateway.
fn send_datagram6(
    me_mac: MacAddr,
    via: MacAddr,
    from: Ipv6Addr,
    to: Ipv6Addr,
    from_port: u16,
    to_port: u16,
    payload: &[u8],
) -> bool {
    let mut out = [0u8; MAX_FRAME];
    let at = eth::HEADER + ipv6::HEADER;
    let body = match udp::write6(
        &mut out[at..],
        Port(from_port),
        Port(to_port),
        payload,
        from,
        to,
    ) {
        Ok(body) => body,
        Err(_) => return false,
    };
    if ipv6::write_header(&mut out[eth::HEADER..], from, to, NextHeader::UDP, 64, body).is_err()
        || eth::write_header(&mut out, via, me_mac, EtherType::IPV6).is_err()
    {
        return false;
    }
    // SAFETY: the return ring is mapped writable.
    unsafe { send(&out[..at + body]) }
}

fn send_datagram(
    me: (MacAddr, Ipv4Addr),
    gateway: MacAddr,
    from: u16,
    to: Ipv4Addr,
    to_port: u16,
    payload: &[u8],
) -> bool {
    let mut out = [0u8; MAX_FRAME];
    let body = match udp::write(
        &mut out[eth::HEADER + ipv4::HEADER..],
        Port(from),
        Port(to_port),
        payload,
        me.1,
        to,
    ) {
        Ok(body) => body,
        Err(_) => return false,
    };
    if ipv4::write_header(
        &mut out[eth::HEADER..],
        me.1,
        to,
        Protocol::UDP,
        body,
        0x2603,
    )
    .is_err()
    {
        return false;
    }
    // Broadcast at layer two when the destination is the broadcast address:
    // a client with no address is answering nobody in particular, and sending
    // that to the gateway's MAC would be asking one station a question meant
    // for all of them.
    let destination = if to == Ipv4Addr::BROADCAST {
        MacAddr::BROADCAST
    } else {
        gateway
    };
    if eth::write_header(&mut out, destination, me.0, EtherType::IPV4).is_err() {
        return false;
    }
    // SAFETY: the return ring is mapped writable by this program.
    unsafe { send(&out[..eth::HEADER + ipv4::HEADER + body]) }
}

/// Datagrams placed into a bound socket. See `drain_ring`.
static DELIVERED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Bulk copies of a packet's bytes this program has made.
///
/// **Counted rather than reasoned about**, which is RFC 0018's own wording. See
/// the same counter in `bin/netd`: together they are what prices the boundary,
/// because every one of these copies exists only because the driver and the
/// protocol code are in different domains. The four-byte length prefix in front
/// of each frame is not a packet and is not counted.
static COPIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Adds one to [`COPIES`].
fn copied() {
    COPIES.store(
        COPIES.load(core::sync::atomic::Ordering::Relaxed) + 1,
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Frames taken from the ring **while serving**, which nothing used to count.
static TAKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where `drain_ring` has read up to, so the report can show it.
static SERVING_TAIL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Why the last frame was not given to a socket.
///
/// `drain_ring` has seven ways to refuse a frame and reported none of them, so
/// a datagram that never reached a socket was indistinguishable from one that
/// never arrived. Each refusal is a different bug, and a count of zero
/// deliveries names none of them.
static WHY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The ports this service holds, packed four to a word — RFC 0063.
///
/// **A static and a word of its own, because words 9 and 10 are taken.** The
/// first version of this instrument wrote straight into the report page at
/// word 9 with `write_volatile` — which is `DELIVERED` — and word 10, which is
/// `WHY`, clobbering the delivery count, the last refusal reason, the frame
/// size and the ethertype that the kernel's "ipd after" line prints. Its own
/// comment claimed word nine was "past the eight `report` writes"; `report`
/// writes twenty-three. It went green because the values coincided —
/// `DELIVERED` was 2, and a single socket on port 2 packs to 2 — which is the
/// worst way for a defect to pass. That is precisely the mistake the comment
/// beside the report array warns about, made again by someone who had not read
/// it, and it is corrected here rather than quietly dropped.
static BOUND_PORTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The generation of each of the low four slots, packed four to a word.
static SLOT_GENERATIONS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Slots four and five, as `port`, `generation`, `port`, `generation`.
static UPPER_SLOTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Refusal codes for [`WHY`], in the order `drain_ring` applies them.
mod why {
    pub const NOT_A_FRAME: u64 = 1;
    pub const NOT_IPV4: u64 = 2;
    pub const NOT_A_HEADER: u64 = 3;
    pub const NOT_UDP: u64 = 4;
    pub const NOT_FOR_US: u64 = 5;
    pub const NOT_A_DATAGRAM: u64 = 6;
    pub const NO_SOCKET: u64 = 7;
}

/// Records why a frame was refused, **with the bytes that caused it**.
///
/// The code alone said "not IPv4" of a frame that certainly was one, which is
/// a claim about the parser or a claim about the bytes and no way to tell
/// which. The length and ethertype the program actually read decide it.
fn refuse(code: u64, length: usize, ethertype: u16) {
    WHY.store(
        code | ((ethertype as u64) << 16) | ((length as u64) << 32),
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// The last full report, so that [`refresh`] can rewrite the page.
///
/// # Why this exists
///
/// Every `report` call in this program is in `ipd_main`, so the page stopped
/// changing the moment `serve` was entered — and `serve` is where all the
/// interesting work happens. The kernel then read eleven frames and nothing
/// delivered, and that was true of a service which had since taken more frames
/// and delivered a datagram. **A counter that has stopped moving reads exactly
/// like a subsystem that has stopped working**, which cost three separate
/// wrong diagnoses in one day, twice on this very page.
/// RFC 0029 step 3's two report words, held here so `refresh` can keep
/// writing them after `serve` takes over the page.
static V6_PREFIX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static V6_STATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

static CACHE: [core::sync::atomic::AtomicU64; 8] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// Rewrites the report with what serving has changed since.
fn refresh() {
    use core::sync::atomic::Ordering::Relaxed;
    let mut held = [0u64; 8];
    for (slot, value) in held.iter_mut().zip(CACHE.iter()) {
        *slot = value.load(Relaxed);
    }
    write_report([
        MARKER,
        held[0] + TAKEN.load(Relaxed),
        held[1],
        held[2],
        held[3],
        held[4],
        held[5],
        held[6] | (u64::from(SERVING_NOW.load(Relaxed)) << 3),
        held[7],
        DELIVERED.load(Relaxed),
        WHY.load(Relaxed),
        // The ring's own two numbers. Counters are a story about the ring;
        // these are the ring. Where they disagree, the counters are wrong.
        // SAFETY: the ring's header, in the region this program mapped.
        unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) },
        SERVING_TAIL.load(Relaxed),
        COPIES.load(Relaxed),
        BURST_PHASE.load(Relaxed),
        BURST_PONGS.load(Relaxed),
        BURST_RESULT.load(Relaxed),
        BURST_SENT.load(Relaxed),
        EMPTY_POLLS.load(Relaxed),
        LONGEST_WAIT.load(Relaxed),
        NOTIFIED_WAKES.load(Relaxed),
        V6_PREFIX.load(Relaxed),
        V6_STATE.load(Relaxed),
        BOUND_PORTS.load(Relaxed),
        SLOT_GENERATIONS.load(Relaxed),
        UPPER_SLOTS.load(Relaxed),
        TCP_FORWARDED.load(Relaxed),
        TCP_RETURNED.load(Relaxed),
        // Word 28, as the builder above: what the address is sitting on.
        BOUND_SHAPE.load(Relaxed),
        // Word 29, as the builder above.
        LACP_STATE.load(Relaxed),
        // Words 30 and 31, as the builder above: LACP traffic both ways, and
        // whether the bond is 802.3ad. `refresh` keeps reporting them after
        // serving starts, which is when the switch has had time to answer.
        LACP_TRAFFIC.load(Relaxed),
        u64::from(BOND_MODE_LACP.load(Relaxed)),
        // Words 32 and 33: **what the partner is, and what it thinks we are.**
        // The switch's own flags answer "is it LACP active"; its record of us
        // answers why SYNC never sets. See `lacp_publish`.
        LACP_PARTNER_STATE.load(Relaxed),
        LACP_RECORDED.load(Relaxed),
        // **Words 34 to 37: the address each link's LACPDU leaves under.**
        //
        // Appended, for the reason written at 23. The kernel prints what it
        // *published* to this service, which says nothing about what this
        // service did with it -- and "four links, four addresses" is the whole
        // claim of RFC 0076 step 4. This is the address after the fallback a
        // member with none takes, so a boot that shows four identical words
        // here has found the bug rather than hidden it.
        SPEAKING_AS[0].load(Relaxed),
        SPEAKING_AS[1].load(Relaxed),
        SPEAKING_AS[2].load(Relaxed),
        SPEAKING_AS[3].load(Relaxed),
        // **Words 38 to 40: what the neighbour says it is**, from its LLDP.
        // An inventory of the TLV types it sends, its port id, and the first
        // organizationally specific OUI and subtype -- see `LLDP_SEEN`. Only
        // what the C620 datasheet grounds is decoded; what the switch actually
        // sends decides what is worth decoding next.
        LLDP_SEEN.load(Relaxed),
        LLDP_ORGANISATION.load(Relaxed),
        LLDP_PORT[0].load(Relaxed),
        LLDP_PORT[1].load(Relaxed),
        LLDP_PORT[2].load(Relaxed),
        LLDP_PORT[3].load(Relaxed),
        // **Words 44 to 47: the VLANs the switch tags on each link** -- see
        // `VLANS_SEEN`. A trunk's character is which VLANs it carries, and the
        // tag was being discarded by the code that named it.
        VLANS_SEEN[0].load(Relaxed),
        VLANS_SEEN[1].load(Relaxed),
        VLANS_SEEN[2].load(Relaxed),
        VLANS_SEEN[3].load(Relaxed),
        // **Words 48 and 49: where the neighbour says it lives, and its name.**
        // See `LLDP_MANAGEMENT`.
        LLDP_MANAGEMENT.load(Relaxed),
        LLDP_NAME.load(Relaxed),
        ASK_STALLS.load(Relaxed),
    ]);
}

/// How many sockets this service will hand out.
///
/// Fixed, like every other table this system exposes to something it does not
/// control: a program that could make the service allocate without bound would
/// hold a denial of service dressed as a feature.
///
/// **Six as of 2026-08-28, four before.** Four was one short of what this
/// machine's own boot needs: the DHCP client holds one for the life of the
/// boot, the v6 round-trip test holds two, and RFC 0058's gate needs *two at
/// once* — a program parked in `poll` and another sending to it. The fifth bind
/// was refused, and the failure arrived as `EADDRINUSE` on a port nobody else
/// held, because that is the only errno a failed bind can honestly guess at.
///
/// The cost is two more [`DATAGRAM`] buffers, 768 bytes, in a service that
/// already maps a page for its ring. The bound stays a bound.
const SOCKETS: usize = 6;

/// One bound socket.
/// The largest datagram a socket will hold for its owner.
///
/// A DHCP offer is about three hundred bytes. Fixed and small, because this is
/// memory a *remote party* fills and there are [`SOCKETS`] of them.
const DATAGRAM: usize = 384;

#[derive(Clone, Copy)]
struct Socket {
    /// Zero when this slot is free.
    port: u16,
    /// Bumped every time the slot is reused, so a capability held across a
    /// close names a socket that no longer exists rather than the next one.
    generation: u32,
    /// Which family this socket was bound in — the method that minted it
    /// (`BIND_UDP` or `BIND_UDP6`), remembered so delivery and the two
    /// receive shapes cannot cross families by accident.
    v6: bool,
    /// **One** datagram, and the limit is stated rather than implied. A queue
    /// is a later question; what this step answers is whether a program holding
    /// a socket can be given what arrived for it.
    from: Address,
    from_port: u16,
    length: u16,
    held: [u8; DATAGRAM],
}

/// TCP segments handed on to `bin/tcpd`.
static TCP_FORWARDED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// TCP segments taken back from `bin/tcpd` and transmitted.
static TCP_RETURNED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Hands one TCP segment to `bin/tcpd`: eight bytes of addresses, then the
/// segment itself.
///
/// This program stays the only parser of the IPv4 header — what crosses is the
/// payload and the two addresses the pseudo-header needs, which is RFC 0020's
/// diagram exactly: "IPv4 payloads where protocol = 6".
///
/// # Safety
///
/// The forward ring must be mapped writable at [`TCP_FWD_AT`].
unsafe fn forward_tcp(source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> bool {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return false;
    };
    // SAFETY: the ring's header, in the region this program mapped. Volatile
    // because the consumer is another domain and takes no lock.
    let (head, tail) = unsafe {
        (
            core::ptr::read_volatile((TCP_FWD_AT + ring::HEAD_OFFSET as u64) as *const u64),
            core::ptr::read_volatile((TCP_FWD_AT + ring::TAIL_OFFSET as u64) as *const u64),
        )
    };
    let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
        return false;
    };
    let total = 8 + segment.len();
    let Some(framed) = ring::frame_to_write(layout, cursor, total) else {
        return false;
    };
    // Assembled contiguously, then written through `abi::ring`'s offsets. The
    // eight address bytes and the segment could be written as separate runs to
    // save this copy, but a wrap can fall inside the address prefix and the
    // arithmetic for that case is exactly the kind this program refuses to
    // write by hand. One bounded memcpy is the price of one copy routine.
    let mut entry = [0u8; 8 + MAX_FRAME];
    entry[0..4].copy_from_slice(&source.octets());
    entry[4..8].copy_from_slice(&destination.octets());
    let Some(slot) = entry.get_mut(8..total) else {
        return false;
    };
    slot.copy_from_slice(segment);
    let prefix = (total as u32).to_le_bytes();
    // SAFETY: offsets are `abi::ring`'s, inside the region mapped writable, and
    // `entry` is a buffer this program owns, `total` bounded by its size.
    unsafe {
        write_runs(TCP_FWD_AT, prefix.as_ptr(), framed.prefix);
        write_runs(TCP_FWD_AT, entry.as_ptr(), framed.payload);
    }
    copied();
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (TCP_FWD_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    // Index first, wake second, as every doorbell in this system orders it.
    call(syscall::INVOKE, TCP_BELL, method::SIGNAL, [0; 4]);
    TCP_FORWARDED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    true
}

/// Hands one v6 segment across to `bin/tcpd`, marker-prefixed.
///
/// The record's first four bytes are [`bhaskix_abi::tcp::V6_RECORD`] — an
/// impossible v4 source — then the two sixteen-byte addresses, then the
/// segment. Same ring, same doorbell, one more record shape.
///
/// # Safety
///
/// As `forward_tcp`.
unsafe fn forward_tcp6(source: Ipv6Addr, destination: Ipv6Addr, segment: &[u8]) -> bool {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return false;
    };
    // SAFETY: the ring's header, in the region this program mapped. Volatile
    // because the consumer is another domain and takes no lock.
    let (head, tail) = unsafe {
        (
            core::ptr::read_volatile((TCP_FWD_AT + ring::HEAD_OFFSET as u64) as *const u64),
            core::ptr::read_volatile((TCP_FWD_AT + ring::TAIL_OFFSET as u64) as *const u64),
        )
    };
    let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
        return false;
    };
    let total = 36 + segment.len();
    let Some(framed) = ring::frame_to_write(layout, cursor, total) else {
        return false;
    };
    let mut entry = [0u8; 36 + MAX_FRAME];
    entry[0..4].copy_from_slice(&bhaskix_abi::tcp::V6_RECORD);
    entry[4..20].copy_from_slice(&source.octets());
    entry[20..36].copy_from_slice(&destination.octets());
    let Some(slot) = entry.get_mut(36..total) else {
        return false;
    };
    slot.copy_from_slice(segment);
    let prefix = (total as u32).to_le_bytes();
    // SAFETY: offsets are `abi::ring`'s, inside the region mapped writable,
    // and `entry` is a buffer this program owns, `total` bounded by its size.
    unsafe {
        write_runs(TCP_FWD_AT, prefix.as_ptr(), framed.prefix);
        write_runs(TCP_FWD_AT, entry.as_ptr(), framed.payload);
    }
    copied();
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (TCP_FWD_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    // Index first, wake second, as every doorbell in this system orders it.
    call(syscall::INVOKE, TCP_BELL, method::SIGNAL, [0; 4]);
    TCP_FORWARDED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    true
}

/// Takes segments `bin/tcpd` has handed back and puts them on the wire.
///
/// Each entry is eight bytes of addresses and a segment; this program wraps it
/// in the IPv4 and Ethernet headers `tcpd` deliberately cannot build, using
/// the gateway's hardware address for every destination — one interface, one
/// route, which is all this network has.
fn drain_tcp_back(
    me: (MacAddr, Ipv4Addr),
    gateway: MacAddr,
    v6_from: Option<Ipv6Addr>,
    router6: Option<MacAddr>,
    tail: &mut u64,
) {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return;
    };
    let mut entry = [0u8; 8 + MAX_FRAME];
    let mut outgoing = [0u8; MAX_FRAME];
    for _ in 0..16 {
        // SAFETY: the ring's header, in the region this program mapped.
        let head = unsafe {
            core::ptr::read_volatile((TCP_BACK_AT + ring::HEAD_OFFSET as u64) as *const u64)
        };
        let Some(cursor) = ring::Cursor::new(layout, head, *tail) else {
            return;
        };
        let mut prefix = [0u8; ring::PREFIX];
        let Some(runs) = ring::length_to_read(layout, cursor) else {
            return;
        };
        // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
        unsafe { read_runs(TCP_BACK_AT, prefix.as_mut_ptr(), runs) };
        let length = u32::from_le_bytes(prefix) as usize;
        if !(8..=8 + MAX_FRAME).contains(&length) {
            *tail = tail.wrapping_add(ring::PREFIX as u64);
            publish_tcp_tail(*tail);
            continue;
        }
        let Some(framed) = ring::frame_to_read(layout, cursor, length) else {
            return;
        };
        // SAFETY: as above; `entry` is large enough and `length` bounded.
        unsafe { read_runs(TCP_BACK_AT, entry.as_mut_ptr(), framed.payload) };
        copied();
        *tail = framed.next;
        publish_tcp_tail(*tail);

        // A v6 record, by its marker. Loopback destinations reinject
        // straight into the forward ring -- self-addressed traffic never
        // touches a wire -- and everything else rides the router, the same
        // one-road discipline the v4 arm has with its gateway.
        if length >= 36 && entry[0..4] == bhaskix_abi::tcp::V6_RECORD {
            let mut source6 = [0u8; 16];
            source6.copy_from_slice(&entry[4..20]);
            let mut destination6 = [0u8; 16];
            destination6.copy_from_slice(&entry[20..36]);
            let (source6, destination6) = (Ipv6Addr(source6), Ipv6Addr(destination6));
            let segment = &entry[36..length];
            if destination6 == LOOPBACK6 {
                // SAFETY: the forward ring is mapped writable.
                if unsafe { forward_tcp6(source6, destination6, segment) } {
                    TCP_RETURNED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                continue;
            }
            let (Some(_from), Some(via)) = (v6_from, router6) else {
                continue;
            };
            let body_length = segment.len();
            if ipv6::write_header(
                &mut outgoing[eth::HEADER..],
                source6,
                destination6,
                NextHeader::TCP,
                64,
                body_length,
            )
            .is_err()
            {
                continue;
            }
            let at = eth::HEADER + ipv6::HEADER;
            let Some(slot) = outgoing.get_mut(at..at + body_length) else {
                continue;
            };
            slot.copy_from_slice(segment);
            if eth::write_header(&mut outgoing, via, me.0, EtherType::IPV6).is_ok()
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..at + body_length]) }
            {
                TCP_RETURNED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            continue;
        }

        let destination = Ipv4Addr(u32::from_be_bytes([entry[4], entry[5], entry[6], entry[7]]));
        let segment = &entry[8..length];
        let body_length = segment.len();
        if ipv4::write_header(
            &mut outgoing[eth::HEADER..],
            me.1,
            destination,
            Protocol::TCP,
            body_length,
            0x2604,
        )
        .is_err()
        {
            continue;
        }
        let at = eth::HEADER + ipv4::HEADER;
        let Some(slot) = outgoing.get_mut(at..at + body_length) else {
            continue;
        };
        slot.copy_from_slice(segment);
        if eth::write_header(&mut outgoing, gateway, me.0, EtherType::IPV4).is_ok()
            // SAFETY: the return ring is mapped writable.
            && unsafe { send(&outgoing[..at + body_length]) }
        {
            TCP_RETURNED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Tells `bin/tcpd` how far this program has read its back ring.
fn publish_tcp_tail(tail: u64) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile((TCP_BACK_AT + ring::TAIL_OFFSET as u64) as *mut u64, tail);
    }
}

/// Takes whatever has arrived and gives each datagram to the socket it is for.
///
/// Called from a client's `RECV_FROM` **and** from the wake a frame rings.
///
/// This said "called from inside a client's `RECV_FROM`, because that is the
/// only event this service can act on while asleep on its endpoint" until
/// 2026-08-14. That stopped being true on 2026-08-13, when RFC 0010's question
/// 1 was answered and `serve` gained the `NOTIFIED` arm that drains without
/// anybody asking — see `serve`, which is the other caller. A comment
/// describing the constraint a change removed is worse than no comment: it
/// tells the next reader the service still cannot do the thing it now does.
///
/// A datagram is matched to a socket by **destination port**. A broadcast
/// destination is accepted as well as this interface's own address: a client
/// with no address yet is answered by broadcast, which is the whole reason
/// DHCP works at all.
#[allow(clippy::too_many_arguments)]
fn drain_ring(
    sockets: &mut [Socket; SOCKETS],
    me: (MacAddr, Ipv4Addr),
    tail: &mut u64,
    can_tcp: bool,
    lacp: &mut Bundle,
    openings: &mut u32,
) {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return;
    };
    let mut frame = [0u8; MAX_FRAME];

    // Bounded: a client asking for one datagram must not be made to walk an
    // arbitrarily long backlog before it is answered.
    for _ in 0..16 {
        // SAFETY: the ring's header, in the region this program mapped.
        let head =
            unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) };
        SERVING_TAIL.store(*tail, core::sync::atomic::Ordering::Relaxed);
        let Some(cursor) = ring::Cursor::new(layout, head, *tail) else {
            return;
        };
        let mut prefix = [0u8; ring::PREFIX];
        let Some(runs) = ring::length_to_read(layout, cursor) else {
            return;
        };
        // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
        unsafe { read_runs(RING_AT, prefix.as_mut_ptr(), runs) };
        // The length, and the member the frame arrived on. `bin/netd` stamps
        // the index; an LACPDU is answered by the machine that speaks for that
        // link and by no other. See `ring::marked`.
        let (length, from_member, _) = ring::marked(u32::from_le_bytes(prefix));
        if length == 0 || length > MAX_FRAME {
            // A length this program has stopped believing. Skip the prefix and
            // carry on rather than wedging on it for ever.
            *tail = tail.wrapping_add(ring::PREFIX as u64);
            continue;
        }
        // `None` is the producer mid-write, not an error. See `frame_to_read`.
        let Some(framed) = ring::frame_to_read(layout, cursor, length) else {
            return;
        };
        // SAFETY: as above; `frame` is `MAX_FRAME` writable bytes and `length`
        // is bounded by it.
        unsafe { read_runs(RING_AT, frame.as_mut_ptr(), framed.payload) };
        // Inbound, copy two of two: the ring into this program's buffer.
        copied();
        *tail = framed.next;
        publish(*tail);
        TAKEN.store(
            TAKEN.load(core::sync::atomic::Ordering::Relaxed) + 1,
            core::sync::atomic::Ordering::Relaxed,
        );

        // Every refusal below is `bhaskix-net`'s. This program decides only
        // which socket a datagram belongs to.
        let seen = if length >= 14 {
            u16::from_be_bytes([frame[12], frame[13]])
        } else {
            0
        };
        // **Parsed for the interface this address lives on**, not for whatever
        // arrived. On an untagged interface that is exactly what `parse` did
        // before; on a VLAN one it accepts that VLAN's tag and refuses every
        // other, which is the boundary RFC 0074 exists to draw.
        // **A trunk carries two kinds of frame and this takes both.** Data
        // belongs to a VLAN and must carry its tag; LACP and LLDP belong to the
        // wire and arrive untagged. Binding a VLAN and refusing everything
        // untagged would make this service deaf to exactly the frames that
        // bring a bundle up -- so an untagged frame is taken when, and only
        // when, it is one of those.
        let untagged = EthFrame::parse_on(&frame[..length], None)
            .ok()
            .filter(|frame| is_link_control(frame.ethertype));
        let on_our_vlan = EthFrame::parse_on(&frame[..length], bound_vlan());
        // **What VLAN the switch put on it**, before deciding whether to take
        // it. `parse_on` already names the tag when it refuses one -- the error
        // is `Unsupported { field: "802.1Q tag for another VLAN", value: id }`
        // -- and `refuse` threw that value away, so this service has been
        // discarding the one fact that says what a trunk is carrying.
        //
        // Recorded against the link it arrived on: the question is what the
        // switch sends *on those ports*, and four ports need not agree.
        match &on_our_vlan {
            Err(bhaskix_net::NetError::Unsupported { field, value })
                if field.starts_with("802.1Q tag for another") =>
            {
                saw_vlan(from_member, *value as u16);
            }
            // Accepted means it carried the tag this interface is bound to.
            Ok(_) if untagged.is_none() => {
                if let Some(ours) = bound_vlan() {
                    saw_vlan(from_member, ours);
                }
            }
            _ => {}
        }
        let Some(parsed) = untagged.or_else(|| on_our_vlan.ok()) else {
            refuse(why::NOT_A_FRAME, length, seen);
            continue;
        };
        // **Slow protocols, which is LACP** -- RFC 0074 step 5. An LACPDU
        // goes to a reserved group address, so it reaches here like any other
        // group frame; what makes it ours is the EtherType. The machine
        // decides what to believe, and a reply goes back on the same wake,
        // which is how two peers converge without either holding a clock.
        // **What the neighbour says it is.** These frames have arrived on every
        // boot and been refused; the switch's own account of itself was on the
        // wire the whole time RFC 0076 was asking for it.
        if parsed.ethertype.0 == bhaskix_net::lldp::ETHERTYPE {
            let seen = bhaskix_net::lldp::inventory(parsed.payload);
            LLDP_SEEN.store(
                u64::from(seen.types)
                    | u64::from(seen.count.min(0xff)) << 32
                    | u64::from(seen.organisations.min(0xff)) << 40
                    | u64::from(seen.whole) << 48
                    | 1 << 49,
                core::sync::atomic::Ordering::Relaxed,
            );
            // **Recorded against the link it arrived on**, which is the whole
            // point: the switch names its own port, and whether four links
            // reach one port or four is what a port-channel question is.
            if let Some((subtype, id)) = seen.port {
                let packed = id.iter().fold(0u64, |word, o| (word << 8) | u64::from(*o));
                let link = from_member.map_or(0, usize::from).min(LACP_MACHINES - 1);
                LLDP_PORT[link].store(
                    packed | u64::from(subtype) << 48,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
            if let Some(address) = seen.management {
                LLDP_MANAGEMENT.store(
                    address.packed() | 1 << 56,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
            if seen.name_length > 0 {
                let name = seen
                    .name
                    .iter()
                    .enumerate()
                    .fold(0u64, |word, (at, byte)| word | u64::from(*byte) << (8 * at));
                LLDP_NAME.store(name, core::sync::atomic::Ordering::Relaxed);
            }
            if let Some((oui, subtype)) = seen.organisation {
                LLDP_ORGANISATION.store(
                    u64::from(oui[0]) << 16
                        | u64::from(oui[1]) << 8
                        | u64::from(oui[2])
                        | u64::from(subtype) << 24,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
        if parsed.ethertype.0 == bhaskix_net::lacp::ETHERTYPE {
            lacp_heard();
            // **To the machine for the link it came in on.** A partner is a
            // property of a link, not of the bond: routing every PDU to one
            // machine would let the second link's partner overwrite the
            // first's, and the report would show a bundle neither link had.
            let member = from_member.map_or(0, usize::from);
            if let Some((index, source, machine)) = lacp.member(member)
                && machine.received(parsed.payload)
            {
                // Answer while awake. A partner that has just told us
                // something is a partner that will want our view of it.
                let pdu = machine.sending();
                let mut body = [0u8; bhaskix_net::lacp::PDU];
                let mut out = [0u8; eth::HEADER + bhaskix_net::lacp::PDU];
                // `crate::frame`, because the local buffer above shadows
                // the builder's name in this function.
                if pdu.write(&mut body).is_ok()
                        // **The link's own address, not the bond's.** See
                        // `Bundle::source`.
                        && let Some(length) = crate::frame(
                            &mut out,
                            bhaskix_net::lacp::GROUP_ADDRESS,
                            source,
                            EtherType(bhaskix_net::lacp::ETHERTYPE),
                            &body,
                        )
                        // SAFETY: the return ring is mapped writable.
                        && unsafe { send_from(&out[..length], Some(index), true) }
                {
                    lacp_sent();
                    *openings = openings.saturating_sub(1);
                }
                lacp_publish(lacp);
            }
            continue;
        }

        // RFC 0029 step 4: a v6 datagram, delivered by the same discipline
        // as the v4 one below — family-matched to the socket, one held
        // datagram, the newest wins.
        if parsed.ethertype == EtherType::IPV6 {
            let Ok((header6, payload6)) = Ipv6Header::parse(parsed.payload) else {
                refuse(why::NOT_A_HEADER, length, seen);
                continue;
            };
            if header6.next_header != NextHeader::UDP {
                refuse(why::NOT_UDP, length, seen);
                continue;
            }
            let Ok(datagram) = UdpDatagram::parse6(payload6, header6.source, header6.destination)
            else {
                refuse(why::NOT_A_DATAGRAM, length, seen);
                continue;
            };
            let Some(socket) = sockets
                .iter_mut()
                .find(|held| held.v6 && held.port != 0 && held.port == datagram.destination.0)
            else {
                refuse(why::NO_SOCKET, length, seen);
                continue;
            };
            let take = datagram.payload.len().min(DATAGRAM);
            socket.held[..take].copy_from_slice(&datagram.payload[..take]);
            socket.length = take as u16;
            ring_datagram_bell();
            socket.from = Address::V6(header6.source);
            socket.from_port = datagram.source.0;
            DELIVERED.store(
                DELIVERED.load(core::sync::atomic::Ordering::Relaxed) + 1,
                core::sync::atomic::Ordering::Relaxed,
            );
            continue;
        }
        if parsed.ethertype != EtherType::IPV4 {
            refuse(why::NOT_IPV4, length, seen);
            continue;
        }
        let Ok((header, payload)) = Ipv4Header::parse(parsed.payload) else {
            refuse(why::NOT_A_HEADER, length, seen);
            continue;
        };
        // RFC 0020 step 4: a TCP segment for this interface goes to the
        // domain that understands it. Forwarded before the UDP refusal, so
        // "not UDP" keeps meaning what it says — a protocol nobody here
        // serves — rather than covering the one that is served next door.
        if can_tcp
            && header.protocol == Protocol::TCP
            && !header.is_fragment()
            && header.destination == me.1
        {
            // SAFETY: the forward ring is mapped writable when `can_tcp`.
            unsafe { forward_tcp(header.source, header.destination, payload) };
            continue;
        }
        if header.protocol != Protocol::UDP || header.is_fragment() {
            refuse(why::NOT_UDP, length, seen);
            continue;
        }
        if header.destination != me.1 && header.destination != Ipv4Addr::BROADCAST {
            refuse(why::NOT_FOR_US, length, seen);
            continue;
        }
        let Ok(datagram) = UdpDatagram::parse(payload, header.source, header.destination) else {
            refuse(why::NOT_A_DATAGRAM, length, seen);
            continue;
        };
        let Some(socket) = sockets
            .iter_mut()
            .find(|held| !held.v6 && held.port != 0 && held.port == datagram.destination.0)
        else {
            refuse(why::NO_SOCKET, length, seen);
            continue;
        };
        // One datagram, and a second overwrites the first rather than being
        // dropped: the newest answer is the one a client asking now wants, and
        // a queue is a later question.
        let take = datagram.payload.len().min(DATAGRAM);
        socket.held[..take].copy_from_slice(&datagram.payload[..take]);
        socket.length = take as u16;
        ring_datagram_bell();
        socket.from = Address::V4(header.source);
        socket.from_port = datagram.source.0;
        // **Counted, because nothing counted it.** Every number this program
        // reported described frames crossing the ring; not one said whether a
        // datagram ever reached a socket. So "the client heard nothing" and
        // "the service delivered nothing" were the same observation, and the
        // search went looking at the device three times over.
        DELIVERED.store(
            DELIVERED.load(core::sync::atomic::Ordering::Relaxed) + 1,
            core::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Serves the network to whoever holds a capability to this endpoint.
///
/// **Blocks in `receive`**, which is the whole reason this is a service rather
/// than the poll loop it was through step 4. A frame arriving while nothing is
/// asking sits in the ring; it is drained when a client next calls, which is
/// what a receive queue is for.
///
/// Returns never.
#[allow(clippy::too_many_arguments)]
fn serve(
    sockets: &mut [Socket; SOCKETS],
    mut me: (MacAddr, Ipv4Addr),
    gateway: MacAddr,
    v6_from: Option<Ipv6Addr>,
    router6: Option<MacAddr>,
    can_send: bool,
    mut can_tcp: bool,
    mut tail: u64,
    mut tcp_tail: u64,
) -> ! {
    // **RFC 0074 step 5's machines, and they live here.** One per bond member,
    // because 802.3ad runs a machine per link -- see `Bundle`. They start as
    // soon as this service knows its own address, because the system id an
    // LACPDU carries is that address.
    let mut lacp = Bundle::new();
    let mut openings = LACP_OPENINGS;
    loop {
        // The configuration may arrive after serving begins -- see
        // `read_interface`. Without this the service would hold an
        // unspecified address for ever on any link whose demonstration ended
        // before `bin/netd` read the device.
        if can_send
            && me.0 == MacAddr::UNSPECIFIED
            && let Some(identity) = read_interface()
        {
            me = identity;
        }

        // Start it, and open the conversation. A peer whose driver is not up
        // yet drops what it is sent, and with no clock there is no retry --
        // so there are a few opening frames rather than one.
        if can_send && me.0 != MacAddr::UNSPECIFIED {
            // What the bond is made of, from the shape `read_interface`
            // published. Zero members is an address straight on a port, which
            // is one link.
            let members =
                (BOUND_SHAPE.load(core::sync::atomic::Ordering::Relaxed) & 0xffff_ffff) as usize;
            lacp.arm(me.0, members, member_addresses());
            if openings > 0 && !lacp.aggregated() {
                // One opening frame per link, each carrying its own port id.
                for index in 0..LACP_MACHINES {
                    let Some((member, source, machine)) = lacp.member(index) else {
                        continue;
                    };
                    if machine.aggregated() {
                        continue;
                    }
                    let pdu = machine.sending();
                    let mut body = [0u8; bhaskix_net::lacp::PDU];
                    let mut out = [0u8; eth::HEADER + bhaskix_net::lacp::PDU];
                    if pdu.write(&mut body).is_ok()
                        // **The link's own address, not the bond's.** See
                        // `Bundle::source`.
                        && let Some(length) = frame(
                            &mut out,
                            bhaskix_net::lacp::GROUP_ADDRESS,
                            source,
                            EtherType(bhaskix_net::lacp::ETHERTYPE),
                            &body,
                        )
                        // SAFETY: the return ring is mapped writable.
                        && unsafe { send_from(&out[..length], Some(member), true) }
                    {
                        lacp_sent();
                    }
                }
                openings -= 1;
            }
            lacp_publish(&lacp);
        }
        // The rings may land after serving has begun — a boot whose
        // demonstration ends early reaches here first — and a serve loop
        // that froze the answer it was constructed with refused `SYN·ACK`s
        // as `NOT_UDP` for the life of the boot, on the boots that lost
        // that race and only those.
        if can_send && !can_tcp {
            can_tcp = try_attach_tcp();
        }
        let (status_in, badge, method, args) = receive();
        // What serving has changed, put where the kernel can read it. See
        // `CACHE`: without this the page froze at the moment serving began.
        refresh();
        // **Woken by a frame rather than by a caller.** RFC 0010 question 1:
        // this is the wake that used to be impossible, and the reason this loop
        // no longer has to be asked before it looks at the wire. Drain, then go
        // back to waiting; there is nobody to reply to.
        //
        // The wake does not say which ring, and it does not need to: `tcpd`'s
        // doorbell and `netd`'s land in the same word, and looking at a ring
        // that is empty costs one volatile read.
        if status_in == status::NOTIFIED {
            NOTIFIED_WAKES.store(
                NOTIFIED_WAKES.load(core::sync::atomic::Ordering::Relaxed) + 1,
                core::sync::atomic::Ordering::Relaxed,
            );
            drain_ring(sockets, me, &mut tail, can_tcp, &mut lacp, &mut openings);
            if can_tcp {
                drain_tcp_back(me, gateway, v6_from, router6, &mut tcp_tail);
            }
            continue;
        }
        if status_in != status::OK {
            continue;
        }
        if can_tcp {
            drain_tcp_back(me, gateway, v6_from, router6, &mut tcp_tail);
        }

        // Unbadged means the caller invoked the service's own endpoint, which
        // is the only capability that can mint a socket. A badge means the
        // caller holds a socket and is using it.
        if badge == 0 {
            if method != socket::BIND_UDP && method != socket::BIND_UDP6 {
                reply(socket::GONE, 0, 0);
                continue;
            }
            if !can_send {
                // No device, or no window to drive it through. Said rather
                // than pretended: a program can tell "nothing answered" from
                // "there is nothing to answer".
                reply(socket::NO_NETWORK, 0, 0);
                continue;
            }
            let wanted = args[0] as u16;
            // **Two refusals, not one.** A free row and a free *port* are
            // different things, and answering `NO_PORT` for both sent callers
            // hunting the holder of a port nobody held -- three times in one
            // day. The table being full is `NO_SOCKET`; the port being spoken
            // for is `NO_PORT`.
            let Some(index) = sockets.iter().position(|held| held.port == 0) else {
                reply(socket::NO_SOCKET, 0, 0);
                continue;
            };
            if wanted != 0 && sockets.iter().any(|held| held.port == wanted) {
                reply(socket::NO_PORT, 0, 0);
                continue;
            }
            // Zero means "assign me one", and the assignment is this service's
            // to make. Ports start above the well-known range.
            let port = if wanted == 0 {
                49152 + index as u16
            } else {
                wanted
            };
            sockets[index].port = port;
            sockets[index].v6 = method == socket::BIND_UDP6;
            let generation = sockets[index].generation;

            // The capability, derived from this program's own endpoint and
            // handed over. **Where it lands is the caller's to say**: `HAND`
            // puts it in the slot the caller declared with `EXPECT`, and no
            // argument here could name another — which is what stops a service
            // filling a slot a program was keeping empty.
            let (handed, _) = call(
                syscall::INVOKE,
                ENDPOINT,
                method::HAND,
                [
                    ENDPOINT,
                    rights::READ | rights::DERIVE,
                    socket::handle(index as u32, generation),
                    0,
                ],
            );
            if handed == status::OK {
                reply(socket::OK, u64::from(port), 0);
            } else {
                // The commonest reason is that the caller never said where.
                // That is the caller's mistake rather than a missing socket, so
                // it gets its own answer and the slot is given back.
                sockets[index].port = 0;
                reply(socket::NOWHERE, 0, 0);
            }
            continue;
        }

        // A badged capability: a socket. The badge was stamped by the kernel on
        // the way through and cannot be forged by the holder, which is the one
        // thing making the rest of this safe.
        let (index, generation) = socket::parts(badge);
        let held = sockets.get(index as usize).copied();
        let Some(held) = held.filter(|held| held.port != 0 && held.generation == generation) else {
            // Either never a socket, or one that has been closed and whose slot
            // may already be somebody else's. The generation is what tells
            // those apart from the socket that is there now.
            reply(socket::GONE, 0, 0);
            continue;
        };

        match method {
            socket::CLOSE => {
                sockets[index as usize].port = 0;
                // Bumped on release rather than on reuse, so the next holder of
                // this slot cannot be mistaken for the one that just left.
                sockets[index as usize].generation = generation.wrapping_add(1);
                reply(socket::OK, 0, 0);
            }
            // **Asking without emptying** -- RFC 0056. The family check is the
            // same one `SEND_TO` makes, and for the same reason: one service
            // holds both, so the method number is what says which was meant.
            socket::PEEK_FROM if held.v6 => reply(socket::WRONG_FAMILY, 0, 0),
            socket::PEEK_FROM6 if !held.v6 => reply(socket::WRONG_FAMILY, 0, 0),
            socket::PEEK_FROM | socket::PEEK_FROM6 => {
                // **Drained first, exactly as `RECV_FROM` does.** This service
                // is asleep in `receive` and has no other wakeup, so a client
                // asking is the only event it can act on. A peek that skipped
                // this would answer "nothing waiting" for a datagram already in
                // the ring, and a program polling the socket would be told for
                // ever that nothing had arrived while its datagrams piled up.
                drain_ring(sockets, me, &mut tail, can_tcp, &mut lacp, &mut openings);
                // The length, and **nothing taken**: the datagram stays where
                // it is for the `recvfrom` that follows.
                reply(socket::OK, u64::from(sockets[index as usize].length), 0);
            }
            socket::SEND_TO if held.v6 => {
                // A v6 socket asked in the v4 shape. Refused by name rather
                // than mis-sent: the caller's two words of address would
                // have been read as one address and a port.
                reply(socket::WRONG_FAMILY, 0, 0);
            }
            socket::SEND_TO => {
                // The payload comes out of memory the **caller** named, with
                // `DRAIN` -- the mirror of `FILL`, built by RFC 0016 step 3 for
                // exactly this and used by the block service since. Which
                // caller is not an argument: it is the one being answered, so a
                // service cannot read a third party's memory.
                let mut payload = [0u8; DATAGRAM];
                let wanted = (args[3] as usize).min(DATAGRAM);
                let (drained, took) = call(
                    syscall::INVOKE,
                    ENDPOINT,
                    method::DRAIN,
                    [args[2], payload.as_mut_ptr() as u64, wanted as u64, 0],
                );
                if drained != status::OK {
                    // No memory named, or not held with `READ`. Sending
                    // something else in its place would answer a different
                    // question than the one asked.
                    reply(socket::GONE, 0, 0);
                    continue;
                }
                let sent = send_datagram(
                    me,
                    gateway,
                    held.port,
                    Ipv4Addr(args[0] as u32),
                    args[1] as u16,
                    &payload[..(took as usize).min(wanted)],
                );
                reply(if sent { socket::OK } else { socket::NO_NETWORK }, 0, 0);
            }
            socket::SEND_TO6 if !held.v6 => {
                reply(socket::WRONG_FAMILY, 0, 0);
            }
            socket::SEND_TO6 => {
                // The wide endpoint in four words: the address's halves,
                // then (length << 16) | port -- the packing the ABI states,
                // with the UDP length field's own cap.
                let mut to = [0u8; 16];
                to[..8].copy_from_slice(&args[0].to_be_bytes());
                to[8..].copy_from_slice(&args[1].to_be_bytes());
                let to = Ipv6Addr(to);
                let to_port = args[2] as u16;
                let wanted = ((args[2] >> 16) as usize).min(DATAGRAM);
                let mut payload = [0u8; DATAGRAM];
                let (drained, took) = call(
                    syscall::INVOKE,
                    ENDPOINT,
                    method::DRAIN,
                    [args[3], payload.as_mut_ptr() as u64, wanted as u64, 0],
                );
                if drained != status::OK {
                    reply(socket::GONE, 0, 0);
                    continue;
                }
                let length = (took as usize).min(wanted);

                // Loopback first: self-addressed traffic never touches a
                // wire on a correct stack, so `[::1]` needs no address, no
                // router and no frame -- delivered to the matching v6
                // socket here, with the source the convention names. A
                // port nobody holds swallows the datagram, exactly as the
                // wire would.
                if to == LOOPBACK6 {
                    let from_port = held.port;
                    if let Some(target) = sockets
                        .iter_mut()
                        .find(|other| other.v6 && other.port != 0 && other.port == to_port)
                    {
                        let take = length.min(DATAGRAM);
                        target.held[..take].copy_from_slice(&payload[..take]);
                        target.length = take as u16;
                        ring_datagram_bell();
                        target.from = Address::V6(LOOPBACK6);
                        target.from_port = from_port;
                        DELIVERED.store(
                            DELIVERED.load(core::sync::atomic::Ordering::Relaxed) + 1,
                            core::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    reply(socket::OK, 0, 0);
                    continue;
                }

                let (Some(from), Some(via)) = (v6_from, router6) else {
                    reply(socket::NO_NETWORK, 0, 0);
                    continue;
                };
                let sent =
                    send_datagram6(me.0, via, from, to, held.port, to_port, &payload[..length]);
                reply(if sent { socket::OK } else { socket::NO_NETWORK }, 0, 0);
            }
            socket::RECV_FROM if held.v6 => {
                reply(socket::WRONG_FAMILY, 0, 0);
            }
            socket::RECV_FROM => {
                // **Asking is what makes this service look at the wire.** It is
                // asleep in `receive` and has no other wakeup, so a client
                // asking for a datagram is the only event it can act on. Not a
                // workaround: the alternative is a poll loop, and this system
                // has already paid for one of those today.
                drain_ring(sockets, me, &mut tail, can_tcp, &mut lacp, &mut openings);

                let waiting = sockets[index as usize];
                if waiting.length == 0 {
                    reply(socket::EMPTY, 0, 0);
                    continue;
                }
                let (filled, _) = call(
                    syscall::INVOKE,
                    ENDPOINT,
                    method::FILL,
                    [
                        args[0],
                        waiting.held.as_ptr() as u64,
                        u64::from(waiting.length),
                        0,
                    ],
                );
                if filled != status::OK {
                    reply(socket::GONE, 0, 0);
                    continue;
                }
                sockets[index as usize].length = 0;
                let Address::V4(from) = waiting.from else {
                    // Cannot happen -- delivery is family-matched -- and
                    // refused by name rather than unwrapped if it ever does.
                    reply(socket::WRONG_FAMILY, 0, 0);
                    continue;
                };
                let mut source = 0u64;
                for octet in from.octets() {
                    source = (source << 8) | u64::from(octet);
                }
                reply(socket::OK, source, u64::from(waiting.from_port));
            }
            socket::RECV_FROM6 if !held.v6 => {
                reply(socket::WRONG_FAMILY, 0, 0);
            }
            socket::RECV_FROM6 => {
                drain_ring(sockets, me, &mut tail, can_tcp, &mut lacp, &mut openings);
                let waiting = sockets[index as usize];
                if waiting.length == 0 {
                    reply(socket::EMPTY, 0, 0);
                    continue;
                }
                let (filled, _) = call(
                    syscall::INVOKE,
                    ENDPOINT,
                    method::FILL,
                    [
                        args[0],
                        waiting.held.as_ptr() as u64,
                        u64::from(waiting.length),
                        0,
                    ],
                );
                if filled != status::OK {
                    reply(socket::GONE, 0, 0);
                    continue;
                }
                sockets[index as usize].length = 0;
                let Address::V6(from) = waiting.from else {
                    reply(socket::WRONG_FAMILY, 0, 0);
                    continue;
                };
                let octets = from.octets();
                let mut high = [0u8; 8];
                let mut low = [0u8; 8];
                high.copy_from_slice(&octets[..8]);
                low.copy_from_slice(&octets[8..]);
                // The reply convention carries three service words; the
                // source port rides above the outcome, as the ABI states.
                reply(
                    socket::OK | (u64::from(waiting.from_port) << 16),
                    u64::from_be_bytes(high),
                    u64::from_be_bytes(low),
                );
            }
            _ => reply(socket::GONE, 0, 0),
        }
    }
}

/// Whether each TCP ring has attached. Statics because both the
/// demonstration loop and `serve` retry them — the kernel installs the rings
/// after this program starts, so any single moment's answer can be "not yet".
static FWD_ATTACHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static BACK_ATTACHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Set the moment `serve` is entered, and reported: the kernel holds the DHCP
/// client back until this is true, because a caller that calls before its
/// service is receiving strands in the send queue — the fourth ordering bug
/// of this shape, and the first whose fix is to say when readiness happens
/// rather than to reorder who starts first.
static SERVING_NOW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Retries whichever TCP ring is not attached yet. Idempotent, one ring at a
/// time, because a successful attach is not repeatable: retrying the pair as
/// one expression wedged `can_tcp` false forever on any boot where the two
/// slots were installed a pass apart.
fn try_attach_tcp() -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    if !FWD_ATTACHED.load(Relaxed) && attach(TCP_FWD, TCP_FWD_AT, 1) {
        FWD_ATTACHED.store(true, Relaxed);
    }
    if !BACK_ATTACHED.load(Relaxed) && attach(TCP_BACK, TCP_BACK_AT, 1) {
        BACK_ATTACHED.store(true, Relaxed);
    }
    FWD_ATTACHED.load(Relaxed) && BACK_ATTACHED.load(Relaxed)
}

/// The entry point.
#[unsafe(no_mangle)]
extern "C" fn ipd_main() -> ! {
    if !attach(RING, RING_AT, 1) || !attach(REPORT, REPORT_AT, 1) {
        exit()
    }
    let can_send = attach(BACK, BACK_AT, 1) && attach(CONFIG, CONFIG_AT, 0);
    // RFC 0020 step 4: the rings to and from `bin/tcpd`. **Retried in the
    // demonstration loop rather than attached once here**, because the kernel
    // installs them *after* this program has started — the TCP domain is set
    // up on the other side of this program's own spawn — so a one-shot attach
    // at entry loses the race on every boot, silently, and the loss presents
    // as a service that took segments into a ring nobody ever drained. A slot
    // that is empty now and full in a moment is what retrying is for. Absent
    // on a machine with no TCP domain, which is a state rather than a fault —
    // TCP frames are then refused as `NOT_UDP` exactly as before the domain
    // existed.
    let mut can_tcp = false;
    // Whether this program has an endpoint to answer on at all. Without one it
    // is still the frame mover it was at step 4, and says so by stopping.
    let serving =
        call(syscall::INVOKE, ENDPOINT, method::INFO, [0; 4]).0 != status::NO_SUCH_CAPABILITY;
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        exit()
    };

    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut first_source = 0u64;
    let mut refused = 0u64;
    let mut built = 0u64;
    let mut buffer = [0u8; MAX_FRAME];
    let mut outgoing = [0u8; MAX_FRAME];
    let mut cache = NeighbourCache::<8>::new(ARP_LIFETIME);
    // Stands in for a clock. See `ARP_LIFETIME`.
    let mut ticks = 0u64;
    let mut me = (MacAddr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
    let mut asked = false;
    // The pass this program last asked on.
    //
    // How many times it *has* asked is not kept here: it is tries minus the two
    // failures, all three of which live in `ASK_STALLS` where both builders of
    // this report can read them. Carried as a local it was invisible to
    // `refresh`, which published a zero over it -- three attempts at carrying a
    // value that did not need carrying.
    let mut ask_pass = 0u64;
    // **Where the request stops, when it stops.** The count above read zero on
    // hardware while `built` rose by nine, which says the block's inner `if`
    // failed and says nothing about which half of it. Three separate counts,
    // because *never reached*, *could not be built* and *the ring would not
    // take it* are three different faults and a single zero is compatible with
    // all of them. Inferring which from the outside was tried three times and
    // cost more than the counters do.
    let mut ask_tries = 0u64;
    let mut ask_unbuilt = 0u64;
    let mut ask_unsent = 0u64;
    let mut pinged = false;
    let mut quiet = 0u32;
    // **Empty passes since the demonstration began, which nothing resets.**
    //
    // `quiet` is a *consecutive* run and a frame clears it, which is right for
    // "the wire has gone quiet, and the work is done". It is exactly wrong as a
    // backstop: on a segment carrying anybody else's traffic the run never gets
    // long, so a demonstration that will never finish never ends either.
    //
    // Measured, 2026-09-06, on two guests joined by one wire: neither reached
    // `serve` in sixty seconds. Each had made thirteen million empty passes
    // with a longest run of two hundred thousand -- a hundredth of the
    // backstop -- because each kept clearing the other's counter with ARP and
    // DHCP nobody was going to answer. A quiet link is a test network. This is
    // the number that does not assume one.
    let mut spent = 0u32;
    let mut run = 0u64;
    let mut sockets = [Socket {
        port: 0,
        generation: 1,
        v6: false,
        from: Address::V4(Ipv4Addr::UNSPECIFIED),
        from_port: 0,
        length: 0,
        held: [0u8; DATAGRAM],
    }; SOCKETS];
    let mut pongs = 0u64;
    // RFC 0029 step 3: the v6 identity and its demonstrations. The
    // link-local address is derived the moment the MAC is known; the global
    // address and the default router arrive by SLAAC; the neighbour
    // solicitation and the ping mirror the ARP request and the v4 ping.
    let mut link_local = Ipv6Addr::UNSPECIFIED;
    let mut prefix6 = Ipv6Addr::UNSPECIFIED;
    let mut global6: Option<Ipv6Addr> = None;
    let mut router6: Option<Ipv6Addr> = None;
    let mut rs_sent = false;
    let mut rs_pass = 0u64;
    let mut ns6_sent = false;
    let mut ns6_pass = 0u64;
    let mut pinged6 = false;
    let mut ping6_pass = 0u64;
    let mut pongs6 = 0u64;
    // Sticky: the v6 host was resolved at least once. The cache entry
    // itself expires on a busy wire — ticks race past the lifetime — and
    // the report's question is "did NDP work", not "is the entry warm".
    let mut resolved6 = false;
    // The router's link address, held from the advertisement itself and
    // never expired: `serve` snapshots it once at its door, and on this
    // network it cannot change. The cache's expiry answered the wrong
    // question here twice — first for the resolved bit, then for this.
    let mut router6_link: Option<MacAddr> = None;
    // The retry clock for the three sends above. Loop passes rather than
    // `ticks`: ticks advance one per *received* frame, and on the quiet
    // wire this family boots on, a lost reply would freeze exactly the
    // clock that should be retrying it.
    let mut passes = 0u64;
    // RFC 0018 step 7's burst state. See `BURST`.
    let mut phase = 0u32;
    let mut burst_sent = 0u32;
    let mut burst_pongs = 0u32;
    let mut burst_waited = 0u32;
    let mut burst_gateway: Option<MacAddr> = None;
    // Only this program advances the tail, so it is kept here and written out
    // rather than read back. A consumer that re-read its own index would be
    // trusting the producer with it.
    let mut tail = 0u64;
    // Where this program has read `tcpd`'s back ring up to. Same discipline.
    let mut tcp_tail = 0u64;

    // A report before anything has arrived, so that "this program never ran"
    // and "this program ran and saw nothing" are different findings. Without
    // it the kernel reads an absent marker for both, and the two have entirely
    // different causes.
    report(
        0,
        0,
        0,
        0,
        0,
        0,
        state(can_send, MacAddr::UNSPECIFIED, can_tcp),
        0,
        0,
        0,
    );

    // No wakeup, and this is a gap rather than a choice. RFC 0018 step 3 asked
    // for a notification here; RFC 0010's notifications can only be signalled
    // by the *kernel* -- a program holding one may `WAIT` and `PEEK` and there
    // is no method that signals -- so a domain cannot wake another domain
    // today. Polling with a yield between looks is what is available, and the
    // missing half is recorded in TRACKER rather than invented here.
    loop {
        // Reported every pass, not only when a frame arrives. It was the
        // latter, and the consequence was a report frozen at the moment the
        // last frame crossed — which was *before* the kernel had published this
        // program's configuration, so the page said "unconfigured" long after
        // it had been configured. A report written only when something happens
        // cannot say what happened last.
        report(
            frames,
            bytes,
            first_source,
            refused,
            built,
            cache.live(ticks) as u64,
            state(can_send, me.0, can_tcp),
            pongs,
            prefix_word(prefix6),
            v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
        );

        passes += 1;

        // The TCP rings, once the kernel has installed them. See the note at
        // `can_tcp`'s declaration: they land after this program starts.
        //
        // **Each ring retried separately, because a successful attach is not
        // repeatable.** The first version retried the pair as one expression;
        // on a boot where the forward ring's slot was installed a pass before
        // the back ring's, the forward attach succeeded, the pair failed, and
        // every later pass re-attached an already-mapped ring — which is
        // refused — so the pair stayed false for the life of the boot with
        // both rings sitting installed. One boot in a handful lost that race,
        // which is the worst kind of failure to have.
        if can_send && !can_tcp {
            can_tcp = try_attach_tcp();
        }

        // What this interface is, once the kernel has been able to say. It
        // cannot say until `bin/netd` has read the address out of the device,
        // so this waits for a marker rather than believing a page of zeroes.
        if can_send
            && me.0 == MacAddr::UNSPECIFIED
            && let Some(identity) = read_interface()
        {
            me = identity;
        }

        // **Ask again if nothing answered.** The v6 solicitation beside this has
        // retried since it was written, for the reason `passes` is declared
        // with: on a quiet wire a lost frame freezes exactly the clock that
        // should be resending it. This asked **once per boot** and nothing said
        // so -- one broadcast at whatever instant the interface first came up,
        // which on hardware is microseconds after four links appeared and the
        // switch's aggregation is still settling. A frame lost there was lost
        // for the whole boot, and the report said `0 arp mappings learned` as
        // though the question had been fairly put.
        if asked
            && passes >= ask_pass + 200_000
            && cache.lookup(Address::V4(ask_about()), ticks).is_none()
        {
            asked = false;
        }
        // One request of this program's own, so that something on the wire can
        // only have come from here. Built entirely by `bhaskix-net`.
        if can_send && !asked && me.0 != MacAddr::UNSPECIFIED {
            ask_tries += 1;
            ASK_STALLS.store(
                ask_stalls(ask_tries, ask_unbuilt, ask_unsent),
                core::sync::atomic::Ordering::Relaxed,
            );
            let request = ArpPacket {
                operation: ArpOp::Request,
                sender_hardware: me.0,
                sender_protocol: me.1,
                target_hardware: MacAddr::UNSPECIFIED,
                target_protocol: ask_about(),
            };
            let mut packet = [0u8; arp::PACKET];
            // Split from the `&&` chain it used to be, so a failure says which
            // step failed rather than only that the whole thing did.
            let framed = request.write(&mut packet).is_ok().then(|| {
                frame(
                    &mut outgoing,
                    MacAddr::BROADCAST,
                    me.0,
                    EtherType::ARP,
                    &packet,
                )
            });
            match framed.flatten() {
                None => {
                    ask_unbuilt += 1;
                    ASK_STALLS.store(
                        ask_stalls(ask_tries, ask_unbuilt, ask_unsent),
                        core::sync::atomic::Ordering::Relaxed,
                    );
                }
                Some(length) => {
                    // SAFETY: the return ring is mapped writable.
                    if unsafe { send(&outgoing[..length]) } {
                        built += 1;
                        asked = true;
                        ask_pass = passes;
                    } else {
                        ask_unsent += 1;
                        ASK_STALLS.store(
                            ask_stalls(ask_tries, ask_unbuilt, ask_unsent),
                            core::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }
            }
        }

        // One echo request, once the cache can say where the gateway is. This
        // is the whole stack in one frame: an address learned from a reply this
        // program parsed, a header and a checksum written by `bhaskix-net`, and
        // a driver that will put it on the wire without understanding any of
        // it.
        if can_send
            && !pinged
            && me.0 != MacAddr::UNSPECIFIED
            && let Some(gateway) = cache.lookup(Address::V4(peer_address()), ticks)
        {
            let mut message = [0u8; icmp::HEADER + PING_PAYLOAD.len()];
            if let Ok(body) = icmp::write(&mut message, false, 0xbe57, 1, &PING_PAYLOAD)
                && ipv4::write_header(
                    &mut outgoing[eth::HEADER..],
                    me.1,
                    peer_address(),
                    Protocol::ICMP,
                    body,
                    0x2601,
                )
                .is_ok()
            {
                let at = eth::HEADER + ipv4::HEADER;
                outgoing[at..at + body].copy_from_slice(&message[..body]);
                let total = at + body;
                if eth::write_header(&mut outgoing, gateway, me.0, EtherType::IPV4).is_ok()
                    // SAFETY: the return ring is mapped writable.
                    && unsafe { send(&outgoing[..total]) }
                {
                    built += 1;
                    pinged = true;
                }
            }
        }

        // RFC 0029 step 3: the same demonstrations, second family. A router
        // solicitation instead of a DHCP exchange, a neighbour solicitation
        // instead of an ARP request, and the same ping — each built entirely
        // by `bhaskix-net` and each sent once.
        if me.0 != MacAddr::UNSPECIFIED && link_local.is_unspecified() {
            link_local = Ipv6Addr::link_local_from(me.0);
        }
        if router6.is_none() && rs_sent && passes >= rs_pass + 200_000 {
            rs_sent = false;
        }
        if can_send && !rs_sent && !link_local.is_unspecified() {
            let mut message = [0u8; 16];
            if let Ok(body) = icmpv6::write_router_solicitation(
                &mut message,
                link_local,
                Ipv6Addr::ALL_ROUTERS,
                Some(me.0),
            ) && let Some(total) = frame6(
                &mut outgoing,
                Ipv6Addr::ALL_ROUTERS.multicast_mac(),
                me.0,
                link_local,
                Ipv6Addr::ALL_ROUTERS,
                255,
                &message[..body],
            )
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..total]) }
            {
                built += 1;
                rs_sent = true;
                rs_pass = passes;
            }
        }
        if ns6_sent
            && passes >= ns6_pass + 200_000
            && cache.lookup(Address::V6(HOST6), ticks).is_none()
        {
            ns6_sent = false;
        }
        if can_send
            && !ns6_sent
            && let Some(from) = global6
        {
            let mut message = [0u8; 32];
            if let Ok(body) = icmpv6::write_neighbour_solicitation(
                &mut message,
                from,
                HOST6.solicited_node(),
                HOST6,
                Some(me.0),
            ) && let Some(total) = frame6(
                &mut outgoing,
                HOST6.solicited_node().multicast_mac(),
                me.0,
                from,
                HOST6.solicited_node(),
                255,
                &message[..body],
            )
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..total]) }
            {
                built += 1;
                ns6_sent = true;
                ns6_pass = passes;
            }
        }
        if pinged6 && pongs6 == 0 && passes >= ping6_pass + 200_000 {
            pinged6 = false;
        }
        if can_send
            && !pinged6
            && let Some(from) = global6
            && let Some(host) = cache.lookup(Address::V6(HOST6), ticks)
        {
            let mut message = [0u8; icmpv6::HEADER + PING_PAYLOAD.len()];
            if let Ok(body) =
                icmpv6::write_echo(&mut message, from, HOST6, false, PING6_ID, 1, &PING_PAYLOAD)
                && let Some(total) =
                    frame6(&mut outgoing, host, me.0, from, HOST6, 64, &message[..body])
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..total]) }
            {
                built += 1;
                pinged6 = true;
                ping6_pass = passes;
            }
        }

        // RFC 0018 step 7: the burst, once the single ping above has come back.
        //
        // Four phases: serialised at each payload size, then pipelined at each.
        // Serialised gives round-trip latency, because one request is in flight
        // at a time and the elapsed time *is* the round trip. Pipelined gives a
        // rate — bounded, in both the split and folded builds, by this driver
        // allowing one transmit outstanding at a time, which is a property of
        // the driver and not of the boundary being priced.
        //
        // The kernel cannot see inside this loop, so the phase counter is the
        // signal: it stamps its clock when the number moves.
        // The gateway's hardware address is taken once and held for the whole
        // burst. **The cache expires in frames handled, and the burst handles
        // more frames than the lifetime**: every run stopped at exactly 245 of
        // 256 in the last phase, which is the tick where `ARP_LIFETIME` ran out
        // and `lookup` began returning nothing. Re-asking mid-burst would put
        // an ARP exchange inside the interval being timed, so the address is
        // held instead — a measurement keeps everything constant except the
        // thing it is measuring.
        if burst_gateway.is_none()
            && let Some(found) = cache.lookup(Address::V4(peer_address()), ticks)
        {
            burst_gateway = Some(found);
        }
        if can_send
            && pongs >= 1
            && phase < 4
            && me.0 != MacAddr::UNSPECIFIED
            && let Some(gateway) = burst_gateway
        {
            let size = if phase.is_multiple_of(2) {
                BURST_SMALL
            } else {
                BURST_LARGE
            };
            let serialised = phase < 2;
            // Serialised waits for the previous reply; pipelined does not.
            let in_flight = burst_sent.saturating_sub(burst_pongs);
            let room = if serialised {
                in_flight == 0
            } else {
                in_flight < BURST_WINDOW
            };
            if burst_sent < BURST && room {
                let mut message = [0u8; icmp::HEADER + BURST_LARGE];
                let mut payload = [0u8; BURST_LARGE];
                // A pattern rather than zeroes, so a reply that came back
                // hollow is not mistaken for one that came back whole.
                for (index, byte) in payload[..size].iter_mut().enumerate() {
                    *byte = (index as u8) ^ 0x5a;
                }
                if let Ok(body) = icmp::write(
                    &mut message[..icmp::HEADER + size],
                    false,
                    BURST_ID,
                    (burst_sent + 1) as u16,
                    &payload[..size],
                ) && ipv4::write_header(
                    &mut outgoing[eth::HEADER..],
                    me.1,
                    peer_address(),
                    Protocol::ICMP,
                    body,
                    0x2602,
                )
                .is_ok()
                {
                    let at = eth::HEADER + ipv4::HEADER;
                    outgoing[at..at + body].copy_from_slice(&message[..body]);
                    let total = at + body;
                    if eth::write_header(&mut outgoing, gateway, me.0, EtherType::IPV4).is_ok()
                        // SAFETY: the return ring is mapped writable.
                        && unsafe { send(&outgoing[..total]) }
                    {
                        burst_sent += 1;
                        BURST_SENT
                            .store(u64::from(burst_sent), core::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            burst_waited += 1;
            // A phase ends when every reply is in, or when waiting for them has
            // gone on long enough that something is not coming. Both end it:
            // a burst that hangs would keep this program out of `serve`.
            if burst_pongs >= BURST || burst_waited > BURST_PATIENCE {
                // What this phase achieved, before the counters go back to zero.
                BURST_RESULT.store(
                    u64::from(burst_pongs),
                    core::sync::atomic::Ordering::Relaxed,
                );
                phase += 1;
                burst_sent = 0;
                burst_pongs = 0;
                burst_waited = 0;
                BURST_SENT.store(0, core::sync::atomic::Ordering::Relaxed);
                BURST_PONGS.store(0, core::sync::atomic::Ordering::Relaxed);
                // Written last, because it is the edge the kernel is watching.
                BURST_PHASE.store(u64::from(phase), core::sync::atomic::Ordering::Relaxed);
            }
        }

        // Segments `bin/tcpd` has queued while this loop was measuring. One
        // volatile read when the ring is empty, and a `SYN` that would
        // otherwise wait for `serve` when it is not.
        //
        // The gateway's address is used if the cache still holds it and the
        // broadcast address if not — **not** gated on the lookup, which is
        // what it was: the cache expires by frames handled, the burst handles
        // more frames than the lifetime, so whether a segment drained here
        // depended on whether it arrived before or after an expiry nobody
        // was thinking about. The demonstration connected on the boots where
        // it won that race and sat unsent on the boots where it lost, which
        // is the exact shape of flakiness this project keeps paying for.
        // Slirp routes on the IP header and accepts a broadcast frame — the
        // DHCP exchange depends on that already.
        if can_tcp && me.0 != MacAddr::UNSPECIFIED {
            let mac = cache
                .lookup(Address::V4(peer_address()), ticks)
                .unwrap_or(MacAddr::BROADCAST);
            drain_tcp_back(me, mac, global6, router6_link, &mut tcp_tail);
        }

        // SAFETY: the ring's header, in the region this program mapped. Read
        // volatile because the producer is another domain and takes no lock.
        let head =
            unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) };

        // Copied out, then validated, then used. `Cursor::new` refuses a pair
        // that cannot be true -- a head behind the tail, or a gap wider than
        // the ring -- which is the one thing standing between a hostile
        // producer and this program reading its own memory as a frame.
        let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
            refused += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        if cursor.is_empty() {
            // **This program has nothing to sleep on.** RFC 0010's
            // notifications can only be signalled by the kernel, so no domain
            // can wake another, and a poll loop is all that is available.
            //
            // A poll loop that never ends is a processor the rest of the
            // machine cannot have — which is exactly what it cost: the shell
            // test timed out with the shell answering every command correctly,
            // because two pinned domains were spinning for the life of the
            // boot.
            //
            // So it stops. This is a demonstration rather than a service: once
            // there has been nothing to do for a long run of passes, it writes
            // a last report and exits. The report page belongs to the keeper
            // domain, so it outlives this program and the kernel still reads
            // it. **A persistent `ipd` needs the wakeup RFC 0010 does not
            // have**, and that is the honest reason this exits rather than
            // idles.
            quiet = quiet.saturating_add(1);
            spent = spent.saturating_add(1);
            // Not before the work is done. Twenty thousand idle passes elapse
            // in a fraction of a second, and the kernel cannot publish this
            // program's configuration until the driver has read the device's
            // address -- so an exit on idleness alone quits before there is
            // anything to be idle about.
            //
            // The second bound is the backstop for a machine where the
            // demonstration cannot finish -- no DMA window, so no configuration
            // and nothing to wait for, or a link with nothing on it that
            // answers. It counts *total* empty passes rather than a run of
            // them, because a run is cleared by any frame at all and the frames
            // that clear it need have nothing to do with this program. See
            // `spent`.
            let done = asked && pinged;
            // **Not while a burst phase is unfinished.** This left for `serve`
            // with the last phase at 245 replies of 256: the ring went quiet
            // between packets, the counter tripped, and the measurement was
            // abandoned rather than finished. `BURST_PATIENCE` already bounds a
            // phase that will never complete, so waiting here cannot hang.
            //
            // Gated on the same conditions the burst itself needs. Without
            // them the burst never starts, `phase` stays at zero for ever, and
            // waiting for it would strand this program short of `serve` — on
            // every machine with no network, which is every BIOS boot.
            if can_send && pongs >= 1 && phase < 4 {
                // Still measuring. Fall through to another pass.
            } else if (done && quiet > 20_000) || spent > 2_000_000 {
                // **Serve rather than stop.** Through step 4 this program
                // exited here, because it had nothing to wait on and a poll
                // loop that never ends is a processor nobody else can have.
                // An endpoint is something to wait on: `receive` blocks, and a
                // service asleep in it costs nothing at all.
                //
                // The demonstration above is done by this point, so what
                // follows is the program's real job. A frame arriving while it
                // is asleep waits in the ring, which is what a receive queue is.
                if serving {
                    report(
                        frames,
                        bytes,
                        first_source,
                        refused,
                        built,
                        cache.live(ticks) as u64,
                        state(can_send, me.0, can_tcp),
                        pongs,
                        prefix_word(prefix6),
                        v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
                    );
                    let gateway = cache
                        .lookup(Address::V4(peer_address()), ticks)
                        .unwrap_or(MacAddr::BROADCAST);
                    // Bound before serving, not before the demonstration: the
                    // loop above polls deliberately and would be woken for
                    // nothing. Refused on a machine with no inbox, which is a
                    // state — `serve` then behaves exactly as it did before.
                    call(syscall::INVOKE, INBOX, method::BIND_SELF, [0; 4]);
                    // Published *before* the blocking receive, so the kernel
                    // reads "serving" only when a caller can no longer strand.
                    SERVING_NOW.store(true, core::sync::atomic::Ordering::Relaxed);
                    report(
                        frames,
                        bytes,
                        first_source,
                        refused,
                        built,
                        cache.live(ticks) as u64,
                        state(can_send, me.0, can_tcp),
                        pongs,
                        prefix_word(prefix6),
                        v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
                    );
                    // The v6 identity and road, snapshotted at the door:
                    // `serve` has no cache to refresh a neighbour from, and
                    // on this network the router's link address never
                    // changes. Held from the advertisement itself rather
                    // than looked up — the cache's expiry made this
                    // snapshot None on any boot whose demonstration phase
                    // outlived the entry's lifetime, which was all of them.
                    let router6_mac = router6_link;
                    // **One last read before blocking.** `serve` parks in
                    // `receive` and is woken by a frame; on a link with no
                    // gateway there is no frame until this service sends one,
                    // and it cannot send without knowing its own address. A
                    // demonstration that ended before the configuration landed
                    // therefore left the service asleep for ever, holding an
                    // unspecified address. Deterministic here, where the
                    // configuration has certainly arrived.
                    if can_send
                        && me.0 == MacAddr::UNSPECIFIED
                        && let Some(identity) = read_interface()
                    {
                        me = identity;
                    }
                    serve(
                        &mut sockets,
                        me,
                        gateway,
                        global6,
                        router6_mac,
                        can_send,
                        can_tcp,
                        tail,
                        tcp_tail,
                    );
                }
                report(
                    frames,
                    bytes,
                    first_source,
                    refused,
                    built,
                    cache.live(ticks) as u64,
                    state(can_send, me.0, can_tcp),
                    pongs,
                    prefix_word(prefix6),
                    v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
                );
                exit()
            }
            // One look that found nothing. See `EMPTY_POLLS`.
            EMPTY_POLLS.store(
                EMPTY_POLLS.load(core::sync::atomic::Ordering::Relaxed) + 1,
                core::sync::atomic::Ordering::Relaxed,
            );
            run += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        // A frame arrived: close the run of empty looks that preceded it.
        if run > LONGEST_WAIT.load(core::sync::atomic::Ordering::Relaxed) {
            LONGEST_WAIT.store(run, core::sync::atomic::Ordering::Relaxed);
        }
        run = 0;
        quiet = 0;

        // The four-byte length first.
        let mut prefix = [0u8; ring::PREFIX];
        let Some(runs) = ring::length_to_read(layout, cursor) else {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
        unsafe { read_runs(RING_AT, prefix.as_mut_ptr(), runs) };
        // **The length is the low twenty-four bits, not the whole word.** The
        // top bits name the bond member the frame arrived on -- see
        // `ring::marked`. This read the word raw until 2026-09-08, when the
        // member index was added and this demonstration, which shares the ring
        // with `drain_ring`, began seeing every frame as sixteen million bytes:
        // 189 refusals, the tail walked forward four bytes at a time, and
        // nothing ever parsed. The frame's own bytes are the same either way;
        // what broke was the arithmetic in front of them.
        let (length, _, _) = ring::marked(u32::from_le_bytes(prefix));
        // A number the other side chose. Bounded before it is used, and a
        // refusal rather than a clamp: a frame that does not fit is not a
        // shorter frame, it is a producer this program has stopped believing.
        if length == 0 || length > MAX_FRAME {
            refused += 1;
            tail = tail.wrapping_add(ring::PREFIX as u64);
            publish(tail);
            continue;
        }

        // The producer has published a length but not yet the bytes. Not an
        // error and not a refusal: look again without moving the tail.
        let Some(framed) = ring::frame_to_read(layout, cursor, length) else {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        // SAFETY: the ring is mapped and `buffer` is `MAX_FRAME` writable
        // bytes, which `length` is bounded by above.
        unsafe { read_runs(RING_AT, buffer.as_mut_ptr(), framed.payload) };
        // Inbound, copy two of two, on the demonstration loop's path rather than
        // the service's. **After** the copy, not before: this path retries when
        // the producer has published a length and not yet the bytes, and a
        // counter incremented before the retry would price crossings that never
        // happened.
        copied();

        // The clock advances per *frame handled*, not per pass round the loop.
        // Per pass it ran at the speed of a spin, so a cache lifetime of a
        // thousand expired in milliseconds and the cache always read empty.
        // Time measured in frames is a fiction, but it is a fiction that orders
        // events the way the thing being measured does.
        ticks += 1;
        frames += 1;
        bytes += length as u64;
        if first_source == 0 && length >= 12 {
            // The source address, six bytes in. Reported rather than parsed:
            // this program has no idea what an Ethernet header means, and the
            // number exists so the kernel can check that the *same* frame
            // crossed two domain boundaries rather than that a counter moved.
            let mut value = 0u64;
            for octet in &buffer[6..12] {
                value = (value << 8) | u64::from(*octet);
            }
            first_source = value;
        }

        // A TCP segment arriving while the demonstration is still running.
        // Forwarded here as well as in `drain_ring`, because `bin/tcpd` opens
        // its own connection as soon as it is configured — which is while this
        // loop is still measuring — and an answer eaten here would cost it a
        // retransmission timeout for nothing.
        if can_tcp
            && let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::IPV4
            && let Ok((header, payload)) = Ipv4Header::parse(parsed.payload)
            && header.protocol == Protocol::TCP
            && !header.is_fragment()
            && header.destination == me.1
        {
            // SAFETY: the forward ring is mapped writable when `can_tcp`.
            unsafe { forward_tcp(header.source, header.destination, payload) };
        }
        // The second family's segments, forwarded here for the same
        // retransmission-sparing reason as the v4 arm above.
        if can_tcp
            && let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::IPV6
            && let Ok((header6, payload6)) = Ipv6Header::parse(parsed.payload)
            && header6.next_header == NextHeader::TCP
        {
            // SAFETY: the forward ring is mapped writable when `can_tcp`.
            unsafe { forward_tcp6(header6.source, header6.destination, payload6) };
        }

        // An IPv4 datagram addressed to us. The echo reply this program asked
        // for arrives here, and so would anything else anyone chose to send:
        // every refusal below is `bhaskix-net`'s rather than this program's.
        if let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::IPV4
            && let Ok((header, payload)) = Ipv4Header::parse(parsed.payload)
            && header.destination == me.1
            && header.protocol == Protocol::ICMP
            && !header.is_fragment()
            && let Ok(echo) = icmp::Echo::parse(payload)
        {
            if echo.is_reply {
                // The payload must come back unchanged, which is the only
                // thing that distinguishes an answer to *our* question from
                // any other echo reply on the segment.
                if echo.payload == PING_PAYLOAD {
                    pongs += 1;
                } else if echo.identifier == BURST_ID {
                    // A burst reply. Counted by identifier and length rather
                    // than by comparing every byte: the comparison is what the
                    // demonstration ping above is for, and doing it per packet
                    // would put this program's own memcmp inside the number it
                    // is trying to measure.
                    if echo.payload.len() == BURST_SMALL || echo.payload.len() == BURST_LARGE {
                        burst_pongs += 1;
                        BURST_PONGS.store(
                            u64::from(burst_pongs),
                            core::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }
            } else if can_send {
                // Somebody pinged us. Written, and not exercised on this
                // network: QEMU's gateway answers echo requests and never
                // sends them.
                let mut message = [0u8; MAX_FRAME];
                if let Ok(body) = icmp::write(
                    &mut message,
                    true,
                    echo.identifier,
                    echo.sequence,
                    echo.payload,
                ) && ipv4::write_header(
                    &mut outgoing[eth::HEADER..],
                    me.1,
                    header.source,
                    Protocol::ICMP,
                    body,
                    0x2602,
                )
                .is_ok()
                {
                    let at = eth::HEADER + ipv4::HEADER;
                    outgoing[at..at + body].copy_from_slice(&message[..body]);
                    if eth::write_header(&mut outgoing, parsed.source, me.0, EtherType::IPV4).is_ok()
                        // SAFETY: the return ring is mapped writable.
                        && unsafe { send(&outgoing[..at + body]) }
                    {
                        built += 1;
                    }
                }
            }
        }

        // RFC 0029 step 3: the second family's arrivals. Neighbour discovery
        // is accepted only at hop limit 255 — the check `icmpv6`'s header
        // assigned to the caller, because a discovery message that crossed a
        // router is a forgery by construction, and the hop limit lives in
        // the IP header only this program sees.
        if let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::IPV6
            && let Ok((header6, body6)) = Ipv6Header::parse(parsed.payload)
            && header6.next_header == NextHeader::ICMPV6
            && !body6.is_empty()
        {
            let (from6, to6) = (header6.source, header6.destination);
            match body6[0] {
                icmpv6::ROUTER_ADVERTISEMENT if header6.hop_limit == 255 => {
                    if let Ok(ra) = icmpv6::RouterAdvertisement::parse(body6, from6, to6) {
                        if let Some(link) = ra.source_link {
                            cache.learn(Address::V6(from6), link, ticks);
                            router6_link = Some(link);
                        }
                        if ra.router_lifetime_seconds > 0 && router6.is_none() {
                            router6 = Some(from6);
                        }
                        // SLAAC's one step: the advertised /64 plus this
                        // interface's identifier. Held once obtained — a
                        // later advertisement does not move an address
                        // sockets may already be bound to.
                        if global6.is_none()
                            && let Some(info) = ra.prefix
                            && info.autonomous
                            && info.prefix_length == 64
                            && me.0 != MacAddr::UNSPECIFIED
                        {
                            prefix6 = info.prefix;
                            global6 = Some(Ipv6Addr::from_prefix(
                                info.prefix,
                                Ipv6Addr::interface_id(me.0),
                            ));
                        }
                    }
                }
                icmpv6::NEIGHBOUR_ADVERTISEMENT if header6.hop_limit == 255 => {
                    if let Ok(na) = icmpv6::NeighbourAdvertisement::parse(body6, from6, to6)
                        && let Some(link) = na.target_link
                        && cache.learn(Address::V6(na.target), link, ticks)
                        && na.target == HOST6
                    {
                        resolved6 = true;
                    }
                }
                icmpv6::NEIGHBOUR_SOLICITATION if header6.hop_limit == 255 && can_send => {
                    if let Ok(ns) = icmpv6::NeighbourSolicitation::parse(body6, from6, to6)
                        && (ns.target == link_local || Some(ns.target) == global6)
                        && !from6.is_unspecified()
                    {
                        // Answered from the address that was asked about, to
                        // the asker, at their link address — the option if
                        // they carried one, the frame's source if not.
                        let to_mac = ns.source_link.unwrap_or(parsed.source);
                        let mut message = [0u8; 40];
                        if let Ok(body) = icmpv6::write_neighbour_advertisement(
                            &mut message,
                            ns.target,
                            from6,
                            ns.target,
                            true,
                            Some(me.0),
                        ) && let Some(total) = frame6(
                            &mut outgoing,
                            to_mac,
                            me.0,
                            ns.target,
                            from6,
                            255,
                            &message[..body],
                        )
                            // SAFETY: the return ring is mapped writable.
                            && unsafe { send(&outgoing[..total]) }
                        {
                            built += 1;
                        }
                    }
                }
                icmpv6::ECHO_REQUEST if can_send => {
                    if let Ok(echo) = icmpv6::Echo::parse(body6, from6, to6)
                        && !echo.is_reply
                        && (to6 == link_local || Some(to6) == global6)
                    {
                        let mut message = [0u8; MAX_FRAME];
                        if let Ok(body) = icmpv6::write_echo(
                            &mut message,
                            to6,
                            from6,
                            true,
                            echo.identifier,
                            echo.sequence,
                            echo.payload,
                        ) && let Some(total) = frame6(
                            &mut outgoing,
                            parsed.source,
                            me.0,
                            to6,
                            from6,
                            64,
                            &message[..body],
                        )
                            // SAFETY: the return ring is mapped writable.
                            && unsafe { send(&outgoing[..total]) }
                        {
                            built += 1;
                        }
                    }
                }
                icmpv6::ECHO_REPLY => {
                    // The v6 pong. Matched by identifier and payload, the
                    // same discipline as the v4 one: only an exact return
                    // proves the whole path.
                    if let Ok(echo) = icmpv6::Echo::parse(body6, from6, to6)
                        && echo.is_reply
                        && echo.identifier == PING6_ID
                        && echo.payload == PING_PAYLOAD
                    {
                        pongs6 += 1;
                    }
                }
                _ => {}
            }
        }

        // **This is the first parsing this system does of bytes from a wire.**
        // Every one of them was chosen by whoever can reach the segment, and
        // every refusal below is `bhaskix-net`'s rather than this program's.
        if let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::ARP
            && let Ok(packet) = ArpPacket::parse(parsed.payload)
        {
            match packet.operation {
                // Somebody answered. The cache learns it, refusing on its own
                // terms what should not be believed -- a group hardware
                // address, an unspecified protocol address.
                ArpOp::Reply => {
                    cache.learn(
                        Address::V4(packet.sender_protocol),
                        packet.sender_hardware,
                        ticks,
                    );
                }
                // Somebody asked, and if they asked for us we answer. Written
                // and host-tested; on this network nothing has a reason to ask
                // us yet, so it is not exercised live until something does.
                ArpOp::Request if can_send && packet.target_protocol == me.1 => {
                    let reply = ArpPacket {
                        operation: ArpOp::Reply,
                        sender_hardware: me.0,
                        sender_protocol: me.1,
                        target_hardware: packet.sender_hardware,
                        target_protocol: packet.sender_protocol,
                    };
                    let mut packet_out = [0u8; arp::PACKET];
                    if reply.write(&mut packet_out).is_ok()
                        && let Some(out) = frame(
                            &mut outgoing,
                            packet.sender_hardware,
                            me.0,
                            EtherType::ARP,
                            &packet_out,
                        )
                        // SAFETY: the return ring is mapped writable.
                        && unsafe { send(&outgoing[..out]) }
                    {
                        built += 1;
                    }
                }
                ArpOp::Request => {}
            }
        }

        tail = framed.next;
        publish(tail);
        // **What this service thinks it is holding** — RFC 0063.
        //
        // Nobody had ever asked. Every hypothesis about the socket-reclaim
        // defect has been about the *adapter's* bookkeeping -- which process
        // record, which handle, which generation -- and two corrections to that
        // bookkeeping made the machine deterministically worse. The port is
        // held here, so this is the service's own answer.
        //
        // Into statics that `report` and `refresh` both carry, rather than a
        // write of its own into the page: the first version did the latter and
        // landed on two words that were already in use. See `BOUND_PORTS`.
        BOUND_PORTS.store(bound_ports(&sockets), core::sync::atomic::Ordering::Relaxed);
        SLOT_GENERATIONS.store(
            slot_generations(&sockets),
            core::sync::atomic::Ordering::Relaxed,
        );
        UPPER_SLOTS.store(upper_slots(&sockets), core::sync::atomic::Ordering::Relaxed);
        report(
            frames,
            bytes,
            first_source,
            refused,
            built,
            cache.live(ticks) as u64,
            state(can_send, me.0, can_tcp),
            pongs,
            prefix_word(prefix6),
            v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
        );
    }
}

/// Tells the producer how far this program has read.
fn publish(tail: u64) {
    // The bytes are finished with before the index that frees them is written,
    // which is the mirror of the producer's fence: a producer that saw the new
    // tail first could overwrite a frame still being read.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile((RING_AT + ring::TAIL_OFFSET as u64) as *mut u64, tail);
    }
}

/// Leaves the findings where the kernel granted memory for them.
/// The high half of the SLAAC prefix, as one report word. Zero until a
/// router advertisement carried one, which is what makes zero mean "none".
fn prefix_word(prefix: Ipv6Addr) -> u64 {
    let o = prefix.octets();
    u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
}

/// What v6 obtained, as bits, with the echo count above them.
fn v6_word(global: bool, router: bool, resolved: bool, pongs6: u64) -> u64 {
    u64::from(global) | (u64::from(router) << 1) | (u64::from(resolved) << 2) | (pongs6 << 8)
}

/// The ports this service currently holds, packed four to a word.
///
/// **Nobody has ever asked it, and that is why the socket-reclaim defect has
/// survived three hypotheses.** Every theory so far has been about the
/// *adapter's* bookkeeping — which process record, which handle, which
/// generation — and two corrections to that bookkeeping made the machine
/// deterministically worse (RFC 0063). The port is held *here*, and this is the
/// service saying what it thinks it holds rather than the adapter saying what
/// it thinks it released.
///
/// Six slots, the low four packed as `u16`s; a zero port is a free slot, which
/// is this table's own convention.
fn bound_ports(sockets: &[Socket; SOCKETS]) -> u64 {
    let mut packed = 0u64;
    for (index, socket) in sockets.iter().take(4).enumerate() {
        packed |= u64::from(socket.port) << (index * 16);
    }
    packed
}

/// The generation of each of the low four slots, packed four to a word.
///
/// **The discriminator [`bound_ports`] lacks.** That instrument samples once,
/// at the boot report, which is after both the release and the rebind — so a
/// boot where the reclaim worked and one where it did not can end with the
/// same port in the same slot, and they do: `slot 0 port 2` reads identically
/// on both. The generation does not: it is bumped every time the slot is
/// reused, so two boots that end alike but arrived differently say so here.
/// Truncated to 16 bits, which is four reuses short of nothing this boot can
/// reach — the whole boot binds a handful of sockets.
fn slot_generations(sockets: &[Socket; SOCKETS]) -> u64 {
    let mut packed = 0u64;
    for (index, socket) in sockets.iter().take(4).enumerate() {
        packed |= u64::from(socket.generation as u16) << (index * 16);
    }
    packed
}

/// The last two slots, as `port`, `generation`, `port`, `generation`.
///
/// `SOCKETS` is six and a word holds four `u16`s, so the two words above cover
/// slots 0 to 3 and this one covers the rest. Stated rather than left implicit:
/// an instrument that watches four of six slots cannot see a leak in the other
/// two, and this defect has already cost two fixes aimed at the wrong place.
fn upper_slots(sockets: &[Socket; SOCKETS]) -> u64 {
    let mut packed = 0u64;
    for (index, socket) in sockets.iter().skip(4).take(2).enumerate() {
        packed |= u64::from(socket.port) << (index * 32);
        packed |= u64::from(socket.generation as u16) << (index * 32 + 16);
    }
    packed
}

#[allow(clippy::too_many_arguments)]
fn report(
    frames: u64,
    bytes: u64,
    first_source: u64,
    refused: u64,
    built: u64,
    learned: u64,
    state: u64,
    pongs: u64,
    v6_prefix: u64,
    v6_state: u64,
) {
    let words = [
        MARKER,
        frames,
        bytes,
        first_source,
        refused,
        // Frames this program *built* and handed back, how many of them were
        // ARP requests, and how many mappings its cache holds. The first says
        // the return path works from this end; the second separates *asked
        // once and nothing answered* from *asked forty times and nothing
        // answered*; the third is the neighbour cache running outside a host
        // test for the first time since it was written.
        //
        // **The count is a parameter rather than something each caller packs.**
        // There are five `report` call sites and the first version packed it at
        // two of them, so the last report written before the kernel reads --
        // one of the three missed -- published a zero over a real count, and
        // the boot said `asked 0 time(s)` while the frames had plainly been
        // built. A parameter makes that a compile error instead.
        built,
        learned,
        // What this program was able to do, as bits: it could send at all, and
        // it had been told what this interface is. "Built nothing" has three
        // causes -- no return ring, no configuration, or a ring that would not
        // take the bytes -- and a count cannot say which.
        state,
        // Echo replies whose payload came back exactly as sent. The only
        // number here that says the whole stack worked end to end rather than
        // that each piece did.
        pongs,
        DELIVERED.load(core::sync::atomic::Ordering::Relaxed),
        WHY.load(core::sync::atomic::Ordering::Relaxed),
        // Words 11 and 12 belong to the ring's own head and tail -- zero
        // here, filled by `refresh` once serving starts, printed by the
        // kernel's "ipd after" line. RFC 0029's first draft took the zeros
        // for spares and its v6 words were silently overwritten on the
        // first refresh; the v6 words live at 21 and 22 instead, and this
        // comment is the map that was missing.
        0,
        0,
        COPIES.load(core::sync::atomic::Ordering::Relaxed),
        BURST_PHASE.load(core::sync::atomic::Ordering::Relaxed),
        BURST_PONGS.load(core::sync::atomic::Ordering::Relaxed),
        BURST_RESULT.load(core::sync::atomic::Ordering::Relaxed),
        BURST_SENT.load(core::sync::atomic::Ordering::Relaxed),
        EMPTY_POLLS.load(core::sync::atomic::Ordering::Relaxed),
        LONGEST_WAIT.load(core::sync::atomic::Ordering::Relaxed),
        NOTIFIED_WAKES.load(core::sync::atomic::Ordering::Relaxed),
        // RFC 0029 step 3: the high half of the SLAAC prefix, and a word
        // packing what v6 obtained with the v6 echo count above it. Stored
        // into statics as well, so `refresh` keeps reporting them after
        // serving starts.
        v6_prefix,
        v6_state,
        // Words 23 and 24: which ports this service holds and how many times
        // each slot has been reused. RFC 0063. Appended, not slotted into a
        // zero that looked spare -- see `BOUND_PORTS`.
        BOUND_PORTS.load(core::sync::atomic::Ordering::Relaxed),
        SLOT_GENERATIONS.load(core::sync::atomic::Ordering::Relaxed),
        UPPER_SLOTS.load(core::sync::atomic::Ordering::Relaxed),
        // Words 26 and 27: TCP segments handed to `bin/tcpd` and taken back.
        // Both counters have existed since TCP did and **neither had a reader**
        // -- they were incremented on every segment and printed nowhere, which
        // is why §3's cookie row has spent four sightings unable to say whether
        // the third leg of a handshake reached the service at all. Appended,
        // for the reason written at 23.
        TCP_FORWARDED.load(core::sync::atomic::Ordering::Relaxed),
        TCP_RETURNED.load(core::sync::atomic::Ordering::Relaxed),
        // Word 28: how many members the interface this address sits on has --
        // RFC 0074 step 6, and the only evidence that the stack is running
        // over a bond rather than over a device. Zero means the address is on
        // a port directly, which is every machine with one NIC. Appended, for
        // the reason written at 23.
        BOUND_SHAPE.load(core::sync::atomic::Ordering::Relaxed),
        // Word 29: what the LACP machine believes -- RFC 0074 step 5.
        LACP_STATE.load(core::sync::atomic::Ordering::Relaxed),
        // Word 30: LACPDUs sent in the high half, slow-protocol frames heard in
        // the low. **So a silent partner and a silent us are different
        // numbers** -- word 29 is zero for both, because it is only ever
        // written when a PDU arrives, and a boot report that cannot tell those
        // apart is one that invites the wrong conclusion. RFC 0076.
        LACP_TRAFFIC.load(core::sync::atomic::Ordering::Relaxed),
        // Word 31: whether the bond under this address is 802.3ad. The kernel
        // printed the word "active-backup" as a literal, so it said that of an
        // LACP bond too. What is reported now is what was built.
        u64::from(BOND_MODE_LACP.load(core::sync::atomic::Ordering::Relaxed)),
        // Words 32 and 33: the partner's own flags per link, and its record of
        // us. Zero here until a PDU has arrived, which `refresh` then keeps
        // current -- and the tail sentinel below is what lets a reader tell
        // that zero from a word nobody wrote.
        LACP_PARTNER_STATE.load(core::sync::atomic::Ordering::Relaxed),
        LACP_RECORDED.load(core::sync::atomic::Ordering::Relaxed),
        // **Words 34 to 37: the address each link's LACPDU leaves under.**
        //
        // Appended, for the reason written at 23. The kernel prints what it
        // *published* to this service, which says nothing about what this
        // service did with it -- and "four links, four addresses" is the whole
        // claim of RFC 0076 step 4. This is the address after the fallback a
        // member with none takes, so a boot that shows four identical words
        // here has found the bug rather than hidden it.
        SPEAKING_AS[0].load(core::sync::atomic::Ordering::Relaxed),
        SPEAKING_AS[1].load(core::sync::atomic::Ordering::Relaxed),
        SPEAKING_AS[2].load(core::sync::atomic::Ordering::Relaxed),
        SPEAKING_AS[3].load(core::sync::atomic::Ordering::Relaxed),
        // **Words 38 to 40: what the neighbour says it is**, from its LLDP.
        // An inventory of the TLV types it sends, its port id, and the first
        // organizationally specific OUI and subtype -- see `LLDP_SEEN`. Only
        // what the C620 datasheet grounds is decoded; what the switch actually
        // sends decides what is worth decoding next.
        LLDP_SEEN.load(core::sync::atomic::Ordering::Relaxed),
        LLDP_ORGANISATION.load(core::sync::atomic::Ordering::Relaxed),
        LLDP_PORT[0].load(core::sync::atomic::Ordering::Relaxed),
        LLDP_PORT[1].load(core::sync::atomic::Ordering::Relaxed),
        LLDP_PORT[2].load(core::sync::atomic::Ordering::Relaxed),
        LLDP_PORT[3].load(core::sync::atomic::Ordering::Relaxed),
        VLANS_SEEN[0].load(core::sync::atomic::Ordering::Relaxed),
        VLANS_SEEN[1].load(core::sync::atomic::Ordering::Relaxed),
        VLANS_SEEN[2].load(core::sync::atomic::Ordering::Relaxed),
        VLANS_SEEN[3].load(core::sync::atomic::Ordering::Relaxed),
        // **Words 48 and 49: where the neighbour says it lives, and its name.**
        // See `LLDP_MANAGEMENT`.
        //
        // **This array and `refresh`'s are the same report built twice**, and
        // nothing checks that they agree. A word added to one and not the other
        // publishes a different report depending on which path ran last, and
        // the length assertion only catches it because both feed the same
        // `write_report`. That is a weaker guarantee than it looks: two arrays
        // of the right length can still carry different things in the same
        // slot.
        LLDP_MANAGEMENT.load(core::sync::atomic::Ordering::Relaxed),
        LLDP_NAME.load(core::sync::atomic::Ordering::Relaxed),
        // **Where the ARP request stopped, when it stopped.** Tries at 19:0,
        // frames it could not build at 39:20, sends the ring refused at 59:40.
        // A single zero for "asked none" is compatible with never reaching the
        // block, with failing to build the frame, and with the ring refusing
        // it, and those are three different faults.
        //
        // **Appended rather than inserted.** This array is read by index in the
        // kernel in dozens of places -- `ipd[23]`, `ipd[40 + n]`, `ipd[44..48]`
        // -- so a word placed in the middle silently renumbers all of them. The
        // first attempt at this put it at index 6 and moved everything after.
        ASK_STALLS.load(core::sync::atomic::Ordering::Relaxed),
    ];
    V6_PREFIX.store(v6_prefix, core::sync::atomic::Ordering::Relaxed);
    V6_STATE.store(v6_state, core::sync::atomic::Ordering::Relaxed);
    for (slot, value) in CACHE.iter().zip([
        frames,
        bytes,
        first_source,
        refused,
        built,
        learned,
        state,
        pongs,
    ]) {
        slot.store(value, core::sync::atomic::Ordering::Relaxed);
    }
    write_report(words);
}

/// Puts the report's words on the report page.
///
/// The count has moved four times and this comment said "ten" until 2026-09-05,
/// which is a small thing that costs a reader the one fact they came for. It is
/// whatever the array says: the type is the documentation, and both builders --
/// `report` and `refresh` -- are forced to agree with it by the compiler, which
/// is the only reason the v6 words' silent overwrite could not happen twice.
fn write_report(words: [u64; REPORT_WORDS]) {
    // SAFETY: the page this program mapped writable, which nothing else
    // reaches. The marker is written last, so a kernel reading a partial report
    // sees no marker rather than half the fields.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((REPORT_AT + index as u64 * 8) as *mut u64, *word);
        }
        // **The tail, one word past the report**, so a reader can prove the
        // page was written to its full length instead of assuming it. Written
        // before the marker, for the marker's own reason.
        core::ptr::write_volatile(
            (REPORT_AT + REPORT_WORDS as u64 * 8) as *mut u64,
            REPORT_TAIL,
        );
        core::ptr::write_volatile(REPORT_AT as *mut u64, words[0]);
    }
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call ipd_main
    ud2
"#
);
