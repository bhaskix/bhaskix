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

use bhaskix_abi::{method, ring, status, syscall};
use bhaskix_net::{
    ArpCache, ArpOp, ArpPacket, EthFrame, EtherType, Ipv4Addr, Ipv4Header, MacAddr, Protocol, arp,
    eth, icmp, ipv4,
};

/// Slot: the ring `bin/netd` writes frames into.
const RING: u64 = 0;
/// Slot: the page this program leaves its findings in.
const REPORT: u64 = 1;
/// Slot: the ring this program hands frames back to `bin/netd` through.
const BACK: u64 = 2;
/// Slot: what this interface is, read-only, written by the kernel.
const CONFIG: u64 = 3;

/// Where this program maps what it holds.
const RING_AT: u64 = 0x2100_0000;
const REPORT_AT: u64 = 0x2110_0000;
const BACK_AT: u64 = 0x2120_0000;
const CONFIG_AT: u64 = 0x2130_0000;

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

/// The marker the kernel writes before this program's configuration is true.
const CONFIG_MARKER: u64 = 0x3146_4e43_5049_5f4e;

/// The address this program asks about, to prove it can send.
///
/// **Deliberately not the one `bin/netd`'s probe asks for.** The driver asks
/// for `10.0.2.2`; this asks for `10.0.2.3`, so a request for `.3` on the wire
/// is a frame that can only have been built here, crossed the return ring, and
/// been transmitted by a program that cannot parse it. One byte of difference
/// is what makes the two distinguishable to a test.
const ASK_ABOUT: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);

/// The address this program pings, once it knows how to reach it.
///
/// QEMU's built-in network answers an echo request to its gateway, which makes
/// a *sent* ping the demonstrable half of ICMP here. Answering one is written
/// and untestable on this network: nothing has a reason to ping us.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

/// What this program puts in an echo request, and expects back unchanged.
const PING_PAYLOAD: [u8; 17] = *b"bhaskix-icmp-0001";

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

/// Copies `length` bytes out of the ring at free-running `tail` into `into`.
///
/// # Safety
///
/// The ring must be mapped at [`RING_AT`] and `into` writable for `length`.
unsafe fn ring_copy_out(
    layout: ring::Layout,
    cursor: ring::Cursor,
    into: *mut u8,
    length: usize,
) -> bool {
    if cursor.readable() < length {
        return false;
    }
    let (first, second) = ring::read_runs(layout, cursor, length);
    if first.length + second.length != length {
        return false;
    }
    // SAFETY: both runs are offsets `abi::ring` computed inside the region this
    // program mapped, `into` is writable for `length` by the caller's
    // obligation, and the two runs are the halves one transfer wraps into.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (RING_AT + first.offset as u64) as *const u8,
            into,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                (RING_AT + second.offset as u64) as *const u8,
                into.add(first.length),
                second.length,
            );
        }
    }
    true
}

/// Copies `length` bytes from `source` into the return ring.
///
/// # Safety
///
/// The return ring must be mapped writable at [`BACK_AT`], and `source`
/// readable for `length`.
unsafe fn back_copy_in(
    layout: ring::Layout,
    head: u64,
    tail: u64,
    source: *const u8,
    length: usize,
) -> Option<u64> {
    let cursor = ring::Cursor::new(layout, head, tail)?;
    if cursor.writable() < length {
        return None;
    }
    let (first, second) = ring::write_runs(layout, cursor, length);
    // SAFETY: both runs are offsets `abi::ring` computed inside the region this
    // program mapped, and `source` is readable for `length` by the caller.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source,
            (BACK_AT + first.offset as u64) as *mut u8,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                source.add(first.length),
                (BACK_AT + second.offset as u64) as *mut u8,
                second.length,
            );
        }
    }
    Some(head + length as u64)
}

/// Hands one frame to `bin/netd` to put on the wire.
///
/// # Safety
///
/// The return ring must be mapped writable at [`BACK_AT`].
unsafe fn send(frame: &[u8]) -> bool {
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
    let prefix = (frame.len() as u32).to_le_bytes();
    // SAFETY: the ring is mapped and both sources are readable.
    let Some(after_prefix) = (unsafe { back_copy_in(layout, head, tail, prefix.as_ptr(), 4) })
    else {
        return false;
    };
    // SAFETY: as above -- the ring is mapped writable and `frame` is a slice
    // this program owns, readable for its own length.
    let Some(after_frame) =
        (unsafe { back_copy_in(layout, after_prefix, tail, frame.as_ptr(), frame.len()) })
    else {
        return false;
    };
    // The bytes, then a fence, then the index that publishes them. The reader
    // is another domain on another CPU and takes no lock.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (BACK_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            after_frame,
        );
    }
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

/// What this program was able to do, as bits.
fn state(can_send: bool, mac: MacAddr) -> u64 {
    u64::from(can_send) | (u64::from(mac != MacAddr::UNSPECIFIED) << 1)
}

/// The entry point.
#[unsafe(no_mangle)]
extern "C" fn ipd_main() -> ! {
    if !attach(RING, RING_AT, 1) || !attach(REPORT, REPORT_AT, 1) {
        exit()
    }
    let can_send = attach(BACK, BACK_AT, 1) && attach(CONFIG, CONFIG_AT, 0);
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
    let mut cache = ArpCache::<8>::new(ARP_LIFETIME);
    // Stands in for a clock. See `ARP_LIFETIME`.
    let mut ticks = 0u64;
    let mut me = (MacAddr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
    let mut asked = false;
    let mut pinged = false;
    let mut quiet = 0u32;
    let mut pongs = 0u64;
    // Only this program advances the tail, so it is kept here and written out
    // rather than read back. A consumer that re-read its own index would be
    // trusting the producer with it.
    let mut tail = 0u64;

    // A report before anything has arrived, so that "this program never ran"
    // and "this program ran and saw nothing" are different findings. Without
    // it the kernel reads an absent marker for both, and the two have entirely
    // different causes.
    report(0, 0, 0, 0, 0, 0, u64::from(can_send), 0);

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
            state(can_send, me.0),
            pongs,
        );

        // What this interface is, once the kernel has been able to say. It
        // cannot say until `bin/netd` has read the address out of the device,
        // so this waits for a marker rather than believing a page of zeroes.
        if can_send && me.0 == MacAddr::UNSPECIFIED {
            // SAFETY: the configuration page, mapped read-only by this program.
            let (marker, mac, address) = unsafe {
                (
                    core::ptr::read_volatile(CONFIG_AT as *const u64),
                    core::ptr::read_volatile((CONFIG_AT + 8) as *const u64),
                    core::ptr::read_volatile((CONFIG_AT + 16) as *const u64),
                )
            };
            if marker == CONFIG_MARKER {
                let mut octets = [0u8; 6];
                for (index, octet) in octets.iter_mut().enumerate() {
                    *octet = (mac >> (40 - index * 8)) as u8;
                }
                me = (MacAddr(octets), Ipv4Addr(address as u32));
            }
        }

        // One request of this program's own, so that something on the wire can
        // only have come from here. Built entirely by `bhaskix-net`.
        if can_send && !asked && me.0 != MacAddr::UNSPECIFIED {
            let request = ArpPacket {
                operation: ArpOp::Request,
                sender_hardware: me.0,
                sender_protocol: me.1,
                target_hardware: MacAddr::UNSPECIFIED,
                target_protocol: ASK_ABOUT,
            };
            let mut packet = [0u8; arp::PACKET];
            if request.write(&mut packet).is_ok()
                && let Some(length) = frame(
                    &mut outgoing,
                    MacAddr::BROADCAST,
                    me.0,
                    EtherType::ARP,
                    &packet,
                )
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..length]) }
            {
                built += 1;
                asked = true;
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
            && let Some(gateway) = cache.lookup(GATEWAY, ticks)
        {
            let mut message = [0u8; icmp::HEADER + PING_PAYLOAD.len()];
            if let Ok(body) = icmp::write(&mut message, false, 0xbe57, 1, &PING_PAYLOAD)
                && ipv4::write_header(
                    &mut outgoing[eth::HEADER..],
                    me.1,
                    GATEWAY,
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
            // Not before the work is done. Twenty thousand idle passes elapse
            // in a fraction of a second, and the kernel cannot publish this
            // program's configuration until the driver has read the device's
            // address -- so an exit on idleness alone quits before there is
            // anything to be idle about.
            //
            // The second bound is the backstop for a machine where the
            // configuration never comes at all, which is every boot without a
            // DMA window: there is nothing to wait for and no reason to spin.
            let done = asked && pinged;
            if (done && quiet > 20_000) || quiet > 2_000_000 {
                report(
                    frames,
                    bytes,
                    first_source,
                    refused,
                    built,
                    cache.live(ticks) as u64,
                    state(can_send, me.0),
                    pongs,
                );
                exit()
            }
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        quiet = 0;

        // The four-byte length first.
        let mut prefix = [0u8; 4];
        // SAFETY: the ring is mapped and `prefix` is four writable bytes.
        if !unsafe { ring_copy_out(layout, cursor, prefix.as_mut_ptr(), 4) } {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        let length = u32::from_le_bytes(prefix) as usize;
        // A number the other side chose. Bounded before it is used, and a
        // refusal rather than a clamp: a frame that does not fit is not a
        // shorter frame, it is a producer this program has stopped believing.
        if length == 0 || length > MAX_FRAME {
            refused += 1;
            tail = tail.wrapping_add(4);
            publish(tail);
            continue;
        }

        let Some(after_prefix) = ring::Cursor::new(layout, head, tail + 4) else {
            refused += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        // SAFETY: the ring is mapped and `buffer` is `MAX_FRAME` writable
        // bytes, which `length` is bounded by above.
        if !unsafe { ring_copy_out(layout, after_prefix, buffer.as_mut_ptr(), length) } {
            // The producer has published a length but not yet the bytes. Not
            // an error and not a refusal: look again without moving the tail.
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }

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
                    cache.learn(packet.sender_protocol, packet.sender_hardware, ticks);
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

        tail = tail.wrapping_add(4 + length as u64);
        publish(tail);
        report(
            frames,
            bytes,
            first_source,
            refused,
            built,
            cache.live(ticks) as u64,
            state(can_send, me.0),
            pongs,
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
) {
    let words = [
        MARKER,
        frames,
        bytes,
        first_source,
        refused,
        // Frames this program *built* and handed back, and how many mappings
        // its cache holds. The first says the return path works from this end;
        // the second is the `ArpCache` running outside a host test for the
        // first time since it was written.
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
    ];
    // SAFETY: the page this program mapped writable, which nothing else
    // reaches. The marker is written last, so a kernel reading a partial report
    // sees no marker rather than half the fields.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((REPORT_AT + index as u64 * 8) as *mut u64, *word);
        }
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
