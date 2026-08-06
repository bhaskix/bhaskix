// SPDX-License-Identifier: Apache-2.0
//! The split virtqueue: descriptors, an available ring, a used ring.
//!
//! [RFC 0014](../../docs/rfc/0014-driver-framework.md) step 5. Two drivers in
//! this tree implemented this protocol independently — one in the kernel and
//! one in a domain — and the second cost three bugs the first had already
//! learned. This is the part they can share: the layout the specification
//! fixes, and the order the writes have to happen in.
//!
//! # What it does not know
//!
//! Where the rings came from. The kernel allocates physical frames and reaches
//! them through the direct map; a driver in a domain maps memory it holds. So
//! every ring is given twice — once as the address *this* code writes through,
//! and once as the address the **device** is told. With an IOMMU those differ,
//! and that is the whole of RFC 0012 from a driver's point of view.
//!
//! # Why the accesses go through [`Bus`]
//!
//! Rings are memory rather than registers, so a plain volatile store would do.
//! Using the same trait buys the same test double: a device model can watch
//! the *order* the ring is written in, which is the one property here that no
//! amount of reading the values afterwards can check.

use crate::{Bus, Volatile};

/// A descriptor's `next` field is meaningful.
pub const NEXT: u16 = 1;
/// The device writes this buffer. Without it, the device reads.
pub const WRITE: u16 = 2;

/// Where one ring is, from both sides.
#[derive(Clone, Copy, Debug)]
pub struct Ring {
    /// The address this code writes through.
    pub at: usize,
    /// The address the device is told, which is not always the same one.
    pub device: u64,
}

/// One split virtqueue.
pub struct Virtqueue<B: Bus = Volatile> {
    descriptors: Ring,
    available: Ring,
    used: Ring,
    size: u16,
    /// The next index this driver will publish.
    available_index: u16,
    /// The last used index it has seen.
    used_index: u16,
    bus: core::marker::PhantomData<B>,
}

impl<B: Bus> Virtqueue<B> {
    /// Names a queue whose three rings are already allocated and zeroed.
    ///
    /// # Safety
    ///
    /// Each ring's `at` must be a mapping, writable and live for as long as
    /// this value, of at least the bytes that ring needs for `size` entries:
    /// sixteen per descriptor, `6 + 2 * size` for the available ring, and
    /// `6 + 8 * size` for the used one. `size` must be a power of two, which
    /// is what makes the index wrap correct.
    #[must_use]
    pub const unsafe fn new(descriptors: Ring, available: Ring, used: Ring, size: u16) -> Self {
        Self {
            descriptors,
            available,
            used,
            size,
            available_index: 0,
            used_index: 0,
            bus: core::marker::PhantomData,
        }
    }

    /// Where the device should be told each ring is.
    #[must_use]
    pub const fn addresses(&self) -> (u64, u64, u64) {
        (
            self.descriptors.device,
            self.available.device,
            self.used.device,
        )
    }

    /// Fills in one descriptor.
    ///
    /// `address` is the **device's** address for the buffer, not this code's.
    /// Handing over a physical address where a translated one was needed is
    /// the mistake RFC 0012 exists to make visible, and naming the parameter
    /// is as far as a type can go towards preventing it.
    pub fn describe(&self, index: u16, address: u64, length: u32, flags: u16, next: u16) {
        let at = self.descriptors.at + (index as usize) * 16;
        // SAFETY: `new`'s obligation -- `index` is bounded by the caller
        // against `size`, and a descriptor is sixteen bytes at that offset.
        unsafe {
            B::store32(at, address as u32);
            B::store32(at + 4, (address >> 32) as u32);
            B::store32(at + 8, length);
            B::store16(at + 12, flags);
            B::store16(at + 14, next);
        }
    }

    /// Publishes a chain, and says nothing about when the device will look.
    ///
    /// The order is the protocol. The head goes into the ring, then a fence,
    /// then the index that makes it visible — a device that saw the index
    /// first would follow a descriptor nobody had written. The device is not a
    /// thread and takes no lock; the fence is the whole of what orders these
    /// writes as far as it is concerned.
    pub fn publish(&mut self, head: u16) {
        let slot = (self.available_index % self.size) as usize;
        // SAFETY: `new`'s obligation. The ring proper starts six bytes in:
        // flags, then index, then the entries.
        unsafe {
            B::store16(self.available.at + 4 + slot * 2, head);
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.available_index = self.available_index.wrapping_add(1);
        // SAFETY: as above; the index is two bytes in.
        unsafe {
            B::store16(self.available.at + 2, self.available_index);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Takes the next completion, if the device has published one.
    ///
    /// `None` means nothing new — which is a normal answer and not an error,
    /// because a driver polling between requests wants to hear it.
    pub fn completed(&mut self) -> Option<u16> {
        // SAFETY: `new`'s obligation. Volatile because this changes without
        // this code writing it, which is the entire question being asked.
        let published = unsafe { B::load16(self.used.at + 2) };
        if published == self.used_index {
            return None;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // The entry this index made visible, not the index itself: a driver
        // that returned the index would be telling its caller how many
        // requests had ever finished rather than which one just did.
        let slot = (self.used_index % self.size) as usize;
        // SAFETY: as above; an entry is eight bytes, six into the ring.
        let id = unsafe { B::load32(self.used.at + 4 + slot * 8) };
        self.used_index = self.used_index.wrapping_add(1);
        Some(id as u16)
    }

    /// How many completions are outstanding, for reporting.
    #[must_use]
    pub fn seen(&self) -> u16 {
        self.used_index
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{self, Model};

    use super::{NEXT, Ring, Virtqueue, WRITE};

    /// Three rings inside the model's register file, at offsets that do not
    /// overlap. Small deliberately: a queue of four wraps in four requests,
    /// and wrapping is the part worth testing.
    fn queue() -> Virtqueue<Model> {
        // SAFETY: `Model` answers from its own array, so every address here is
        // backed for as long as the test runs. Four entries: 64 bytes of
        // descriptors, 14 of available ring, 38 of used.
        unsafe {
            Virtqueue::new(
                Ring {
                    at: 0x00,
                    device: 0x1000,
                },
                Ring {
                    at: 0x40,
                    device: 0x2000,
                },
                Ring {
                    at: 0x60,
                    device: 0x3000,
                },
                4,
            )
        }
    }

    #[test]
    fn a_chain_is_written_before_the_index_that_publishes_it() {
        // The one property here that reading the values afterwards cannot
        // check. A device that saw the index first would follow a descriptor
        // nobody had written, and the memory would look identical either way
        // once both writes had landed.
        let _alone = testing::exclusive();
        let mut queue = queue();

        queue.describe(0, 0x1000, 16, NEXT, 1);
        queue.publish(0);

        // The available ring's index lives two bytes in; the entry four.
        let writes: alloc::vec::Vec<(usize, u64)> = (0..testing::accesses())
            .map(testing::access)
            .filter(|(write, ..)| *write)
            .map(|(_, _, at, value)| (at, value))
            .collect();

        let entry = writes
            .iter()
            .position(|(at, _)| *at == 0x40 + 4)
            .expect("the ring entry was written");
        let index = writes
            .iter()
            .position(|(at, _)| *at == 0x40 + 2)
            .expect("the index was written");
        assert!(entry < index, "the entry is published before the index");
    }

    #[test]
    fn a_descriptor_holds_what_the_device_will_read() {
        let _alone = testing::exclusive();
        let queue = queue();
        queue.describe(1, 0x1234_5678_9abc_def0, 512, NEXT | WRITE, 2);

        // Sixteen bytes at index one, written as the specification lays them
        // out. The offsets are spelled here rather than recomputed with the
        // expression `describe` uses, because a check that repeats the formula
        // cannot catch an error in it.
        let at = 0x10;
        let writes: alloc::vec::Vec<(usize, usize, u64)> = (0..testing::accesses())
            .map(testing::access)
            .filter(|(write, ..)| *write)
            .map(|(_, width, at, value)| (at, width, value))
            .collect();
        assert!(writes.contains(&(at, 4, 0x9abc_def0)), "address, low half");
        assert!(
            writes.contains(&(at + 4, 4, 0x1234_5678)),
            "address, high half"
        );
        assert!(writes.contains(&(at + 8, 4, 512)), "length");
        assert!(
            writes.contains(&(at + 12, 2, u64::from(NEXT | WRITE))),
            "flags"
        );
        assert!(writes.contains(&(at + 14, 2, 2)), "next");
    }

    #[test]
    fn nothing_is_completed_until_the_device_says_so() {
        let _alone = testing::exclusive();
        let mut queue = queue();
        assert_eq!(queue.completed(), None, "a fresh queue owes nothing");

        // The device publishes: entry zero names descriptor 3, then the index.
        testing::offer(0x60 + 4, &3u32.to_le_bytes());
        testing::offer(0x60 + 2, &1u16.to_le_bytes());

        assert_eq!(queue.completed(), Some(3), "the descriptor it finished");
        assert_eq!(queue.completed(), None, "and only once");
    }

    #[test]
    fn the_available_index_wraps_without_leaving_the_ring() {
        // A queue of four, five requests. The fifth must land in slot zero
        // rather than five entries in, which would be past the ring and into
        // whatever the driver put next.
        let _alone = testing::exclusive();
        let mut queue = queue();
        for head in 0..5u16 {
            queue.publish(head);
        }

        let slots: alloc::vec::Vec<usize> = (0..testing::accesses())
            .map(testing::access)
            .filter(|(write, _, at, _)| *write && *at >= 0x40 + 4 && *at < 0x40 + 4 + 8)
            .map(|(_, _, at, _)| at - (0x40 + 4))
            .collect();
        assert_eq!(slots, [0, 2, 4, 6, 0], "four slots, then back to the first");
    }
}
