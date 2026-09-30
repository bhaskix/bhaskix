// SPDX-License-Identifier: Apache-2.0
//! The connection table: slots, generations, birth order, and armed rings.
//!
//! [RFC 0086](../../../docs/rfc/0086-the-motivating-workload.md) step 2.
//! **Arithmetic over arrays, holding nothing but what it is given** — no ring
//! is mapped here, no segment sent — so every property the service leans on is
//! a host test rather than something only a boot can show.
//!
//! # Why it exists
//!
//! `bin/tcpd` held exactly two connections, one outbound and one accepted, in
//! slots fixed by name. Sixteen clients at once need a table, and a table
//! reuses slots constantly, which exposes what two fixed slots could hide:
//!
//! - **A slot reused must not answer to its predecessor's capability.** Every
//!   handle was minted with generation 1, so a capability kept from an earlier
//!   connection carried the same badge as the next connection in its slot.
//!   Here each slot's generation moves on when it is emptied, and a handle is
//!   only honoured if its generation is the slot's current one.
//! - **Accept takes the oldest.** A connection that finished its handshake
//!   first is handed to the program first; slot order would let a low slot
//!   starve a high one under load.
//! - **Rings are armed before they are needed.** A connection's rings are the
//!   program's memory (RFC 0022), and bytes arrive from the moment the peer's
//!   `ACK` is accepted — before anybody calls `ACCEPT` — so the program arms
//!   pairs in advance and a new connection takes the oldest armed one. With
//!   none armed, the `ACK` is dropped and the peer retransmits it; the cookie
//!   (RFC 0048) is still valid, so nothing is lost but time.
//! - **A step borrows its connection without ending it.** `bin/tcpd` takes a
//!   connection out of its slot for the length of one state-machine step and
//!   puts it back; [`Table::lend`] and [`Table::give_back`] do that without
//!   touching the generation or the birth, which is what makes a borrowed
//!   connection keep its handle and its place in the accept queue.

/// The largest generation a handle can carry: thirty-one bits, because the
/// badge's top bit says "listener" (`abi::tcp::handle`).
pub const GENERATION_MASK: u32 = 0x7fff_ffff;

/// A slot and the generation it was issued under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    /// The slot.
    pub index: u32,
    /// Its generation when the handle was issued; never zero.
    pub generation: u32,
}

/// Why a table refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Every slot is occupied.
    Full,
    /// The handle names a slot outside the table, an empty slot, or a slot
    /// whose occupant is not the one it was issued for.
    Stale,
}

/// The next generation after `generation`: wraps within the mask and skips
/// zero, so a handle built from a zeroed word never matches a live slot.
#[must_use]
pub const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1) & GENERATION_MASK;
    if next == 0 { 1 } else { next }
}

/// `N` slots of `T`, each with a generation and a birth number.
pub struct Table<T, const N: usize> {
    slots: [Option<T>; N],
    generations: [u32; N],
    births: [u64; N],
    born: u64,
}

impl<T, const N: usize> Default for Table<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Table<T, N> {
    /// An empty table; every slot starts at generation 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            generations: [1; N],
            births: [0; N],
            born: 0,
        }
    }

    /// Puts `value` in the lowest free slot.
    ///
    /// # Errors
    ///
    /// [`Refusal::Full`] when every slot is occupied; `value` is dropped.
    pub fn insert(&mut self, value: T) -> Result<Handle, Refusal> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Refusal::Full)?;
        self.slots[index] = Some(value);
        self.born += 1;
        self.births[index] = self.born;
        Ok(Handle {
            index: index as u32,
            generation: self.generations[index],
        })
    }

    /// Which slot `handle` names, if it still names its own occupant.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stale`] for a slot out of range, empty, or re-occupied
    /// since the handle was issued.
    pub fn resolve(&self, handle: Handle) -> Result<usize, Refusal> {
        let index = handle.index as usize;
        if index >= N || self.slots[index].is_none() || self.generations[index] != handle.generation
        {
            return Err(Refusal::Stale);
        }
        Ok(index)
    }

    /// The handle for the occupant of `index`, if there is one.
    #[must_use]
    pub fn handle_of(&self, index: usize) -> Option<Handle> {
        (index < N && self.slots[index].is_some()).then(|| Handle {
            index: index as u32,
            generation: self.generations[index],
        })
    }

    /// Takes the occupant of `index` out for the length of one step, leaving
    /// its generation and birth alone — see [`Table::give_back`].
    pub fn lend(&mut self, index: usize) -> Option<T> {
        self.slots.get_mut(index)?.take()
    }

    /// Puts back what [`Table::lend`] took. Refused, handing `value` back, if
    /// the slot was filled in the meantime — which would mean an `insert`
    /// reused a slot mid-step, and is a bug in the caller rather than a state.
    ///
    /// # Errors
    ///
    /// `Err(value)` when `index` is out of range or occupied.
    pub fn give_back(&mut self, index: usize, value: T) -> Result<(), T> {
        match self.slots.get_mut(index) {
            Some(slot @ None) => {
                *slot = Some(value);
                Ok(())
            }
            _ => Err(value),
        }
    }

    /// Empties `index` and moves its generation on, so every handle issued
    /// for what was there is stale from now on. Returns what was there.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        let taken = self.slots.get_mut(index)?.take();
        if taken.is_some() {
            self.generations[index] = next_generation(self.generations[index]);
            self.births[index] = 0;
        }
        taken
    }

    /// The occupant of `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref()
    }

    /// The occupant of `index`, mutably.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.slots.get_mut(index)?.as_mut()
    }

    /// The oldest occupant for which `wanted` holds — the one `ACCEPT` hands
    /// out next.
    pub fn oldest(&self, mut wanted: impl FnMut(&T) -> bool) -> Option<usize> {
        (0..N)
            .filter(|&index| self.slots[index].as_ref().is_some_and(&mut wanted))
            .min_by_key(|&index| self.births[index])
    }

    /// The first occupant, in slot order, for which `wanted` holds.
    pub fn find(&self, mut wanted: impl FnMut(&T) -> bool) -> Option<usize> {
        (0..N).find(|&index| self.slots[index].as_ref().is_some_and(&mut wanted))
    }

    /// Occupied slots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// Whether no slot is occupied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Slots, occupied or not.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }
}

/// Ring pairs a program has armed a listener with, oldest first.
///
/// `T` is whatever the service needs to find the pair again — in `bin/tcpd`,
/// the pair's own number, which the program was told when it armed it and is
/// told again when `ACCEPT` hands it the connection that took it.
pub struct Armed<T, const N: usize> {
    queue: [Option<T>; N],
    head: usize,
    count: usize,
}

impl<T, const N: usize> Default for Armed<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Armed<T, N> {
    /// No pair armed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: core::array::from_fn(|_| None),
            head: 0,
            count: 0,
        }
    }

    /// Arms one pair, behind every pair already waiting.
    ///
    /// # Errors
    ///
    /// [`Refusal::Full`] when `N` pairs are already waiting; `value` is
    /// dropped.
    pub fn arm(&mut self, value: T) -> Result<(), Refusal> {
        if self.count == N {
            return Err(Refusal::Full);
        }
        self.queue[(self.head + self.count) % N] = Some(value);
        self.count += 1;
        Ok(())
    }

    /// Takes the oldest armed pair.
    pub fn take(&mut self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        let taken = self.queue[self.head].take();
        self.head = (self.head + 1) % N;
        self.count -= 1;
        taken
    }

    /// Pairs waiting.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether none is waiting.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_fill_lowest_first_and_refuse_at_size() {
        let mut table: Table<u8, 3> = Table::new();
        assert_eq!(table.insert(10).map(|h| h.index), Ok(0));
        assert_eq!(table.insert(11).map(|h| h.index), Ok(1));
        assert_eq!(table.insert(12).map(|h| h.index), Ok(2));
        assert_eq!(table.insert(13), Err(Refusal::Full));
        assert_eq!(table.len(), 3);
        assert_eq!(table.capacity(), 3);
    }

    #[test]
    fn a_reused_slot_does_not_answer_to_its_predecessors_handle() {
        let mut table: Table<&str, 2> = Table::new();
        let first = table.insert("first").unwrap();
        assert_eq!(table.resolve(first), Ok(0));
        assert_eq!(table.remove(0), Some("first"));
        assert_eq!(
            table.resolve(first),
            Err(Refusal::Stale),
            "an empty slot is stale"
        );

        let second = table.insert("second").unwrap();
        assert_eq!(second.index, first.index, "the slot is reused");
        assert_ne!(
            second.generation, first.generation,
            "under a new generation"
        );
        assert_eq!(
            table.resolve(first),
            Err(Refusal::Stale),
            "the old handle names nothing"
        );
        assert_eq!(table.resolve(second), Ok(0));
    }

    #[test]
    fn a_handle_out_of_range_or_for_an_empty_slot_is_stale() {
        let table: Table<u8, 2> = Table::new();
        assert_eq!(
            table.resolve(Handle {
                index: 9,
                generation: 1
            }),
            Err(Refusal::Stale)
        );
        assert_eq!(
            table.resolve(Handle {
                index: 1,
                generation: 1
            }),
            Err(Refusal::Stale)
        );
    }

    #[test]
    fn generations_wrap_within_the_mask_and_never_reach_zero() {
        assert_eq!(next_generation(1), 2);
        assert_eq!(next_generation(GENERATION_MASK), 1);
        assert_eq!(
            next_generation(u32::MAX),
            1,
            "a stray high bit is masked off"
        );
        let mut generation = GENERATION_MASK - 2;
        for _ in 0..6 {
            generation = next_generation(generation);
            assert_ne!(generation, 0);
            assert_eq!(generation & !GENERATION_MASK, 0);
        }
    }

    #[test]
    fn accept_takes_the_oldest_not_the_lowest_slot() {
        let mut table: Table<(char, bool), 3> = Table::new();
        table.insert(('a', true)).unwrap(); // slot 0, born 1
        table.insert(('b', true)).unwrap(); // slot 1, born 2
        table.remove(0);
        table.insert(('c', true)).unwrap(); // slot 0 again, born 3
        // Slot 0 is lower, but 'b' in slot 1 is older.
        assert_eq!(table.oldest(|&(_, ready)| ready), Some(1));
        // Only what the predicate admits is considered.
        table.get_mut(1).unwrap().1 = false;
        assert_eq!(table.oldest(|&(_, ready)| ready), Some(0));
        assert_eq!(table.find(|&(name, _)| name == 'b'), Some(1));
    }

    #[test]
    fn armed_pairs_are_taken_oldest_first_and_refused_at_size() {
        let mut armed: Armed<&str, 2> = Armed::new();
        assert_eq!(armed.arm("p0"), Ok(()));
        assert_eq!(armed.arm("p1"), Ok(()));
        assert_eq!(armed.arm("p2"), Err(Refusal::Full), "at size, refused");
        assert_eq!(armed.take(), Some("p0"));
        assert_eq!(armed.arm("p2"), Ok(()), "room again once one is taken");
        assert_eq!(armed.take(), Some("p1"));
        assert_eq!(armed.take(), Some("p2"), "the wrap keeps the order");
        assert_eq!(armed.take(), None);
        assert!(armed.is_empty());
    }

    #[test]
    fn a_lent_connection_keeps_its_handle_and_its_place_in_the_accept_queue() {
        let mut table: Table<u8, 3> = Table::new();
        let older = table.insert(1).unwrap();
        let younger = table.insert(2).unwrap();
        let lent = table.lend(older.index as usize).unwrap();
        assert!(
            table.resolve(older).is_err(),
            "while lent, the slot is empty"
        );
        assert_eq!(table.give_back(older.index as usize, lent), Ok(()));
        assert_eq!(
            table.resolve(older),
            Ok(0),
            "same generation after the step"
        );
        assert_eq!(table.oldest(|_| true), Some(0), "and still the oldest");
        assert_eq!(table.resolve(younger), Ok(1));
        // Giving back into an occupied slot is refused, value returned.
        assert_eq!(table.give_back(1, 9), Err(9));
    }
}
