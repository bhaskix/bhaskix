// SPDX-License-Identifier: Apache-2.0
//! Network interfaces — ports, bonds and VLANs, and the rules between them.
//!
//! [RFC 0074](../../docs/rfc/0074-what-a-network-interface-is.md). Before this
//! the system had a network stack and no notion of an interface: one driver
//! drove *the* device, one service read *the* ring, and an address belonged to
//! the machine. There was no way to say "this port", let alone "these two
//! bonded" or "VLAN 17 on that bond".
//!
//! An interface is a named thing that carries frames, has an address and an
//! MTU, and may hold IP addresses. Three kinds, which compose in one direction:
//!
//! ```text
//!   vlan17  ──parent──▶  bond0  ──members──▶  port0, port1
//! ```
//!
//! # What is deliberately refused
//!
//! **Stacking without a rule.** A VLAN of a VLAN, a bond of bonds, a port in
//! two bonds, two VLANs with the same tag on one parent — each is refused at
//! the point of composition rather than left to behave oddly later. The two
//! useful shapes are `vlan → port` and `vlan → bond → ports`, and a
//! configuration that cannot be drawn is one nobody can reason about.
//!
//! # No allocator
//!
//! A fixed table. Ring 3 has no global allocator, and a table that cannot grow
//! is one that cannot fail to grow at an awkward moment; [`Error::Exhausted`]
//! is an honest refusal where a silent reallocation would be a surprise.

use crate::addr::MacAddr;

/// How many interfaces exist at once.
///
/// Four physical ports, a bond over them, and a VLAN or two is the shape this
/// is built for; sixteen leaves room without making the table large.
pub const MAX: usize = 16;

/// An interface's position in the table, which is also its stable identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Index(pub u8);

/// The largest frame an interface carries by default.
pub const DEFAULT_MTU: u16 = 1500;

/// What an interface is made of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One device port, as a driver presents it.
    Physical {
        /// Which port of that driver, for a card with several.
        port: u16,
    },
    /// Several physical interfaces under one, with a mode.
    Bond {
        /// How a member is chosen.
        mode: BondMode,
    },
    /// A tag on a parent, which may be physical or a bond.
    Vlan {
        /// The interface the tagged frames arrive on.
        parent: Index,
        /// The 802.1Q identifier.
        id: u16,
    },
}

/// How a bond picks the member a frame leaves by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondMode {
    /// One member carries everything; another takes over when it fails.
    ///
    /// **Needs no protocol and no cooperation from the switch**, which makes it
    /// the mode to build first: it works against a switch that is not
    /// configured for aggregation at all, and it is testable by downing a link.
    ActiveBackup,
    /// Members are aggregated by 802.3ad, and one is usable only while its
    /// LACP machine says so.
    Lacp,
}

/// Why an interface operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The table is full.
    Exhausted,
    /// The index names no interface.
    NoSuchInterface(Index),
    /// A bond's member must be a physical port.
    MemberNotPhysical(Index),
    /// A VLAN's parent must be physical or a bond, never another VLAN.
    ParentIsVlan(Index),
    /// That port already belongs to a bond.
    AlreadyBonded(Index),
    /// A VLAN interface cannot be a bond member.
    MemberIsVlan(Index),
    /// The parent already carries a VLAN with that identifier.
    DuplicateVlan(u16),
    /// A bond cannot hold more members.
    BondFull,
    /// The identifier is outside 802.1Q's twelve bits, or is zero.
    BadVlanId(u16),
}

/// How many members a bond holds.
pub const MAX_MEMBERS: usize = 8;

/// One interface.
#[derive(Clone, Copy, Debug)]
pub struct Interface {
    /// What it is made of.
    pub kind: Kind,
    /// Its hardware address. A bond's is its first member's, by convention;
    /// a VLAN's is its parent's.
    pub mac: MacAddr,
    /// The largest frame it carries.
    pub mtu: u16,
    /// Whether the link under it is usable.
    ///
    /// For a physical interface this is what the driver reports. For a bond and
    /// a VLAN it is derived, and [`Interfaces::link_of`] is what derives it —
    /// this field is only meaningful for a physical one.
    pub link_up: bool,
    /// A bond's members, in the order they were added.
    pub members: [Option<Index>; MAX_MEMBERS],
    /// Which member a bond is currently sending by.
    pub active: Option<Index>,
}

impl Interface {
    /// How many members a bond has.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.iter().flatten().count()
    }

    /// The members, in order.
    pub fn members(&self) -> impl Iterator<Item = Index> + '_ {
        self.members.iter().flatten().copied()
    }
}

/// Every interface this system has.
#[derive(Clone, Copy, Debug)]
pub struct Interfaces {
    table: [Option<Interface>; MAX],
}

impl Default for Interfaces {
    fn default() -> Self {
        Self::new()
    }
}

impl Interfaces {
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { table: [None; MAX] }
    }

    /// The interface at `index`, if there is one.
    #[must_use]
    pub fn get(&self, index: Index) -> Option<&Interface> {
        self.table.get(index.0 as usize)?.as_ref()
    }

    /// How many interfaces exist.
    #[must_use]
    pub fn count(&self) -> usize {
        self.table.iter().flatten().count()
    }

    /// Every interface, with its index.
    pub fn iter(&self) -> impl Iterator<Item = (Index, &Interface)> + '_ {
        self.table
            .iter()
            .enumerate()
            .filter_map(|(at, slot)| slot.as_ref().map(|face| (Index(at as u8), face)))
    }

    fn insert(&mut self, face: Interface) -> Result<Index, Error> {
        let at = self
            .table
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Exhausted)?;
        self.table[at] = Some(face);
        Ok(Index(at as u8))
    }

    fn kind_of(&self, index: Index) -> Result<Kind, Error> {
        self.get(index)
            .map(|face| face.kind)
            .ok_or(Error::NoSuchInterface(index))
    }

    /// Adds a physical port, as a driver found it.
    ///
    /// # Errors
    ///
    /// [`Error::Exhausted`] when the table is full.
    pub fn add_physical(&mut self, port: u16, mac: MacAddr, mtu: u16) -> Result<Index, Error> {
        self.insert(Interface {
            kind: Kind::Physical { port },
            mac,
            mtu,
            link_up: false,
            members: [None; MAX_MEMBERS],
            active: None,
        })
    }

    /// Adds an empty bond.
    ///
    /// # Errors
    ///
    /// [`Error::Exhausted`] when the table is full.
    pub fn add_bond(&mut self, mode: BondMode) -> Result<Index, Error> {
        self.insert(Interface {
            kind: Kind::Bond { mode },
            // Takes its first member's address when one is added.
            mac: MacAddr([0; 6]),
            mtu: DEFAULT_MTU,
            link_up: false,
            members: [None; MAX_MEMBERS],
            active: None,
        })
    }

    /// Puts a physical interface into a bond.
    ///
    /// **The bond takes its first member's address**, which is the convention
    /// and is written down here rather than left to whichever member answers
    /// first. Its MTU becomes the smallest of its members', because a frame
    /// that fits the bond must fit whichever member carries it.
    ///
    /// # Errors
    ///
    /// [`Error::MemberNotPhysical`] for a bond, [`Error::MemberIsVlan`] for a
    /// VLAN, [`Error::AlreadyBonded`] if the port is in another bond, and
    /// [`Error::BondFull`].
    pub fn enslave(&mut self, bond: Index, member: Index) -> Result<(), Error> {
        match self.kind_of(bond)? {
            Kind::Bond { .. } => {}
            _ => return Err(Error::MemberNotPhysical(bond)),
        }
        match self.kind_of(member)? {
            Kind::Physical { .. } => {}
            Kind::Vlan { .. } => return Err(Error::MemberIsVlan(member)),
            Kind::Bond { .. } => return Err(Error::MemberNotPhysical(member)),
        }
        // A port belongs to at most one bond, so that a frame has one path out
        // and a failover has one place to move it to.
        if self.bond_of(member).is_some() {
            return Err(Error::AlreadyBonded(member));
        }

        let (mac, mtu) = {
            let face = self.get(member).ok_or(Error::NoSuchInterface(member))?;
            (face.mac, face.mtu)
        };
        let slot = {
            let bonded = self
                .table
                .get_mut(bond.0 as usize)
                .and_then(Option::as_mut)
                .ok_or(Error::NoSuchInterface(bond))?;
            let first = bonded.member_count() == 0;
            let slot = bonded
                .members
                .iter()
                .position(Option::is_none)
                .ok_or(Error::BondFull)?;
            bonded.members[slot] = Some(member);
            if first {
                bonded.mac = mac;
                bonded.mtu = mtu;
            } else {
                bonded.mtu = bonded.mtu.min(mtu);
            }
            slot
        };
        let _ = slot;
        self.reselect(bond);
        Ok(())
    }

    /// Which bond a port belongs to, if any.
    #[must_use]
    pub fn bond_of(&self, member: Index) -> Option<Index> {
        self.iter()
            .find(|(_, face)| {
                matches!(face.kind, Kind::Bond { .. }) && face.members().any(|m| m == member)
            })
            .map(|(index, _)| index)
    }

    /// Adds a VLAN on a parent.
    ///
    /// # Errors
    ///
    /// [`Error::ParentIsVlan`] for stacking, [`Error::DuplicateVlan`] when the
    /// parent already carries that identifier, and [`Error::BadVlanId`] for one
    /// outside 802.1Q's range.
    pub fn add_vlan(&mut self, parent: Index, id: u16) -> Result<Index, Error> {
        if id == 0 || id > 0xfff {
            return Err(Error::BadVlanId(id));
        }
        match self.kind_of(parent)? {
            Kind::Vlan { .. } => return Err(Error::ParentIsVlan(parent)),
            Kind::Physical { .. } | Kind::Bond { .. } => {}
        }
        if self.vlan_on(parent, id).is_some() {
            return Err(Error::DuplicateVlan(id));
        }
        let (mac, mtu) = {
            let face = self.get(parent).ok_or(Error::NoSuchInterface(parent))?;
            (face.mac, face.mtu)
        };
        self.insert(Interface {
            kind: Kind::Vlan { parent, id },
            mac,
            // The tag costs four bytes of what the parent will carry.
            mtu: mtu.saturating_sub(4),
            link_up: false,
            members: [None; MAX_MEMBERS],
            active: None,
        })
    }

    /// The VLAN interface for `id` on `parent`, if one exists.
    #[must_use]
    pub fn vlan_on(&self, parent: Index, id: u16) -> Option<Index> {
        self.iter()
            .find(|(_, face)| face.kind == Kind::Vlan { parent, id })
            .map(|(index, _)| index)
    }

    /// Tells the table a physical link came up or went down.
    ///
    /// Returns whether any bond changed its active member as a result, which
    /// is what a caller reports: a failover nobody is told about is one nobody
    /// can trust happened.
    pub fn set_link(&mut self, index: Index, up: bool) -> bool {
        let Some(face) = self
            .table
            .get_mut(index.0 as usize)
            .and_then(Option::as_mut)
        else {
            return false;
        };
        if !matches!(face.kind, Kind::Physical { .. }) {
            return false;
        }
        face.link_up = up;
        match self.bond_of(index) {
            Some(bond) => {
                let before = self.get(bond).and_then(|b| b.active);
                self.reselect(bond);
                before != self.get(bond).and_then(|b| b.active)
            }
            None => false,
        }
    }

    /// Chooses a bond's active member.
    ///
    /// **Sticky**: a member that is up and already active stays active. Moving
    /// traffic between links because a *different* link came back is churn
    /// nobody asked for, and on a bond it means reordering frames for no gain.
    fn reselect(&mut self, bond: Index) {
        let choice = {
            let Some(face) = self.get(bond) else {
                return;
            };
            let still_good = face
                .active
                .filter(|active| self.get(*active).is_some_and(|m| m.link_up));
            still_good.or_else(|| {
                face.members()
                    .find(|m| self.get(*m).is_some_and(|face| face.link_up))
            })
        };
        if let Some(face) = self.table.get_mut(bond.0 as usize).and_then(Option::as_mut) {
            face.active = choice;
        }
    }

    /// Whether an interface can carry traffic.
    ///
    /// Derived rather than stored for everything but a physical port: a bond is
    /// up while any member is, and a VLAN is up while its parent is.
    #[must_use]
    pub fn link_of(&self, index: Index) -> bool {
        let Some(face) = self.get(index) else {
            return false;
        };
        match face.kind {
            Kind::Physical { .. } => face.link_up,
            Kind::Bond { .. } => face.active.is_some(),
            Kind::Vlan { parent, .. } => self.link_of(parent),
        }
    }

    /// The physical port a frame leaving `index` goes out of.
    ///
    /// Follows a VLAN to its parent and a bond to its active member, so a
    /// caller with `vlan17` gets the port to hand the frame to.
    #[must_use]
    pub fn egress_port(&self, index: Index) -> Option<Index> {
        match self.get(index)?.kind {
            Kind::Physical { .. } => Some(index),
            Kind::Bond { .. } => self.get(index)?.active,
            Kind::Vlan { parent, .. } => self.egress_port(parent),
        }
    }

    /// The VLAN tag a frame leaving `index` carries, if any.
    #[must_use]
    pub fn egress_tag(&self, index: Index) -> Option<u16> {
        match self.get(index)?.kind {
            Kind::Vlan { id, .. } => Some(id),
            _ => None,
        }
    }

    /// Which interface a frame arriving on `port` with `tag` belongs to.
    ///
    /// **The receive half of the model.** A frame arrives on a physical port
    /// and this says whose it is: the VLAN interface if it carries that VLAN's
    /// tag, the bond if the port is bonded and the frame is untagged, or the
    /// port itself. `None` means no interface claims it, which is the answer
    /// for a tag nobody is configured for — the segmentation boundary, decided
    /// here rather than by a parser.
    #[must_use]
    pub fn classify(&self, port: Index, tag: Option<u16>) -> Option<Index> {
        // A tagged frame belongs to a VLAN on the port, or on the bond the port
        // is in, and to nothing else.
        let carrier = self.bond_of(port).unwrap_or(port);
        match tag {
            Some(id) => self.vlan_on(carrier, id).or_else(|| self.vlan_on(port, id)),
            None => Some(carrier),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MacAddr = MacAddr([0x08, 0x94, 0xef, 0x00, 0x00, 0x01]);
    const B: MacAddr = MacAddr([0x08, 0x94, 0xef, 0x00, 0x00, 0x02]);

    /// Two ports, a bond over them and a VLAN on the bond — the shape the
    /// SR550 is actually cabled in.
    fn bonded() -> (Interfaces, Index, Index, Index, Index) {
        let mut faces = Interfaces::new();
        let port0 = faces.add_physical(0, A, 1500).expect("room");
        let port1 = faces.add_physical(1, B, 1500).expect("room");
        let bond = faces.add_bond(BondMode::ActiveBackup).expect("room");
        faces.enslave(bond, port0).expect("port0 joins");
        faces.enslave(bond, port1).expect("port1 joins");
        let vlan = faces.add_vlan(bond, 17).expect("vlan 17");
        (faces, port0, port1, bond, vlan)
    }

    /// The composition rules, each refused at the point of composition.
    #[test]
    fn a_configuration_that_cannot_be_drawn_is_refused() {
        let (mut faces, port0, _port1, bond, vlan) = bonded();

        // A VLAN of a VLAN.
        assert_eq!(faces.add_vlan(vlan, 18), Err(Error::ParentIsVlan(vlan)));
        // A second VLAN with the same tag on the same parent.
        assert_eq!(faces.add_vlan(bond, 17), Err(Error::DuplicateVlan(17)));
        // A different tag on the same parent is fine.
        assert!(faces.add_vlan(bond, 18).is_ok());
        // A port already in a bond.
        let other = faces.add_bond(BondMode::ActiveBackup).expect("room");
        assert_eq!(
            faces.enslave(other, port0),
            Err(Error::AlreadyBonded(port0))
        );
        // A bond inside a bond, and a VLAN as a member.
        assert_eq!(
            faces.enslave(other, bond),
            Err(Error::MemberNotPhysical(bond))
        );
        assert_eq!(faces.enslave(other, vlan), Err(Error::MemberIsVlan(vlan)));
        // Identifiers outside the twelve-bit field.
        assert_eq!(faces.add_vlan(port0, 0), Err(Error::BadVlanId(0)));
        assert_eq!(faces.add_vlan(port0, 4096), Err(Error::BadVlanId(4096)));
    }

    /// A bond takes its first member's address, and the smallest MTU.
    #[test]
    fn a_bond_inherits_from_its_members_and_a_vlan_pays_for_its_tag() {
        let mut faces = Interfaces::new();
        let port0 = faces.add_physical(0, A, 9000).expect("room");
        let port1 = faces.add_physical(1, B, 1500).expect("room");
        let bond = faces.add_bond(BondMode::ActiveBackup).expect("room");

        faces.enslave(bond, port0).expect("first");
        assert_eq!(faces.get(bond).expect("bond").mac, A, "the first member's");
        assert_eq!(faces.get(bond).expect("bond").mtu, 9000);

        faces.enslave(bond, port1).expect("second");
        assert_eq!(faces.get(bond).expect("bond").mac, A, "not the second's");
        assert_eq!(
            faces.get(bond).expect("bond").mtu,
            1500,
            "a frame must fit whichever member carries it"
        );

        let vlan = faces.add_vlan(bond, 17).expect("vlan");
        assert_eq!(
            faces.get(vlan).expect("vlan").mtu,
            1496,
            "the tag costs four bytes"
        );
        assert_eq!(faces.get(vlan).expect("vlan").mac, A, "the parent's");
    }

    /// Active-backup: one member carries, another takes over, and it is sticky.
    #[test]
    fn a_bond_fails_over_and_does_not_flap_back() {
        let (mut faces, port0, port1, bond, vlan) = bonded();

        // Nothing is up, so nothing is active and nothing above it is up.
        assert!(!faces.link_of(bond));
        assert!(!faces.link_of(vlan));
        assert_eq!(faces.egress_port(vlan), None);

        // The first member comes up and takes the traffic.
        assert!(faces.set_link(port0, true), "the active member changed");
        assert_eq!(faces.get(bond).expect("bond").active, Some(port0));
        assert!(faces.link_of(bond));
        assert!(faces.link_of(vlan), "a VLAN is up while its parent is");
        assert_eq!(faces.egress_port(vlan), Some(port0));

        // The second coming up changes nothing: churn nobody asked for.
        assert!(!faces.set_link(port1, true), "it moved for no reason");
        assert_eq!(faces.get(bond).expect("bond").active, Some(port0));

        // The active one fails and the other takes over.
        assert!(faces.set_link(port0, false), "failover");
        assert_eq!(faces.get(bond).expect("bond").active, Some(port1));
        assert!(
            faces.link_of(vlan),
            "the VLAN stayed up across the failover"
        );
        assert_eq!(faces.egress_port(vlan), Some(port1));

        // The first coming back does not steal it back.
        assert!(!faces.set_link(port0, true), "it flapped back");
        assert_eq!(faces.get(bond).expect("bond").active, Some(port1));

        // Both down: the bond is down and so is everything on it.
        faces.set_link(port0, false);
        assert!(faces.set_link(port1, false), "the last member left");
        assert_eq!(faces.get(bond).expect("bond").active, None);
        assert!(!faces.link_of(bond));
        assert!(!faces.link_of(vlan));
    }

    /// Which interface an arriving frame belongs to.
    #[test]
    fn a_frame_is_classified_to_the_interface_that_was_configured_for_it() {
        let (mut faces, port0, port1, bond, vlan) = bonded();
        faces.set_link(port0, true);

        // Tagged 17 on either member belongs to the VLAN over the bond.
        assert_eq!(faces.classify(port0, Some(17)), Some(vlan));
        assert_eq!(faces.classify(port1, Some(17)), Some(vlan));
        // Untagged belongs to the bond, not to the port it landed on.
        assert_eq!(faces.classify(port0, None), Some(bond));
        // A tag nobody is configured for belongs to nothing.
        assert_eq!(faces.classify(port0, Some(99)), None);

        // An unbonded port keeps its own frames.
        let mut plain = Interfaces::new();
        let lone = plain.add_physical(0, A, 1500).expect("room");
        let tagged = plain.add_vlan(lone, 5).expect("vlan");
        assert_eq!(plain.classify(lone, None), Some(lone));
        assert_eq!(plain.classify(lone, Some(5)), Some(tagged));
        assert_eq!(plain.classify(lone, Some(6)), None);
    }

    /// Egress follows the composition down to a port and names the tag.
    #[test]
    fn a_frame_leaves_by_the_active_member_carrying_its_tag() {
        let (mut faces, port0, _port1, bond, vlan) = bonded();
        faces.set_link(port0, true);

        assert_eq!(faces.egress_port(vlan), Some(port0));
        assert_eq!(faces.egress_tag(vlan), Some(17));
        assert_eq!(faces.egress_port(bond), Some(port0));
        assert_eq!(faces.egress_tag(bond), None, "a bond adds no tag");
        assert_eq!(faces.egress_port(port0), Some(port0));
    }

    /// The table refuses rather than growing.
    #[test]
    fn a_full_table_is_an_honest_refusal() {
        let mut faces = Interfaces::new();
        for port in 0..MAX {
            assert!(faces.add_physical(port as u16, A, 1500).is_ok());
        }
        assert_eq!(faces.count(), MAX);
        assert_eq!(faces.add_physical(99, A, 1500), Err(Error::Exhausted));
        assert_eq!(
            faces.add_bond(BondMode::ActiveBackup),
            Err(Error::Exhausted)
        );
    }
}
