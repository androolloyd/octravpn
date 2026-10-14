// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native composable commitment openings and their exact admission decisions.
use super::hidden::{acc_size, digest_eq, hasher, Digest};
use crate::field::Fp;
use sha2::Digest as _;
use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    None,
    Cell,
    Expression,
    Unknown(u8),
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Operation {
    #[default]
    None,
    Source,
    Add,
    Subtract,
    Scale,
    AddConstant,
    Product,
    Reset,
    Unknown(u8),
}
impl Operation {
    fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Source => 1,
            Self::Add => 2,
            Self::Subtract => 3,
            Self::Scale => 4,
            Self::AddConstant => 5,
            Self::Product => 6,
            Self::Reset => 7,
            Self::Unknown(tag) => tag,
        }
    }
    pub fn closed(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Subtract | Self::Scale | Self::AddConstant | Self::Product
        )
    }
}
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Opening {
    pub value: Fp,
    pub blind: Digest,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cell {
    pub kind: Kind,
    pub operation: Operation,
    pub tag: Digest,
    pub digest: Digest,
    pub bound: bool,
    pub hiding: bool,
    pub native: bool,
    pub basis_closed: bool,
    pub prebound: bool,
    pub composable: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decision {
    pub admitted: bool,
    pub digest: bool,
    pub bound: bool,
    pub hiding: bool,
    pub native: bool,
    pub basis_closed: bool,
    pub prebound: bool,
    pub composable: bool,
    pub rejects_unbound: bool,
    pub rejects_basis_open: bool,
    pub rejects_posthoc: bool,
    pub rejects_nonclosed: bool,
}
pub fn cell_digest(tag: &Digest, opening: &Opening) -> Digest {
    let mut h = hasher(b"pvac.native.com.cell");
    h.update(tag);
    h.update(opening.value.to_bytes_le());
    h.update(opening.blind);
    h.finalize().into()
}
fn expression_digest(
    domain: &[u8],
    operation: Operation,
    left: &Digest,
    right: &Digest,
    scalar: Fp,
) -> Digest {
    let mut h = hasher(domain);
    acc_size(&mut h, operation.tag() as usize);
    h.update(left);
    h.update(right);
    h.update(scalar.to_bytes_le());
    h.finalize().into()
}
impl Opening {
    pub fn new(value: Fp, blind: Digest) -> Self {
        Self { value, blind }
    }
    pub fn combine(&self, operation: Operation, right: &Self, scalar: Fp) -> Option<Self> {
        let (value, right_blind, scalar) = match operation {
            Operation::Add => (self.value + right.value, &right.blind, Fp::ZERO),
            Operation::Subtract => (self.value - right.value, &right.blind, Fp::ZERO),
            Operation::Scale => (self.value * scalar, &[0; 32], scalar),
            Operation::AddConstant => (self.value + scalar, &[0; 32], scalar),
            Operation::Product => (self.value * right.value, &right.blind, Fp::ZERO),
            _ => return None,
        };
        Some(Self {
            value,
            blind: expression_digest(
                b"pvac.native.com.blind",
                operation,
                &self.blind,
                right_blind,
                scalar,
            ),
        })
    }
}
impl Cell {
    pub fn new(tag: Digest, opening: &Opening, prebound: bool) -> Self {
        Self {
            kind: Kind::Cell,
            operation: Operation::Source,
            tag,
            digest: cell_digest(&tag, opening),
            bound: true,
            hiding: true,
            native: true,
            basis_closed: true,
            prebound,
            composable: false,
        }
    }
    pub fn expression(
        operation: Operation,
        left: &Self,
        right: &Self,
        scalar: Fp,
        opening: Option<&Opening>,
    ) -> Self {
        let tag = expression_digest(
            b"pvac.native.com.expr",
            operation,
            &left.digest,
            &right.digest,
            scalar,
        );
        Self {
            kind: Kind::Expression,
            operation,
            tag,
            digest: opening.map_or(tag, |value| cell_digest(&tag, value)),
            bound: left.bound && right.bound,
            hiding: left.hiding && right.hiding,
            native: left.native && right.native,
            basis_closed: left.basis_closed && right.basis_closed,
            prebound: left.prebound && right.prebound,
            composable: operation.closed(),
        }
    }
    fn decision(&self) -> Decision {
        Decision {
            bound: self.bound,
            hiding: self.hiding,
            native: self.native,
            basis_closed: self.basis_closed,
            prebound: self.prebound,
            composable: self.composable,
            rejects_unbound: !self.bound || !self.hiding || !self.native,
            rejects_basis_open: !self.basis_closed,
            rejects_posthoc: !self.prebound,
            ..Decision::default()
        }
    }
    pub fn verify_opening(&self, opening: &Opening) -> Decision {
        let mut decision = self.decision();
        decision.digest =
            self.kind == Kind::Cell && digest_eq(&self.digest, &cell_digest(&self.tag, opening));
        decision.admitted = decision.digest
            && decision.bound
            && decision.hiding
            && decision.native
            && decision.basis_closed
            && decision.prebound;
        decision
    }
    /// A bare claim is always refused in the pinned native implementation.
    pub fn claim(&self) -> Decision {
        Decision {
            digest: self.kind != Kind::None,
            rejects_nonclosed: self.kind == Kind::Expression && !self.composable,
            ..self.decision()
        }
    }
    pub fn verify_expression(
        &self,
        operation: Operation,
        left: (&Self, &Opening),
        right: (&Self, &Opening),
        scalar: Fp,
        opening: &Opening,
    ) -> Decision {
        let Some(expected) = left.1.combine(operation, right.1, scalar) else {
            return Decision {
                rejects_nonclosed: true,
                ..Decision::default()
            };
        };
        let left_decision = left.0.verify_opening(left.1);
        let right_decision = if matches!(operation, Operation::Scale | Operation::AddConstant) {
            left_decision
        } else {
            right.0.verify_opening(right.1)
        };
        let expected_cell = Self::expression(operation, left.0, right.0, scalar, Some(&expected));
        let mut decision = Decision {
            digest: left_decision.admitted
                && right_decision.admitted
                && digest_eq(&self.tag, &expected_cell.tag)
                && digest_eq(&self.digest, &expected_cell.digest)
                && digest_eq(&self.digest, &cell_digest(&self.tag, opening))
                && digest_eq(&opening.blind, &expected.blind)
                && opening.value == expected.value,
            bound: self.bound && left_decision.bound && right_decision.bound,
            hiding: self.hiding && left_decision.hiding && right_decision.hiding,
            native: self.native && left_decision.native && right_decision.native,
            basis_closed: self.basis_closed
                && left_decision.basis_closed
                && right_decision.basis_closed,
            prebound: self.prebound && left_decision.prebound && right_decision.prebound,
            composable: self.composable,
            ..Decision::default()
        };
        decision.rejects_unbound = !decision.bound || !decision.hiding || !decision.native;
        decision.rejects_basis_open = !decision.basis_closed;
        decision.rejects_posthoc = !decision.prebound;
        decision.rejects_nonclosed = !decision.composable;
        decision.admitted = decision.digest
            && decision.bound
            && decision.hiding
            && decision.native
            && decision.basis_closed
            && decision.prebound
            && decision.composable;
        decision
    }
}
