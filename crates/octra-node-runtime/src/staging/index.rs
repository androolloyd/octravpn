use super::Entry;
use std::{cmp::Ordering, sync::Arc};

pub(super) fn rate(a: &Entry, b: &Entry) -> Ordering {
    (&b.tx.ou * &a.cost).cmp(&(&a.tx.ou * &b.cost))
}
fn float_compare(a: f64, b: f64) -> Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.partial_cmp(&b).expect("finite or infinite values"),
    }
}
macro_rules! ordered_entry {
    ($name:ident, $compare:expr) => {
        #[derive(Clone, Debug)]
        pub(super) struct $name(pub Arc<Entry>);
        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                ($compare)(&self.0, &other.0)
            }
        }
        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.cmp(other) == Ordering::Equal
            }
        }
        impl Eq for $name {}
    };
}
ordered_entry!(Eviction, |a: &Entry, b: &Entry| rate(b, a)
    .then_with(|| a.hash.cmp(&b.hash))
    .then_with(|| a.key.cmp(&b.key)));
ordered_entry!(Selection, |a: &Entry, b: &Entry| rate(a, b)
    .then_with(|| a.hash.cmp(&b.hash))
    .then_with(|| a.tx.from.cmp(&b.tx.from)));
ordered_entry!(Recent, |a: &Entry, b: &Entry| float_compare(
    b.tx.timestamp,
    a.tx.timestamp
)
.then_with(|| float_compare(b.added_at, a.added_at))
.then_with(|| a.hash.cmp(&b.hash)));
