//! First-declaration symbol indices and staged compiler work bounds.
use super::{
    ast::{Contract, Expr, Name, Nodes, Type},
    limits,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn first<T>(entries: &[T], key: impl Fn(&T) -> &Name) -> BTreeMap<Name, usize> {
    let mut index = BTreeMap::new();
    for (position, item) in entries.iter().enumerate() {
        index.entry(key(item).clone()).or_insert(position);
    }
    index
}
pub(crate) fn check(contract: &Contract, metered: bool) -> Result<(), Vec<u8>> {
    if metered && contract.functions.len() + contract.forms.len() > limits::FUNCTIONS {
        Err(b"Program function limit exceeded".to_vec())
    } else if metered && contract.consts.len() > crate::octb::MAX_CONSTANTS {
        Err(b"Program constant limit exceeded".to_vec())
    } else {
        Ok(())
    }
}

pub(crate) struct Index {
    pub consts: BTreeMap<Name, usize>,
    pub functions: BTreeMap<Name, usize>,
    pub structs: BTreeMap<Name, usize>,
    pub enums: BTreeMap<Name, usize>,
    pub state: BTreeMap<Name, usize>,
    pub events: BTreeMap<Name, usize>,
    pub errors: BTreeMap<Name, usize>,
    pub interfaces: BTreeMap<Name, usize>,
    aliases: BTreeMap<(u8, Name), Name>,
}
impl Index {
    pub(crate) fn new(contract: &Contract) -> Self {
        Self {
            consts: first(&contract.consts, |item| &item.name),
            functions: first(&contract.functions, |item| &item.name),
            structs: first(&contract.structs, |item| &item.name),
            enums: first(&contract.enums, |item| &item.name),
            state: first(&contract.state, |item| &item.name),
            events: first(&contract.events, |item| &item.name),
            errors: first(&contract.errors, |item| &item.name),
            interfaces: first(&contract.interfaces, |item| &item.name),
            aliases: BTreeMap::new(),
        }
    }
}

impl Index {
    pub(crate) fn resolve(
        &mut self,
        contract: &Contract,
        nodes: &Nodes,
        mode: u8,
        name: &[u8],
    ) -> Result<Name, Name> {
        let mut name = name.to_vec();
        let mut path = BTreeSet::new();
        loop {
            if let Some(target) = self.aliases.get(&(mode, name.clone())) {
                name.clone_from(target);
                break;
            }
            if path.contains(&name) {
                return Err(name);
            }
            let special = match name.as_slice() {
                b"epoch" => mode & 1 != 0,
                b"epoch_time" => mode & 2 != 0,
                b"value" => mode & 4 != 0,
                _ => false,
            };
            let next = if special {
                None
            } else {
                self.consts.get(&name).and_then(|&index| {
                    let item = &contract.consts[index];
                    if mode & 8 != 0 && nodes.typ(item.typ) != &Type::Void {
                        return None;
                    }
                    match nodes.expression(item.value) {
                        Expr::Var(next) => Some(next.clone()),
                        _ => None,
                    }
                })
            };
            let Some(next) = next else {
                break;
            };
            path.insert(name);
            name = next;
        }
        for alias in path {
            self.aliases.insert((mode, alias), name.clone());
        }
        Ok(name)
    }
}
