// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Flat immutable lists shared by replay values and register-layout vectors.
//! Cons/unhead take constant time; destruction does not recurse.
use std::sync::Arc;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListId(usize);
#[derive(Clone, Debug)]
enum Node<T> {
    Array(Arc<[T]>, usize),
    Cons(T, ListId),
}
#[derive(Clone, Debug)]
pub(crate) struct Lists<T> {
    nodes: Vec<(Node<T>, usize)>,
}
impl<T> Default for Lists<T> {
    fn default() -> Self {
        Self { nodes: vec![] }
    }
}
impl<T: Copy> Lists<T> {
    fn push(&mut self, node: Node<T>, length: usize) -> ListId {
        let id = ListId(self.nodes.len());
        self.nodes.push((node, length));
        id
    }
    pub(super) fn array(&mut self, values: Vec<T>) -> ListId {
        let length = values.len();
        self.push(Node::Array(values.into(), 0), length)
    }
    pub(super) fn len(&self, list: ListId) -> usize {
        self.nodes[list.0].1
    }
    pub(super) fn cons(&mut self, value: T, tail: ListId) -> ListId {
        self.push(Node::Cons(value, tail), self.len(tail) + 1)
    }
    pub(super) fn uncons(&mut self, list: ListId) -> Option<(T, ListId)> {
        match self.nodes[list.0].0.clone() {
            Node::Cons(value, tail) => Some((value, tail)),
            Node::Array(values, at) => {
                let value = *values.get(at)?;
                let length = values.len() - at - 1;
                Some((value, self.push(Node::Array(values, at + 1), length)))
            }
        }
    }
    pub(super) fn nth(&self, mut list: ListId, mut index: usize) -> Option<T> {
        loop {
            match &self.nodes[list.0].0 {
                Node::Array(values, at) => return values.get(at.checked_add(index)?).copied(),
                Node::Cons(value, tail) => {
                    if index == 0 {
                        return Some(*value);
                    }
                    index -= 1;
                    list = *tail;
                }
            }
        }
    }
    pub(super) fn iter(&self, list: ListId) -> Iter<'_, T> {
        Iter {
            lists: self,
            cursor: Some(list),
            array: None,
        }
    }
    pub(super) fn collect(&self, list: ListId) -> Vec<T> {
        let mut out = Vec::with_capacity(self.len(list));
        out.extend(self.iter(list));
        out
    }
    pub(super) fn append(&mut self, left: ListId, mut right: ListId) -> ListId {
        for value in self.collect(left).into_iter().rev() {
            right = self.cons(value, right);
        }
        right
    }
}
pub(crate) struct Iter<'a, T> {
    lists: &'a Lists<T>,
    cursor: Option<ListId>,
    array: Option<std::slice::Iter<'a, T>>,
}
impl<T: Copy> Iterator for Iter<'_, T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        loop {
            if let Some(array) = &mut self.array {
                return array.next().copied();
            }
            match &self.lists.nodes[self.cursor.take()?.0].0 {
                Node::Cons(value, tail) => {
                    self.cursor = Some(*tail);
                    return Some(*value);
                }
                Node::Array(values, at) => self.array = Some(values[*at..].iter()),
            }
        }
    }
}
