// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Location lowering mirrors instruction lowering but remains independently
//! derived from source marks, including native inequality specialization.
use super::{
    LocationId, Locations, Multiplicity, Tag, Term, TermId, Terms, TreeId, Trees, Type, Types,
};
#[derive(Clone, Copy)]
enum Form {
    Leaf(Tag),
    Unary(Tag),
    Binary(Tag),
    Vector(bool),
    Let(bool),
    Unpair,
    Branch(Tag),
    Effect,
    Fold,
}
enum Task {
    Visit(TermId, TreeId),
    Finish(Form, TreeId, usize),
}
impl Locations {
    pub fn from_term(
        &mut self,
        types: &Types,
        terms: &Terms,
        trees: &Trees,
        term: TermId,
        mark: TreeId,
    ) -> Option<LocationId> {
        let mut pending = vec![Task::Visit(term, mark)];
        let mut out = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Visit(term, mark) => {
                    let node = terms.get(term);
                    let tree = trees.get(mark);
                    let mut children = node.children();
                    if children.len() != tree.children.len() {
                        return None;
                    }
                    let mut marks = tree.children.to_vec();
                    let form = match node {
                        Term::Unit => Form::Leaf(Tag::Void),
                        Term::Bool(_) | Term::Int(_) | Term::Narrow(..) | Term::Bytes(_) => {
                            Form::Leaf(Tag::Push)
                        }
                        Term::Var(_) => Form::Leaf(Tag::Get),
                        Term::Vec(..) => Form::Vector(false),
                        Term::Seq(..) => Form::Vector(true),
                        Term::Let(bind, _, body) => {
                            let erased = bind.multiplicity == Multiplicity::Zero;
                            if erased {
                                children = vec![*body];
                                marks = vec![tree.children[1]];
                            }
                            Form::Let(erased)
                        }
                        Term::Unpair(..) => Form::Unpair,
                        Term::If(..) => Form::Branch(Tag::Fork),
                        Term::Case(..) => Form::Branch(Tag::Choice),
                        Term::Fst(_) | Term::Length(_) => Form::Unary(Tag::First),
                        Term::Snd(_) => Form::Unary(Tag::Second),
                        Term::Neg(_) => Form::Unary(Tag::Negate),
                        Term::Abs(_) => Form::Unary(Tag::Absolute),
                        Term::Fit(..) => Form::Unary(Tag::Fit),
                        Term::Wide(_) => Form::Unary(Tag::Wide),
                        Term::Take(count, _) => Form::Unary(Tag::Clip(*count)),
                        Term::Drop(count, _) => Form::Unary(Tag::Skip(*count)),
                        Term::At(index, _) => Form::Unary(Tag::Pick(*index)),
                        Term::Uncons(_) => Form::Unary(Tag::Unhead),
                        Term::Inl(..) => Form::Unary(Tag::Left),
                        Term::Inr(..) => Form::Unary(Tag::Right),
                        Term::Close(_) => Form::Unary(Tag::Close),
                        Term::Pair(..) => Form::Binary(Tag::Duo),
                        Term::Add(..) => Form::Binary(Tag::Plus),
                        Term::Sub(..) => Form::Binary(Tag::Minus),
                        Term::Mul(..) => Form::Binary(Tag::Times),
                        Term::Div(..) => Form::Binary(Tag::Quot),
                        Term::Mod(..) => Form::Binary(Tag::Rem),
                        Term::Cat(..) => Form::Binary(Tag::Join),
                        Term::Vcat(..) => Form::Binary(Tag::Append),
                        Term::Cmp(rel, ..) => Form::Binary(Tag::Order(*rel)),
                        Term::Eq(typ, left, right) => {
                            let different = if matches!(types.get(*typ), Type::Bool)
                                && matches!(terms.get(*right), Term::Bool(false))
                            {
                                match terms.get(*left) {
                                    Term::Eq(typ, lhs, rhs)
                                        if matches!(types.get(*typ), Type::Int) =>
                                    {
                                        Some((*lhs, *rhs))
                                    }
                                    _ => None,
                                }
                            } else {
                                None
                            };
                            if let Some((lhs, rhs)) = different {
                                let inner = trees.get(tree.children[0]);
                                if inner.children.len() != 2 {
                                    return None;
                                }
                                children = vec![lhs, rhs];
                                marks = inner.children.to_vec();
                                Form::Binary(Tag::Different)
                            } else {
                                Form::Binary(Tag::Same)
                            }
                        }
                        Term::Act(..) => Form::Effect,
                        Term::Vfold(..) => Form::Fold,
                        Term::Step(..) => return None,
                    };
                    pending.push(Task::Finish(form, mark, children.len()));
                    pending.extend(
                        children
                            .into_iter()
                            .zip(marks)
                            .rev()
                            .map(|(term, mark)| Task::Visit(term, mark)),
                    );
                }
                Task::Finish(form, mark, count) => {
                    let children = out.split_off(out.len() - count);
                    let tree = trees.get(mark);
                    let at = tree.at;
                    let done = self.done();
                    let location = match form {
                        Form::Leaf(tag) => self.step(tag, at, done),
                        Form::Unary(tag) => {
                            let rest = self.step(tag, at, done);
                            self.continue_with(children[0], rest)
                        }
                        Form::Binary(tag) => {
                            let rest = self.step(tag, at, done);
                            let rest = self.continue_with(children[1], rest);
                            self.continue_with(children[0], rest)
                        }
                        Form::Vector(sequence) => {
                            let mut rest = if sequence {
                                self.step(Tag::Pack, at, done)
                            } else {
                                done
                            };
                            for _ in &children {
                                rest = self.step(Tag::Cons, at, rest);
                            }
                            rest = self.step(Tag::Empty, at, rest);
                            for child in children.into_iter().rev() {
                                rest = self.continue_with(child, rest);
                            }
                            rest
                        }
                        Form::Let(true) => children[0],
                        Form::Let(false) | Form::Unpair => {
                            let tag = if matches!(form, Form::Unpair) {
                                Tag::Scope2
                            } else {
                                Tag::Scope
                            };
                            let rest = self.next(tag, at, None, vec![children[1]], done);
                            self.continue_with(children[0], rest)
                        }
                        Form::Branch(tag) => {
                            let branches = [
                                trees.get(tree.children[1]).at,
                                trees.get(tree.children[2]).at,
                            ];
                            let rest = self.next(
                                tag,
                                at,
                                Some(branches),
                                vec![children[1], children[2]],
                                done,
                            );
                            self.continue_with(children[0], rest)
                        }
                        Form::Effect => self.next(Tag::Effect, at, None, vec![children[0]], done),
                        Form::Fold => {
                            let rest = self.next(Tag::Iter, at, None, vec![children[2]], done);
                            let rest = self.continue_with(children[1], rest);
                            self.continue_with(children[0], rest)
                        }
                    };
                    out.push(location);
                }
            }
        }
        out.pop()
    }
}
