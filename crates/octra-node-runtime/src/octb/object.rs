// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{work, Budget, Exec, Instruction as I, Machine, Request, Trap, Value};
use octra_node_protocol::circle_object::{self as object, Input, Write};

impl Machine {
    fn object_scan(&mut self) -> Exec {
        if self.options.object_cost {
            let count = i64::try_from(self.storage.values().len()).map_err(|_| Trap::Refused)?;
            self.charge(work::scaled_product(&[count, 5], 1).ok_or(Trap::Refused)?)?;
        }
        Ok(())
    }
    fn object_writes(&mut self, writes: &[Write], budget: &mut Option<&mut Budget>) -> Exec {
        let mut base = 0_i64;
        let mut prior = 0_i64;
        let mut requests = Vec::with_capacity(writes.len());
        for write in writes {
            let (cost, old, request) = match write {
                Write::Set(key, value) => {
                    let key_len = i64::try_from(key.len()).map_err(|_| Trap::Refused)?;
                    let value_len = i64::try_from(value.len()).map_err(|_| Trap::Refused)?;
                    (10, 10 + value_len / 32, Request::Write(key_len, value_len))
                }
                Write::Del(key) => (
                    5,
                    5,
                    Request::Erase(i64::try_from(key.len()).map_err(|_| Trap::Refused)?),
                ),
            };
            base = base
                .checked_add(cost)
                .filter(|v| *v <= work::MAX_INT)
                .ok_or(Trap::Refused)?;
            prior = prior
                .checked_add(old)
                .filter(|v| *v <= work::MAX_INT)
                .ok_or(Trap::Refused)?;
            requests.push(request);
        }
        self.bytes(budget, base, prior, &requests)?;
        // Native checks this after charging the complete write plan, and before
        // applying even its first write. Journal undo order then stays identical.
        if writes
            .iter()
            .any(|w| matches!(w, Write::Set(_, value) if value.len() > 4_194_304))
        {
            return Err(Trap::Refused);
        }
        for write in writes {
            match write {
                Write::Set(key, value) => self.write(key.clone(), Some(value.clone())),
                Write::Del(key) => self.write(key.clone(), None),
            }
        }
        Ok(())
    }
    pub(super) fn execute_object(&mut self, op: &I, budget: &mut Option<&mut Budget>) -> Exec {
        match op {
            I::ObjectMemberCount(dest, object) => {
                let object = self.text(*object)?;
                self.object_scan()?;
                let count = object::members(&self.storage, &object).len();
                self.set(*dest, Value::int(count))?;
            }
            I::ObjectHasMember(dest, object, member) => {
                let present =
                    object::has_member(&self.storage, &self.text(*object)?, &self.text(*member)?);
                self.set(*dest, Value::Bool(present))?;
            }
            I::ObjectMemberRefAt(dest, object, index) => {
                let object = self.text(*object)?;
                let index = self.index(*index)?;
                self.object_scan()?;
                let members = object::members(&self.storage, &object);
                let value = usize::try_from(index)
                    .ok()
                    .and_then(|i| members.get(i))
                    .cloned()
                    .unwrap_or_default();
                self.set(*dest, Value::string(value))?;
            }
            I::ObjectTransitionApply(
                dest,
                transition,
                object,
                previous,
                next,
                bundle,
                hash,
                proof,
                receipt,
                status,
                intent,
            ) => {
                self.view_guard(budget)?;
                let object = self.text(*object)?;
                self.object_scan()?;
                let plan = object::apply(
                    &self.storage,
                    self.context.epoch,
                    self.options.object_quorum,
                    Input {
                        transition_ref: &self.text(*transition)?,
                        object_ref: &object,
                        previous_state_ref: &self.text(*previous)?,
                        next_state_ref: &self.text(*next)?,
                        member_bundle: &self.text(*bundle)?,
                        touched_members_hash: &self.text(*hash)?,
                        proof_kind: &self.text(*proof)?,
                        proof_receipt_hash: &self.text(*receipt)?,
                        status: &self.text(*status)?,
                        intent_id: &self.text(*intent)?,
                    },
                    |_| object::members(&self.storage, &object),
                )
                .map_err(|_| Trap::Refused)?;
                self.object_writes(&plan.writes, budget)?;
                self.set(*dest, Value::int(plan.version))?;
            }
            _ => unreachable!("object instructions are dispatched together"),
        }
        Ok(())
    }
}
