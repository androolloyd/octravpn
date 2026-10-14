// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{data, work, Budget, Exec, Host, Machine, Request, SpawnRequest, Trap, Value};
use octra_node_protocol::{native_base64, native_integer::parse_int63};

impl Machine {
    fn spawn_input(&mut self, input: Vec<u8>, budget: &mut Option<&mut Budget>) -> Exec<Vec<u8>> {
        if input.starts_with(b"OCTB") {
            return Ok(input);
        }
        if let Some(b) = budget {
            let plan = work::decoding(input.len() as i64, 0, 0, false).ok_or(Trap::Refused)?;
            b.plan(
                self.effort,
                self.options.limit,
                5000 + plan.max_bytes / 100,
                &plan.requests,
            )
            .ok_or(Trap::Refused)?;
            self.effort = b
                .charge(self.effort, self.options.limit, 0, &plan.requests)
                .ok_or(Trap::Refused)?;
        }
        match native_base64::decode(&input) {
            Ok(raw) => Ok(raw),
            Err(_) if budget.is_none() => Ok(input),
            Err(_) => Err(Trap::Refused),
        }
    }

    pub(super) fn spawn(
        &mut self,
        dest: u8,
        source: u8,
        base: u8,
        count: u8,
        host: &mut impl Host,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        if base >= 64 || u16::from(base) + u16::from(count) > 64 {
            return Err(Trap::Refused);
        }
        self.view_guard(budget)?;
        if self.context.depth >= 8 {
            return Err(Trap::Refused);
        }
        let code = self.spawn_input(self.text(source)?, budget)?;
        if code.len() < 12 {
            return Err(Trap::Refused);
        }
        let params = self.regs[usize::from(base)..usize::from(base) + usize::from(count)].to_vec();
        let key = b"\0spawn_nonce";
        let nonce = self
            .storage
            .get(key)
            .and_then(|v| parse_int63(v))
            .unwrap_or(0);
        let next = data::add(nonce, 1).to_string().into_bytes();
        self.bytes(
            budget,
            0,
            0,
            &[Request::Write(key.len() as i64, next.len() as i64)],
        )?;
        self.storage.replace(key.to_vec(), next);
        self.charge(5000 + code.len() as i64 / 100)?;
        let limit = if self.options.is_view || self.options.fhe_work || budget.is_some() {
            (self.options.limit - self.effort).max(0)
        } else {
            1_000_000
        };
        let result = host.spawn(
            SpawnRequest {
                parent: &self.context.address,
                code: &code,
                nonce,
                params: &params,
                limit,
            },
            budget.as_deref_mut(),
        )?;
        let Some(result) = result else {
            self.storage
                .replace(key.to_vec(), nonce.to_string().into_bytes());
            return Err(if self.options.async_exec {
                Trap::HostRefused
            } else {
                Trap::Refused
            });
        };
        if let Err(error) = self.charge(result.effort) {
            if self.options.async_exec {
                self.storage
                    .replace(key.to_vec(), nonce.to_string().into_bytes());
                return Err(Trap::HostRefused);
            }
            return Err(error);
        }
        self.events.extend(result.events);
        self.set(dest, Value::Address(result.address.into()))
    }
}
