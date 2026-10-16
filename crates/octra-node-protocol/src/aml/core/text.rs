// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_text's bounded byte diagnostics, including its exact boundary ellipsis.
pub const MAX: usize = 1024;
#[derive(Default)]
pub struct Text {
    out: Vec<u8>,
    cut: bool,
}
impl Text {
    fn room(&self) -> usize {
        (MAX - 3).saturating_sub(self.out.len())
    }
    pub fn full(&self) -> bool {
        self.cut || self.room() == 0
    }
    pub fn add(&mut self, value: &[u8]) {
        if self.cut {
            return;
        }
        let room = self.room();
        if room == 0 {
            self.cut = true;
        } else if value.len() <= room {
            self.out.extend(value);
        } else {
            self.out.extend(&value[..room]);
            self.cut = true;
        }
    }
    pub fn finish(mut self) -> Vec<u8> {
        if self.full() {
            self.out.extend(b"...");
        }
        self.out
    }
}
pub fn clip(value: &[u8]) -> Vec<u8> {
    if value.len() <= MAX {
        value.to_vec()
    } else {
        [&value[..MAX - 3], b"..."].concat()
    }
}
