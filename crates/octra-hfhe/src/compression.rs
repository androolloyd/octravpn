// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Exact PVAC adaptive range coding, including native decoder refusal rules.
use crate::Error;

struct Predictor {
    previous: usize,
    order: [usize; 256],
    contexts: Vec<u32>,
    context: usize,
}

impl Predictor {
    fn new() -> Self {
        let contexts = (0..0x10000_u32)
            .map(|i| {
                let weight = (i & 1) * 2
                    + (i & 2)
                    + ((i >> 2) & 1)
                    + ((i >> 3) & 1)
                    + ((i >> 4) & 1)
                    + ((i >> 5) & 1)
                    + ((i >> 6) & 1)
                    + ((i >> 7) & 1)
                    + 3;
                (weight << 28) | 6
            })
            .collect();
        Self {
            previous: 0,
            order: [0x66; 256],
            contexts,
            context: 0,
        }
    }

    fn predict(&mut self) -> u32 {
        self.context = self.previous << 8 | self.order[self.previous];
        self.contexts[self.context] >> 16
    }

    fn update(&mut self, bit: u32) {
        let entry = &mut self.contexts[self.context];
        let count = *entry & 255;
        let probability = *entry >> 14;
        if count < 90 {
            *entry += 1;
            let delta = (bit << 18)
                .wrapping_sub(probability)
                .wrapping_mul(32768 / (count + count + 3))
                & 0xffff_ff00;
            *entry = entry.wrapping_add(delta);
        }
        let order = &mut self.order[self.previous];
        *order = (*order + *order + bit as usize) & 255;
        self.previous = self.previous + self.previous + bit as usize;
        if self.previous >= 256 {
            self.previous = 0;
        }
    }
}

struct Range {
    predictor: Predictor,
    lo: u32,
    hi: u32,
}

impl Range {
    fn new() -> Self {
        Self {
            predictor: Predictor::new(),
            lo: 0,
            hi: u32::MAX,
        }
    }

    fn middle(&mut self) -> u32 {
        let probability = self.predictor.predict();
        let width = self.hi.wrapping_sub(self.lo);
        self.lo
            .wrapping_add((width >> 16).wrapping_mul(probability))
            .wrapping_add(((width & 0xffff).wrapping_mul(probability)) >> 16)
    }

    fn update(&mut self, middle: u32, bit: u32) {
        if bit != 0 {
            self.hi = middle;
        } else {
            self.lo = middle.wrapping_add(1);
        }
        self.predictor.update(bit);
    }

    fn shift(&mut self) {
        self.lo <<= 8;
        self.hi = (self.hi << 8) | 255;
    }
}

pub fn pack(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let length =
        u32::try_from(raw.len()).map_err(|_| Error("HFHE compression length unavailable"))?;
    let mut output = vec![0xec];
    output.extend_from_slice(&length.to_be_bytes());
    let mut range = Range::new();
    let mut encode = |bit| {
        let middle = range.middle();
        range.update(middle, bit);
        while (range.lo ^ range.hi) & 0xff00_0000 == 0 {
            output.push((range.hi >> 24) as u8);
            range.shift();
        }
    };
    for &byte in raw {
        encode(1);
        for bit in (0..8).rev() {
            encode(u32::from(byte >> bit & 1));
        }
    }
    encode(0);
    while (range.lo ^ range.hi) & 0xff00_0000 == 0 {
        output.push((range.hi >> 24) as u8);
        range.shift();
    }
    output.push((range.hi >> 24) as u8);
    Ok(output)
}

pub fn unpack(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() < 5 || data[0] != 0xec {
        return Err(Error("pvac_compress: bad header"));
    }
    let length = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
    if length > 32 * 1024 * 1024 {
        return Err(Error("pvac_compress: size exceeds 32MB limit"));
    }
    let payload = &data[5..];
    if length > 0 && (payload.is_empty() || payload.len() < length.div_ceil(64)) {
        return Err(Error("pvac_compress: expansion ratio rejected"));
    }
    let mut position = 0;
    let mut next_byte = || {
        let byte = payload.get(position).copied().unwrap_or(0);
        if position < payload.len() {
            position += 1;
        }
        u32::from(byte)
    };
    let mut code = 0_u32;
    for _ in 0..4 {
        code = (code << 8) | next_byte();
    }
    let mut range = Range::new();
    let mut decode = || {
        let middle = range.middle();
        let bit = u32::from(code <= middle);
        range.update(middle, bit);
        while (range.lo ^ range.hi) & 0xff00_0000 == 0 {
            range.shift();
            code = (code << 8) | next_byte();
        }
        bit
    };
    let mut output = Vec::with_capacity(length);
    while decode() != 0 {
        let mut byte = 1_u32;
        while byte < 256 {
            byte = byte + byte + decode();
        }
        if output.len() >= length {
            return Err(Error("pvac_compress: output exceeds declared size"));
        }
        output.push((byte - 256) as u8);
    }
    if output.len() != length {
        return Err(Error("pvac_compress: size mismatch"));
    }
    Ok(output)
}
