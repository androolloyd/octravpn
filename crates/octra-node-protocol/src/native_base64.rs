// SPDX-License-Identifier: ISC
// Port of the default padded decoder in OCaml base64 3.5.2.
// Copyright (c) 2006-2009 Citrix Systems Inc.
// Copyright (c) 2010 Thomas Gazagnaire <thomas@gazagnaire.com>
// Copyright (c) 2014-2016 Anil Madhavapeddy <anil@recoil.org>
// Copyright (c) 2016 David Kaloper Meršinjak
// Copyright (c) 2018 Romain Calascibetta <romain.calascibetta@gmail.com>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//! Native default-alphabet decoding, including excess-padding acceptance and
//! right-to-left error precedence. This is protocol compatibility, not a general
//! recommendation for new Base64 formats.

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("Wrong padding")]
    WrongPadding,
    #[error("Malformed input")]
    Malformed,
    #[error("Too much input")]
    TooMuchInput,
}
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let mut at = 0;
    while at < input.len() {
        // Native examines the fourth byte first, including on short groups.
        let group = input.get(at..at + 4).ok_or(Error::WrongPadding)?;
        let mut digits = [0_u32; 4];
        let mut padding = 0;
        for i in (0..4).rev() {
            digits[i] = match group[i] {
                b'A'..=b'Z' => u32::from(group[i] - b'A'),
                b'a'..=b'z' => u32::from(group[i] - b'a' + 26),
                b'0'..=b'9' => u32::from(group[i] - b'0' + 52),
                b'+' => 62,
                b'/' => 63,
                b'=' if padding == 3 - i => {
                    padding += 1;
                    0
                }
                _ => return Err(Error::Malformed),
            };
        }
        let value = (digits[0] << 18) | (digits[1] << 12) | (digits[2] << 6) | digits[3];
        let bytes = [(value >> 16) as u8, (value >> 8) as u8, value as u8];
        at += 4;
        if at == input.len() {
            output.extend_from_slice(&bytes[..3 - padding.min(3)]);
            break;
        }
        match padding {
            0 => output.extend_from_slice(&bytes),
            4 => {
                if input[at..].iter().any(|&b| b != b'=') {
                    return Err(Error::Malformed);
                }
                // Once a full padding group is seen, even a partial remaining
                // padding group is native-valid. Nothing more is decoded.
                break;
            }
            _ => return Err(Error::TooMuchInput),
        }
    }
    Ok(output)
}
