//! Existing Circle OCWR1/OCWS1 wire frames. No new host ABI is required.
use crate::{Error, MAX_REQUEST_BYTES};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Param {
    String(String),
    Int(u64),
}

pub struct Request {
    pub method: String,
    pub params: Vec<Param>,
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    if length > input.len() {
        return Err(Error::Frame);
    }
    let (result, rest) = input.split_at(length);
    *input = rest;
    Ok(result)
}

pub fn decode(mut input: &[u8]) -> Result<Request, Error> {
    if input.len() > MAX_REQUEST_BYTES || take(&mut input, 5)? != b"OCWR1" {
        return Err(Error::Frame);
    }
    let length =
        u16::from_be_bytes(take(&mut input, 2)?.try_into().map_err(|_| Error::Frame)?) as usize;
    if length == 0 || length > 64 {
        return Err(Error::Frame);
    }
    let method = std::str::from_utf8(take(&mut input, length)?)
        .map_err(|_| Error::Frame)?
        .to_owned();
    let count =
        u16::from_be_bytes(take(&mut input, 2)?.try_into().map_err(|_| Error::Frame)?) as usize;
    if count > 8 {
        return Err(Error::Frame);
    }
    let mut params = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = take(&mut input, 1)?[0];
        let length =
            u32::from_be_bytes(take(&mut input, 4)?.try_into().map_err(|_| Error::Frame)?) as usize;
        let value = std::str::from_utf8(take(&mut input, length)?).map_err(|_| Error::Frame)?;
        params.push(match tag {
            4 => Param::String(value.to_owned()),
            3 => {
                let number = value.parse::<u64>().map_err(|_| Error::Frame)?;
                if number.to_string() != value {
                    return Err(Error::Frame);
                }
                Param::Int(number)
            }
            _ => return Err(Error::Frame),
        });
    }
    if !input.is_empty() {
        return Err(Error::Frame);
    }
    Ok(Request { method, params })
}

pub fn response(json: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(json.len() + 10);
    output.extend_from_slice(b"OCWS1");
    output.push(4);
    output.extend_from_slice(&(json.len() as u32).to_be_bytes());
    output.extend_from_slice(json);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_lengths_trailing_bytes_and_noncanonical_numbers_are_rejected() {
        let mut frame = b"OCWR1\0\x06retire\0\x01\x03\0\0\0\x011".to_vec();
        assert_eq!(decode(&frame).unwrap().params, vec![Param::Int(1)]);
        frame.push(0);
        assert!(decode(&frame).is_err());
        assert!(decode(b"OCWR1\0\x06retire\0\x01\x03\0\0\0\x0201").is_err());
        assert!(decode(b"OCWR1\0\x06retire\0\x01\x04\xff\xff\xff\xff").is_err());
    }
}
