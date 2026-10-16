//! Native OCPG program envelopes and OCPS source packages. Decoding validates
//! framing and source paths; compilation and admission certificates follow later.
use crate::transaction::decode_base64;
use base64::{engine::general_purpose::STANDARD, Engine};
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);
fn err(text: &str) -> Error {
    Error(text.into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub code: Vec<u8>,
    pub cert: Vec<u8>,
}
impl Envelope {
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < 16 {
            return Err(err("program envelope too short"));
        }
        if !raw.starts_with(b"OCPG") {
            return Err(err("bad program envelope magic"));
        }
        let version = u16::from_le_bytes(raw[4..6].try_into().unwrap());
        let flags = u16::from_le_bytes(raw[6..8].try_into().unwrap());
        let code = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
        let cert = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;
        if version != 2 {
            return Err(Error(format!(
                "unsupported program envelope version: {version}"
            )));
        }
        if flags != 0 {
            return Err(Error(format!(
                "unsupported program envelope flags: {flags}"
            )));
        }
        if code > 16 * 1024 * 1024 {
            return Err(err("program bytecode too large"));
        }
        if cert > 1024 * 1024 {
            return Err(err("program certificate too large"));
        }
        if code > raw.len() - 16 || cert > raw.len() - 16 - code {
            return Err(err("invalid program envelope length"));
        }
        if code + cert + 16 != raw.len() {
            return Err(err("program envelope trailing bytes"));
        }
        Ok(Self {
            code: raw[16..16 + code].to_vec(),
            cert: raw[16 + code..].to_vec(),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.code.len() > 16 * 1024 * 1024 {
            return Err(err("program bytecode too large"));
        }
        if self.cert.len() > 1024 * 1024 {
            return Err(err("program certificate too large"));
        }
        let mut bytes = b"OCPG\x02\x00\x00\x00".to_vec();
        bytes.extend((self.code.len() as u32).to_le_bytes());
        bytes.extend((self.cert.len() as u32).to_le_bytes());
        bytes.extend(&self.code);
        bytes.extend(&self.cert);
        Ok(bytes)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub path: Vec<u8>,
    pub body: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub compiler_profile: u16,
    pub main: Vec<u8>,
    pub sources: Vec<Source>,
    pub envelope: Vec<u8>,
}
pub fn valid_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path[0] != b'/'
        && path
            .iter()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'.' | b'_' | b'-' | b'/'))
        && path
            .split(|v| *v == b'/')
            .all(|p| !p.is_empty() && p != b"." && p != b"..")
}
pub fn normalize(main: &[u8], mut sources: Vec<Source>) -> Result<Vec<Source>, Error> {
    if !valid_path(main) {
        return Err(err("invalid Program main path"));
    }
    if sources.is_empty() || sources.len() > 32 {
        return Err(err("too many Program sources"));
    }
    sources.sort_by(|a, b| a.path.cmp(&b.path));
    let mut previous: Option<&[u8]> = None;
    let mut total = 0;
    for source in &sources {
        if !valid_path(&source.path) {
            return Err(err("invalid Program source path"));
        }
        if previous == Some(source.path.as_slice()) {
            return Err(err("duplicate Program source path"));
        }
        if source.body.len() > 65_536 {
            return Err(err("Program source too large"));
        }
        total += source.path.len() + source.body.len();
        previous = Some(&source.path);
    }
    if total > 262_144 {
        return Err(err("Program sources too large"));
    }
    if !sources.iter().any(|s| s.path == main) {
        return Err(err("Program main source missing"));
    }
    Ok(sources)
}
struct Reader<'a> {
    raw: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if length > self.raw.len() - self.offset {
            return Err(err("invalid Program package length"));
        }
        let at = self.offset;
        self.offset += length;
        Ok(&self.raw[at..self.offset])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}
impl Package {
    /// Native framing encoder. Call `normalize` before building a source bundle;
    /// structural decoding and source admission remain separate operations.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.envelope.len() > 2_097_152 {
            return Err(err("Program envelope too large"));
        }
        let mut raw = b"OCPS\x01\x00".to_vec();
        raw.extend(self.compiler_profile.to_le_bytes());
        raw.extend((self.main.len() as u16).to_le_bytes());
        raw.extend(&self.main);
        raw.extend((self.sources.len() as u16).to_le_bytes());
        for source in &self.sources {
            raw.extend((source.path.len() as u16).to_le_bytes());
            raw.extend(&source.path);
            raw.extend((source.body.len() as u32).to_le_bytes());
            raw.extend(&source.body);
        }
        raw.extend((self.envelope.len() as u32).to_le_bytes());
        raw.extend(&self.envelope);
        Ok(raw)
    }
    pub fn decode_base64(encoded: &[u8]) -> Result<Self, Error> {
        let raw = decode_base64(encoded).map_err(|_| err("invalid Program package encoding"))?;
        if STANDARD.encode(&raw).as_bytes() != encoded {
            return Err(err("invalid Program package encoding"));
        }
        Self::decode(&raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < 12 {
            return Err(err("Program package too short"));
        }
        if !raw.starts_with(b"OCPS") {
            return Err(err("bad Program package magic"));
        }
        let mut reader = Reader { raw, offset: 4 };
        let version = reader.u16()?;
        let compiler_profile = reader.u16()?;
        let length = usize::from(reader.u16()?);
        let main = reader.take(length)?.to_vec();
        let count = reader.u16()?;
        if version != 1 {
            return Err(err("unsupported Program package version"));
        }
        if compiler_profile != 1 {
            return Err(err("unsupported Program compiler profile"));
        }
        if count == 0 || count > 32 {
            return Err(err("too many Program sources"));
        }
        let mut sources = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let length = usize::from(reader.u16()?);
            let path = reader.take(length)?.to_vec();
            let length = reader.u32()? as usize;
            let body = reader.take(length)?.to_vec();
            sources.push(Source { path, body });
        }
        let length = reader.u32()? as usize;
        if length > 2_097_152 {
            return Err(err("Program envelope too large"));
        }
        let envelope = reader.take(length)?.to_vec();
        if reader.offset != raw.len() {
            return Err(err("Program package trailing bytes"));
        }
        let normalized = normalize(&main, sources.clone())?;
        if normalized != sources {
            return Err(err("invalid Program source path"));
        }
        Envelope::decode(&envelope).map_err(|e| Error(format!("Program admission failed: {e}")))?;
        Ok(Self {
            compiler_profile,
            main,
            sources,
            envelope,
        })
    }
}
