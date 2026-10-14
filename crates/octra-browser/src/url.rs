//! Native Circle path normalization plus browser-relative URL resolution.
use crate::Error;
use octra_node_protocol::circles;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OctUrl {
    pub circle_id: String,
    /// Decoded native canonical path; never percent-decode this field again.
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    directory: bool,
}

pub fn normalize_path(raw: &[u8]) -> Result<String, Error> {
    circles::normalize_path(raw).map_err(|e| Error::Invalid(e.to_string()))
}

fn percent_decode(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0;
    while pos < raw.len() {
        if raw[pos] == b'%' {
            if pos + 2 >= raw.len() {
                return Err(Error::Invalid("truncated percent escape".into()));
            }
            let hi = char::from(raw[pos + 1]).to_digit(16);
            let lo = char::from(raw[pos + 2]).to_digit(16);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(Error::Invalid("invalid percent escape".into()));
            };
            out.push((hi * 16 + lo) as u8);
            pos += 3;
        } else {
            out.push(raw[pos]);
            pos += 1;
        }
    }
    Ok(out)
}

pub fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    out
}

impl OctUrl {
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() > 16 * 1024 {
            return Err(Error::Invalid("browser URL exceeds limit".into()));
        }
        let prefix = input
            .get(..6)
            .ok_or_else(|| Error::Invalid("expected oct:// URL".into()))?;
        if !prefix.eq_ignore_ascii_case("oct://") {
            return Err(Error::Invalid("expected oct:// URL".into()));
        }
        let rest = &input[6..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let circle = &rest[..end];
        // Circle identifiers remain case-sensitive. The browser boundary excludes
        // URL authority syntax; the native state parser remains independent.
        if circle.is_empty()
            || circle.len() > 256
            || !circle
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || matches!(circle, "." | "..")
        {
            return Err(Error::Invalid("invalid Circle identifier".into()));
        }
        let rest = &rest[end..];
        let (before_fragment, fragment) = rest
            .split_once('#')
            .map_or((rest, None), |(p, f)| (p, Some(f.to_owned())));
        let (path, query) = before_fragment
            .split_once('?')
            .map_or((before_fragment, None), |(p, q)| (p, Some(q.to_owned())));
        let path = if path.is_empty() { "/" } else { path };
        let normalized = normalize_path(path.as_bytes())?;
        if normalized.chars().any(|c| c.is_control() || c == '\\')
            || query
                .as_ref()
                .is_some_and(|s| s.chars().any(char::is_control))
            || fragment
                .as_ref()
                .is_some_and(|s| s.chars().any(char::is_control))
        {
            return Err(Error::Invalid("control or backslash in browser URL".into()));
        }
        let decoded = percent_decode(path.as_bytes())?;
        let directory =
            decoded.ends_with(b"/") || decoded.rsplit(|b| *b == b'/').next() == Some(b".");
        Ok(Self {
            circle_id: circle.into(),
            path: normalized,
            query,
            fragment,
            directory,
        })
    }

    pub fn as_string(&self) -> String {
        let mut path = encode_path(&self.path);
        if self.directory && !path.ends_with('/') {
            path.push('/');
        }
        format!(
            "oct://{}{path}{}{}",
            self.circle_id,
            self.query
                .as_ref()
                .map_or(String::new(), |s| format!("?{s}")),
            self.fragment
                .as_ref()
                .map_or(String::new(), |s| format!("#{s}"))
        )
    }

    pub fn is_directory(&self) -> bool {
        self.directory
    }

    /// Browser dot-segment resolution is done before native lookup. Native direct
    /// URLs still refuse traversal, matching Circles.normalize_path.
    pub fn resolve(&self, reference: &str) -> Result<Self, Error> {
        if reference.len() > 16 * 1024 {
            return Err(Error::Invalid("browser URL exceeds limit".into()));
        }
        let reference = reference.trim();
        if reference
            .get(..6)
            .is_some_and(|s| s.eq_ignore_ascii_case("oct://"))
        {
            return Self::parse(reference);
        }
        if reference.starts_with("//")
            || reference.contains('\\')
            || reference.chars().any(char::is_control)
            || reference
                .split(['/', '?', '#'])
                .next()
                .is_some_and(|s| s.contains(':'))
        {
            return Err(Error::Invalid("external or executable URL refused".into()));
        }
        let (without_fragment, fragment) = reference
            .split_once('#')
            .map_or((reference, None), |(p, f)| (p, Some(f.to_owned())));
        let (raw_path, query) = without_fragment
            .split_once('?')
            .map_or((without_fragment, None), |(p, q)| (p, Some(q.to_owned())));
        if raw_path.is_empty() {
            let mut out = self.clone();
            out.fragment = fragment;
            if query.is_some() {
                out.query = query;
            }
            return Ok(out);
        }
        let decoded = percent_decode(raw_path.as_bytes())?;
        let decoded = std::str::from_utf8(&decoded)
            .map_err(|_| Error::Invalid("path is not valid utf-8".into()))?;
        let mut parts = if decoded.starts_with('/') {
            Vec::new()
        } else {
            let mut base = self
                .path
                .split('/')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            if !self.directory {
                base.pop();
            }
            base
        };
        for part in decoded.split('/') {
            match part {
                "" | "." => (),
                ".." => {
                    parts.pop();
                }
                value => parts.push(value),
            }
        }
        let mut path = format!("/{}", parts.join("/"));
        if (decoded.ends_with('/')
            || decoded
                .rsplit('/')
                .next()
                .is_some_and(|p| matches!(p, "." | "..")))
            && !path.ends_with('/')
        {
            path.push('/');
        }
        Self::parse(&format!(
            "oct://{}{}{}{}",
            self.circle_id,
            encode_path(&path),
            query.map_or(String::new(), |s| format!("?{s}")),
            fragment.map_or(String::new(), |s| format!("#{s}"))
        ))
    }

    pub fn path_key(&self) -> String {
        path_key(&self.path)
    }
    pub fn resource_key(&self) -> String {
        resource_key(&self.circle_id, &self.path)
    }
}

pub fn path_key(path: &str) -> String {
    circles::path_key(path.as_bytes())
}
pub fn resource_key(circle: &str, path: &str) -> String {
    circles::resource_key(circle.as_bytes(), path.as_bytes())
}
