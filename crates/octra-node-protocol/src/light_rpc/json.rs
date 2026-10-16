//! Ordered byte-preserving JSON output shared by native read projections.
pub fn null() -> Vec<u8> {
    b"null".to_vec()
}
pub fn string(value: impl AsRef<[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    crate::transaction::json_string(&mut out, value.as_ref());
    out
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
pub fn number(value: impl ToString) -> Vec<u8> {
    value.to_string().into_bytes()
}
pub fn boolean(value: bool) -> Vec<u8> {
    if value {
        b"true".to_vec()
    } else {
        b"false".to_vec()
    }
}
pub fn optional(value: Option<&[u8]>) -> Vec<u8> {
    value.map_or_else(null, string)
}
pub fn array(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut out = vec![b'['];
    for (i, value) in values.into_iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend(value);
    }
    out.push(b']');
    out
}
pub fn object(values: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (i, (key, value)) in values.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        crate::transaction::json_string(&mut out, key.as_bytes());
        out.push(b':');
        out.extend(value);
    }
    out.push(b'}');
    out
}

pub fn base64(value: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(value)
}
