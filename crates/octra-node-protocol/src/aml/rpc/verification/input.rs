// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::files;
use super::{validate, Document, Error, File, Result, Value};
use crate::rpc::{param, require_address};
pub struct Prepared {
    address: Vec<u8>,
    input: Input,
}
enum Input {
    Single {
        source: usize,
        files: Option<Vec<usize>>,
    },
    Project {
        main: Vec<u8>,
        source: Vec<u8>,
        imports: Vec<File>,
    },
}
#[derive(Clone)]
pub struct Material {
    pub(super) address: Vec<u8>,
    pub(super) main: Vec<u8>,
    pub(super) source: Vec<u8>,
    pub(super) files: Option<Vec<File>>,
}
impl Material {
    pub fn address(&self) -> &[u8] {
        &self.address
    }
}
fn shape(doc: &Document, params: &Value) -> Result<Input> {
    match param(doc, params, 1) {
        Some(Value::String(_)) => {
            let files = match param(doc, params, 2) {
                None => None,
                Some(Value::List(items)) => Some(items.clone()),
                _ => return Err(Error::invalid(b"program files must be an array")),
            };
            let Value::List(items) = params else {
                unreachable!("positional source was found")
            };
            Ok(Input::Single {
                source: items[1],
                files,
            })
        }
        Some(object @ Value::Object(fields)) => {
            let (Some(Value::String(main)), Some(Value::List(items))) =
                (doc.field(object, b"main"), doc.field(object, b"files"))
            else {
                return Err(Error::invalid(
                    b"expected {main, files} with a valid program main path",
                ));
            };
            if fields.len() != 2 || !files::valid_path(main) {
                return Err(Error::invalid(
                    b"expected {main, files} with a valid program main path",
                ));
            }
            let mut files = files::read(doc, items)?;
            let at = files
                .iter()
                .position(|file| file.path == *main)
                .ok_or_else(|| Error::invalid(b"program main source is missing"))?;
            let source = files.remove(at).source;
            Ok(Input::Project {
                main: main.clone(),
                source,
                imports: files,
            })
        }
        _ => Err(Error::invalid(b"expected source string or {main, files}")),
    }
}
pub fn prepare(doc: &Document, params: &Value) -> Result<Prepared> {
    let address = require_address(doc, params, 0, "address");
    let input = shape(doc, params);
    Ok(Prepared {
        address: address?.to_vec(),
        input: input?,
    })
}
impl Prepared {
    /// String-form source/file validation belongs inside the verification lease;
    /// project-form validation happened earlier in native verify_input.
    pub fn materialize(self, doc: &Document) -> Result<Material> {
        let (main, source, files) = match self.input {
            Input::Single { source, files } => {
                let Some(Value::String(source)) = doc.get(source) else {
                    unreachable!("prepared source string")
                };
                validate(source, None, None)?;
                let files = files
                    .as_ref()
                    .map(|items| files::read_with(doc, items, source.len(), Some(b"main.aml")))
                    .transpose()?;
                (b"main.aml".to_vec(), source.clone(), files)
            }
            Input::Project {
                main,
                source,
                imports,
            } => {
                validate(&source, Some(&imports), Some(&main))?;
                (main, source, Some(imports))
            }
        };
        Ok(Material {
            address: self.address,
            main,
            source,
            files,
        })
    }
}
