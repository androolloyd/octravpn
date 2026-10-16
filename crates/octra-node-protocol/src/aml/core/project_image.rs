// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_pimg exact project code trees and canonical bit images.
use super::{
    bin::{self, Bits, Code, CodeId, Codes},
    project::{self, Project, Root, Source, Target},
    rule::{self, Field, Rule, LOCAL},
    Natural,
};
use num_traits::ToPrimitive;

pub(crate) fn text_code(codes: &mut Codes, value: &[u8]) -> CodeId {
    let bytes = value
        .iter()
        .map(|byte| codes.num(*byte))
        .collect::<Vec<_>>();
    codes.list(&bytes)
}
pub(crate) fn text_get(codes: &Codes, root: CodeId) -> Option<Vec<u8>> {
    codes
        .list_get(root)?
        .into_iter()
        .map(|id| {
            let Code::Num(value) = codes.get(id) else {
                return None;
            };
            Natural::byte(value)
        })
        .collect()
}
pub(crate) fn tagged(codes: &Codes, root: CodeId, expected: u32) -> Option<CodeId> {
    let Code::Tag(tag, body) = codes.get(root) else {
        return None;
    };
    (tag.to_u32()? == expected).then_some(*body)
}
fn rule_code(codes: &mut Codes, value: &rule::Id) -> CodeId {
    let values = value
        .values()
        .into_iter()
        .map(|value| codes.num(value))
        .collect::<Vec<_>>();
    let body = codes.list(&values);
    codes.tag(0, body)
}
fn rule_get(codes: &Codes, root: CodeId) -> Option<rule::Id> {
    let values = codes
        .list_get(tagged(codes, root, 0)?)?
        .into_iter()
        .map(|id| {
            let Code::Num(value) = codes.get(id) else {
                return None;
            };
            Some(value.as_ref())
        })
        .collect::<Option<Vec<_>>>()?;
    let [version, limits @ ..] = values.as_slice() else {
        return None;
    };
    if limits.len() != 11
        || limits
            .iter()
            .zip(LOCAL.values())
            .any(|(actual, expected)| actual.to_i64() != Some(expected))
    {
        return None;
    }
    let version = Natural::new(version)?;
    Rule::new(i64::from(version.get()), 0.into(), LOCAL)
        .ok()
        .map(|value| value.id().clone())
}
fn target_code(codes: &mut Codes, target: Target) -> CodeId {
    codes.tag(
        match target {
            Target::Octb1 => 0,
            Target::Ocps1 => 1,
        },
        codes.nil(),
    )
}
fn target_get(codes: &Codes, root: CodeId) -> Option<Target> {
    let Code::Tag(tag, body) = codes.get(root) else {
        return None;
    };
    if !matches!(codes.get(*body), Code::Nil) {
        return None;
    }
    match tag.to_u8()? {
        0 => Some(Target::Octb1),
        1 => Some(Target::Ocps1),
        _ => None,
    }
}
fn source_code(codes: &mut Codes, value: &Source) -> CodeId {
    let path = text_code(codes, value.path());
    let body = text_code(codes, value.body());
    let deps = value
        .deps()
        .iter()
        .map(|dep| text_code(codes, dep))
        .collect::<Vec<_>>();
    let deps = codes.list(&deps);
    let fields = codes.list(&[path, body, deps]);
    codes.tag(1, fields)
}
fn source_get(codes: &Codes, root: CodeId) -> Option<Source> {
    let [path, body, deps] = codes.fields::<3>(tagged(codes, root, 1)?)?;
    let path = text_get(codes, path)?;
    let body = text_get(codes, body)?;
    let deps = codes
        .list_get(deps)?
        .into_iter()
        .map(|dep| text_get(codes, dep))
        .collect::<Option<Vec<_>>>()?;
    Some(project::source(&path, &body, deps))
}
fn root_code(codes: &mut Codes, value: &Root) -> CodeId {
    let path = text_code(codes, value.path());
    let name = text_code(codes, value.name());
    let feed = text_code(codes, value.feed());
    let fields = codes.list(&[path, name, feed]);
    codes.tag(2, fields)
}
fn root_get(codes: &Codes, root: CodeId) -> Option<Root> {
    let [path, name, feed] = codes.fields::<3>(tagged(codes, root, 2)?)?;
    Some(project::root_feed(
        &text_get(codes, path)?,
        &text_get(codes, name)?,
        &text_get(codes, feed)?,
    ))
}
pub fn code(codes: &mut Codes, value: &Project) -> Option<CodeId> {
    if value.rule().version() > LOCAL.get(Field::Nat) {
        return None;
    }
    let sources = value
        .sources()
        .iter()
        .map(|value| source_code(codes, value))
        .collect::<Vec<_>>();
    let sources = codes.list(&sources);
    let roots = value
        .roots()
        .iter()
        .map(|value| root_code(codes, value))
        .collect::<Vec<_>>();
    let roots = codes.list(&roots);
    let rule = rule_code(codes, value.rule());
    let target = target_code(codes, value.target());
    let fields = codes.list(&[sources, roots, rule, target]);
    Some(codes.tag(3, fields))
}
pub fn get(codes: &Codes, root: CodeId) -> Option<Project> {
    let [sources, roots, rule, target] = codes.fields::<4>(tagged(codes, root, 3)?)?;
    let sources = codes
        .list_get(sources)?
        .into_iter()
        .map(|value| source_get(codes, value))
        .collect::<Option<Vec<_>>>()?;
    let roots = codes
        .list_get(roots)?
        .into_iter()
        .map(|value| root_get(codes, value))
        .collect::<Option<Vec<_>>>()?;
    project::make(
        rule_get(codes, rule)?,
        target_get(codes, target)?,
        sources,
        roots,
    )
    .ok()
}
pub fn encode(value: &Project) -> Option<Bits> {
    let mut codes = Codes::default();
    let root = code(&mut codes, value)?;
    bin::encode(&codes, root)
}
pub fn valid(value: &Project) -> bool {
    encode(value).is_some()
}
pub fn decode(input: &[bool]) -> Option<Project> {
    let decoded = bin::decode(input)?;
    let value = get(&decoded.codes, decoded.root)?;
    (encode(&value)?.as_slice() == input).then_some(value)
}
