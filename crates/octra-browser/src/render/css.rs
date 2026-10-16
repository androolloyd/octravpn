//! Token-aware, bounded public CSS resource rewriting. Unrelated source bytes
//! are preserved; strings that are not URL/import/image-set operands stay data.
use crate::{Error, OctUrl, MAX_ASSET_BYTES};
use cssparser::{ParseError, Parser, ParserInput, Token};

const MAX_DEPTH: usize = 64;
const MAX_TOKENS: usize = 1_000_000;

#[derive(Default)]
struct Budget {
    tokens: usize,
    output: usize,
}

pub(super) fn rewrite(
    input: &[u8],
    base: &OctUrl,
    route: &dyn Fn(&OctUrl) -> String,
) -> Result<Vec<u8>, Error> {
    if input.len() > MAX_ASSET_BYTES {
        return Err(Error::TooLarge);
    }
    let source =
        std::str::from_utf8(input).map_err(|_| Error::Invalid("CSS is not valid UTF-8".into()))?;
    let mut input = ParserInput::new(source);
    let mut parser = Parser::new(&mut input);
    let mut budget = Budget::default();
    walk(&mut parser, base, route, 0, false, &mut budget)
        .map(String::into_bytes)
        .map_err(|_| Error::Invalid("CSS resource rewrite refused".into()))
}

fn resource(value: &str, base: &OctUrl, route: &dyn Fn(&OctUrl) -> String) -> Result<String, ()> {
    let value = value.trim();
    let url = base.resolve(value).map_err(|_| ())?;
    if url.circle_id != base.circle_id {
        return Err(());
    }
    let target = if value.starts_with('#') {
        value.to_owned()
    } else {
        route(&url)
    };
    quote(&target)
}

fn quote(value: &str) -> Result<String, ()> {
    let mut out = String::new();
    cssparser::serialize_string(value, &mut out).map_err(|_| ())?;
    // A CSS escape may decode to an HTML raw-text end tag. Keep that byte
    // escaped when this stylesheet is inserted back into a <style> element.
    Ok(out.replace('<', "\\3C "))
}

fn quoted_closed(raw: &str) -> bool {
    let Some(quote) = raw.as_bytes().first() else {
        return false;
    };
    raw.len() >= 2
        && raw.as_bytes().last() == Some(quote)
        && raw.as_bytes()[..raw.len() - 1]
            .iter()
            .rev()
            .take_while(|b| **b == b'\\')
            .count()
            .is_multiple_of(2)
}

fn walk<'i>(
    input: &mut Parser<'i, '_>,
    base: &OctUrl,
    route: &dyn Fn(&OctUrl) -> String,
    depth: usize,
    image_strings: bool,
    budget: &mut Budget,
) -> Result<String, ParseError<'i, ()>> {
    if depth > MAX_DEPTH {
        return Err(input.new_custom_error(()));
    }
    let mut out = String::new();
    let mut import = false;
    let mut namespace = false;
    loop {
        let start = input.position();
        let token = match input.next_including_whitespace_and_comments() {
            Ok(token) => token.clone(),
            Err(error) if error.kind == cssparser::BasicParseErrorKind::EndOfInput => break,
            Err(error) => return Err(error.into()),
        };
        budget.tokens += 1;
        if budget.tokens > MAX_TOKENS || token.is_parse_error() {
            return Err(input.new_custom_error(()));
        }
        let raw = input.slice_from(start).to_owned();
        if matches!(&token, Token::QuotedString(_)) && !quoted_closed(&raw) {
            return Err(input.new_custom_error(()));
        }
        // Nested output has already consumed its shared budget. Charge only
        // its wrapper here, so all live rewritten prefixes share one cap.
        let mut nested_bytes = 0;
        let rewritten = match token {
            Token::WhiteSpace(_) => raw,
            Token::Comment(_) => {
                if !raw.ends_with("*/") {
                    return Err(input.new_custom_error(()));
                }
                raw
            }
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("import") => {
                import = true;
                raw
            }
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("namespace") => {
                namespace = true;
                raw
            }
            Token::Semicolon => {
                if import {
                    return Err(input.new_custom_error(()));
                }
                namespace = false;
                raw
            }
            Token::QuotedString(value) if import || image_strings => {
                import = false;
                resource(&value, base, route).map_err(|()| input.new_custom_error(()))?
            }
            Token::UnquotedUrl(value) => {
                if !raw.ends_with(')') {
                    return Err(input.new_custom_error(()));
                }
                import = false;
                let target = if namespace {
                    quote(&value)
                } else {
                    resource(&value, base, route)
                }
                .map_err(|()| input.new_custom_error(()))?;
                format!("url({target})")
            }
            Token::Function(name) if name.eq_ignore_ascii_case("url") => {
                import = false;
                let target = input.parse_nested_block(|nested| {
                    let begin = nested.position();
                    let value = nested.expect_string_cloned()?;
                    if !quoted_closed(nested.slice_from(begin).trim()) {
                        return Err(nested.new_custom_error(()));
                    }
                    nested.expect_exhausted()?;
                    (if namespace {
                        quote(&value)
                    } else {
                        resource(&value, base, route)
                    })
                    .map_err(|()| nested.new_custom_error(()))
                })?;
                if !input.slice_from(start).ends_with(')') {
                    return Err(input.new_custom_error(()));
                }
                format!("url({target})")
            }
            Token::Function(name) => {
                if import {
                    return Err(input.new_custom_error(()));
                }
                let images = name.eq_ignore_ascii_case("image-set")
                    || name.eq_ignore_ascii_case("-webkit-image-set");
                let body = input.parse_nested_block(|nested| {
                    walk(nested, base, route, depth + 1, images, budget)
                })?;
                if !input.slice_from(start).ends_with(')') {
                    return Err(input.new_custom_error(()));
                }
                nested_bytes = body.len();
                format!("{raw}{body})")
            }
            Token::ParenthesisBlock | Token::SquareBracketBlock | Token::CurlyBracketBlock => {
                if import {
                    return Err(input.new_custom_error(()));
                }
                let close = match token {
                    Token::ParenthesisBlock => ')',
                    Token::SquareBracketBlock => ']',
                    _ => '}',
                };
                let body = input.parse_nested_block(|nested| {
                    walk(nested, base, route, depth + 1, false, budget)
                })?;
                if !input.slice_from(start).ends_with(close) {
                    return Err(input.new_custom_error(()));
                }
                nested_bytes = body.len();
                format!("{raw}{body}{close}")
            }
            _ => {
                if import {
                    return Err(input.new_custom_error(()));
                }
                raw
            }
        };
        let added = rewritten.len() - nested_bytes;
        if added > MAX_ASSET_BYTES.saturating_sub(budget.output) {
            return Err(input.new_custom_error(()));
        }
        budget.output += added;
        if rewritten.len() > MAX_ASSET_BYTES.saturating_sub(out.len()) {
            return Err(input.new_custom_error(()));
        }
        out.push_str(&rewritten);
    }
    if import {
        return Err(input.new_custom_error(()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(css: &str) -> Result<String, Error> {
        let base = OctUrl::parse("oct://MiXeD/docs/index.html").unwrap();
        rewrite(css.as_bytes(), &base, &|url| {
            crate::render::gateway_route(Some("scope"), url)
        })
        .map(|b| String::from_utf8(b).unwrap())
    }
    #[test]
    fn relative_root_import_escaped_and_image_set_urls_are_pinned() {
        let output = run(r#"@import "../theme.css" screen; a {background:u\72l("image%20one.svg#rect"); src:url(/fonts/a.woff2); background-image:image-set("../a.png" 1x,url('../b.png') 2x)}"#).unwrap();
        for expected in [
            "/snapshots/scope/MiXeD/theme.css",
            "/snapshots/scope/MiXeD/docs/image%20one.svg#rect",
            "/snapshots/scope/MiXeD/fonts/a.woff2",
            "/snapshots/scope/MiXeD/a.png",
            "/snapshots/scope/MiXeD/b.png",
        ] {
            assert!(output.contains(expected), "{output}");
        }
        assert!(output.starts_with("@import "));
    }
    #[test]
    fn strings_namespaces_and_fragment_references_keep_their_meaning() {
        let output = run(r##"@namespace svg url("http://www.w3.org/2000/svg"); a{content:"literal url(unchanged)";clip-path:url("#mask");color:rgb(1, 2, 3)}"##).unwrap();
        assert!(output.contains("http://www.w3.org/2000/svg"));
        assert!(output.contains("literal url(unchanged)"));
        assert!(output.contains("url(\"#mask\")"));
        assert!(output.contains("rgb(1, 2, 3)"));
        let html_escape = run(r##"a{clip-path:url("#\3c /style>")} "##).unwrap();
        assert!(!html_escape.to_ascii_lowercase().contains("</style"));
        assert!(html_escape.contains("\\3C "));
    }
    #[test]
    fn external_cross_circle_executable_and_malformed_urls_are_refused() {
        for value in [
            r"a{background:url(https://evil.invalid/x)}",
            r#"@import "//evil.invalid/x";"#,
            r"a{background:url('oct://Other/x')}",
            r"a{background:url('javascript:alert(1)')}",
            r"a{background:url('data:image/png,x')}",
            r"a{background:url('%')}",
            r"a{background:url('x')",
            r"a{background:url('x) }",
            "a{background:url(x}",
            "/* missing end",
            "@import ;",
            r#"@import "x""#,
        ] {
            // A complete import operand without a final semicolon is valid CSS.
            if value == r#"@import "x""# {
                assert!(run(value).is_ok());
            } else {
                assert!(run(value).is_err(), "{value}");
            }
        }
    }
    #[test]
    fn nesting_token_input_and_output_budgets_are_bounded() {
        assert!(run(&format!("a{{x:{}1{}}}", "f(".repeat(66), ")".repeat(66))).is_err());
        assert!(run(&";".repeat(MAX_TOKENS + 1)).is_err());
        assert!(run(&" ".repeat(MAX_ASSET_BYTES + 1)).is_err());
        assert!(run(&format!("a{{x:{}}}", "url(a) ".repeat(300_000))).is_err());

        // Each level alone is below the cap, but their expanded prefixes must
        // not accumulate until the outermost concatenation rejects them.
        let prefix = "url(a) ".repeat(4096);
        let source = format!("{prefix}f({prefix}f({prefix}f({prefix})))");
        let mut input = ParserInput::new(&source);
        let mut parser = Parser::new(&mut input);
        let mut budget = Budget::default();
        let base = OctUrl::parse("oct://MiXeD/a.css").unwrap();
        assert!(walk(
            &mut parser,
            &base,
            &|_| "/".repeat(1024),
            0,
            false,
            &mut budget,
        )
        .is_err());
        assert!(budget.output <= MAX_ASSET_BYTES);
        assert!(
            budget.tokens < 20_000,
            "must stop before parsing all levels"
        );
    }
}
