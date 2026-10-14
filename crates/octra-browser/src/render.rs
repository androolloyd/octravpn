//! HTML is rewritten by a bounded HTML5 parser and served in an opaque sandbox.
use crate::{url::encode_path, Error, OctUrl, MAX_ASSET_BYTES};
use lol_html::{element, HtmlRewriter, MemorySettings, Settings};

pub fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Absolute path on the local browser server, preserving native percent bytes.
pub fn route(prefix: &str, scope: &str, kind: &str, url: &OctUrl) -> String {
    let full = url.as_string();
    let suffix = full
        .strip_prefix(&format!("oct://{}", url.circle_id))
        .expect("Circle prefix");
    format!("{prefix}/{kind}/{scope}/{}{suffix}", url.circle_id)
}

pub fn rewrite_html(
    input: &[u8],
    base: &OctUrl,
    prefix: &str,
    scope: &str,
) -> Result<Vec<u8>, Error> {
    rewrite(input, base, false, |kind, url| {
        route(prefix, scope, kind, url)
    })
}

pub(crate) fn rewrite_app(
    input: &[u8],
    base: &OctUrl,
    prefix: &str,
    scope: &str,
) -> Result<Vec<u8>, Error> {
    rewrite(input, base, true, |kind, url| {
        route(prefix, scope, kind, url)
    })
}

pub(crate) fn gateway_route(scope: Option<&str>, url: &OctUrl) -> String {
    let suffix = url.as_string();
    let suffix = suffix.strip_prefix("oct://").expect("Circle URL");
    scope.map_or_else(
        || format!("/circles/{suffix}"),
        |scope| format!("/snapshots/{scope}/{suffix}"),
    )
}

pub(crate) fn rewrite_gateway(input: &[u8], base: &OctUrl, scope: &str) -> Result<Vec<u8>, Error> {
    rewrite(input, base, false, |kind, url| {
        gateway_route((kind == "asset").then_some(scope), url)
    })
}

fn rewrite(
    input: &[u8],
    base: &OctUrl,
    executable: bool,
    route: impl Fn(&str, &OctUrl) -> String,
) -> Result<Vec<u8>, Error> {
    if input.len() > MAX_ASSET_BYTES {
        return Err(Error::TooLarge);
    }
    let html =
        std::str::from_utf8(input).map_err(|_| Error::Invalid("HTML is not valid UTF-8".into()))?;
    let mut output = Vec::new();
    if executable {
        output.extend_from_slice(b"<!doctype html><meta charset=utf-8><script>");
        output.extend_from_slice(include_bytes!("sdk.js"));
        output.extend_from_slice(b"</script>");
    }
    let mut overflow = false;
    let settings = Settings::new()
        .with_memory_settings(
            MemorySettings::default().with_max_allowed_memory_usage(MAX_ASSET_BYTES),
        )
        .append_element_content_handler(element!("*", |el| {
            let tag = el.tag_name();
            if matches!(
                tag.as_str(),
                "base" | "iframe" | "frame" | "frameset" | "object" | "embed" | "portal"
            ) || tag == "script" && !executable
            {
                el.remove();
                return Ok(());
            }
            if tag == "meta"
                && (el.get_attribute("http-equiv").is_some()
                    || el.get_attribute("charset").is_some())
            {
                el.remove();
                return Ok(());
            }
            // Form submission stays disabled. Executable pages use the separate
            // host intent interface, with no same-origin privilege or network API.
            let names = el
                .attributes()
                .iter()
                .map(lol_html::html_content::Attribute::name)
                .collect::<Vec<_>>();
            for name in names {
                if name.starts_with("on") && !executable
                    || matches!(
                        name.as_str(),
                        "srcdoc"
                            | "srcset"
                            | "ping"
                            | "action"
                            | "formaction"
                            | "target"
                            | "formtarget"
                            | "download"
                            | "autofocus"
                    )
                {
                    el.remove_attribute(&name);
                }
            }
            for name in ["href", "src", "poster", "background", "xlink:href"] {
                let Some(value) = el.get_attribute(name) else {
                    continue;
                };
                let navigation = matches!(tag.as_str(), "a" | "area") && name == "href";
                let local_fragment = value.starts_with('#');
                match base.resolve(&value) {
                    Ok(target) if navigation => {
                        if local_fragment {
                            el.set_attribute(
                                name,
                                &format!("#{}", target.fragment.as_deref().unwrap_or_default()),
                            )?;
                        } else {
                            el.set_attribute(name, &route("view", &target))?;
                            el.set_attribute("target", "_top")?;
                            el.set_attribute("rel", "noreferrer noopener")?;
                            if executable {
                                el.set_attribute("data-octra-navigation", "true")?;
                            }
                        }
                    }
                    Ok(target) if target.circle_id == base.circle_id => {
                        el.set_attribute(name, &route("asset", &target))?;
                    }
                    _ => el.remove_attribute(name),
                }
            }
            if tag == "link"
                && !el
                    .get_attribute("rel")
                    .is_some_and(|r| r.eq_ignore_ascii_case("stylesheet"))
            {
                el.remove();
            }
            Ok(())
        }));
    let mut rewriter = HtmlRewriter::new(settings, |chunk: &[u8]| {
        if chunk.len() > MAX_ASSET_BYTES.saturating_sub(output.len()) {
            overflow = true;
        } else if !overflow {
            output.extend_from_slice(chunk);
        }
    });
    rewriter
        .write(html.as_bytes())
        .map_err(|_| Error::Invalid("HTML rewrite refused".into()))?;
    rewriter
        .end()
        .map_err(|_| Error::Invalid("HTML rewrite refused".into()))?;
    if overflow {
        return Err(Error::TooLarge);
    }
    Ok(output)
}

/// CSP resource sources include only this Circle and this snapshot. No scripts,
/// network APIs, nested frames, form submission, or same-origin privileges.
pub fn asset_csp(origin: &str, prefix: &str, scope: &str, circle: &str) -> String {
    let source = format!("{origin}{prefix}/asset/{scope}/{}/", encode_path(circle));
    public_asset_csp(&source)
}

pub(crate) fn public_asset_csp(source: &str) -> String {
    format!("default-src 'none'; script-src 'none'; style-src 'unsafe-inline' {source}; img-src {source}; font-src {source}; media-src {source}; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; sandbox allow-top-navigation-by-user-activation")
}

pub(crate) fn app_csp(origin: &str, prefix: &str, scope: &str, circle: &str) -> String {
    let source = format!("{origin}{prefix}/asset/{scope}/{}/", encode_path(circle));
    // No same-origin, top navigation, popups, forms, fetch, workers or frames.
    // Navigation goes through the shell, which requires browser user activation.
    format!("default-src 'none'; script-src 'unsafe-inline' {source}; style-src 'unsafe-inline' {source}; img-src {source}; font-src {source}; media-src {source}; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; sandbox allow-scripts")
}
