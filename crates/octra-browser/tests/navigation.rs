use octra_browser::OctUrl;
#[test]
fn relative_navigation_preserves_query_fragment_and_literal_percent_bytes() {
    let base = OctUrl::parse("oct://Circle/docs/index.html?mode=one#part").unwrap();
    for (reference, expected) in [
        ("../about?mode=two#next", "oct://Circle/about?mode=two#next"),
        ("#next", "oct://Circle/docs/index.html?mode=one#next"),
        ("?mode=two", "oct://Circle/docs/index.html?mode=two"),
        ("images/a%252Fb.svg", "oct://Circle/docs/images/a%252Fb.svg"),
        (".", "oct://Circle/docs/"),
        ("..", "oct://Circle/"),
        ("oct://Other/page#section", "oct://Other/page#section"),
    ] {
        assert_eq!(
            base.resolve(reference).unwrap().as_string(),
            expected,
            "{reference}"
        );
    }
    assert_eq!(
        base.resolve(".")
            .unwrap()
            .resolve("style.css")
            .unwrap()
            .path,
        "/docs/style.css"
    );
    assert!(OctUrl::parse("oct://Circle/docs%2F")
        .unwrap()
        .is_directory());
    assert_eq!(
        OctUrl::parse("oct://Circle/docs/.")
            .unwrap()
            .resolve("style.css")
            .unwrap()
            .path,
        "/docs/style.css"
    );
    assert_eq!(
        base.path_key(),
        OctUrl::parse("oct://Circle/docs/index.html?other")
            .unwrap()
            .path_key()
    );
}
#[test]
fn browser_authority_traversal_and_external_urls_are_refused() {
    for raw in [
        "https://circle/path",
        "oct://a@b/x",
        "oct://a:80/x",
        "oct://a/../x",
        "oct://a/%2e%2e",
        "oct://a/%00",
        "oct://a/%ff",
        "oct://a/\\foo",
        "oct://a/?x\r\n",
    ] {
        assert!(OctUrl::parse(raw).is_err(), "{raw:?}");
    }
    let base = OctUrl::parse("oct://a/").unwrap();
    for raw in [
        "//external/path",
        "http://external/path",
        "javascript:alert(1)",
        "data:text/html,hello",
        "/\\external",
        "bad\nurl",
    ] {
        assert!(base.resolve(raw).is_err(), "{raw:?}");
    }
    assert!(base.resolve(&"x".repeat(16385)).is_err());
}
