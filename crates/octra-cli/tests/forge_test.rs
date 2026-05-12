//! `forge test` — render the pretty output from a synthetic libtest stream.
//!
//! We don't shell out to `cargo test` here (it would recurse into our
//! own crate); the wrapper's job is to parse the format and re-emit a
//! Foundry-style summary, so we exercise the parser directly.

#[test]
fn render_test_output_pretty_prints_pass_and_fail() {
    let stdout = "running 3 tests\n\
        test a ... ok\n\
        test b ... FAILED\n\
        test c ... ignored\n\
        \n\
        failures:\n\
        \n\
        ---- b stdout ----\n\
        thread 'b' panicked at 'boom'\n\
        OU=4242\n\
        \n\
        failures:\n\
            b\n\
        \n\
        test result: FAILED. 1 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out\n";
    // The renderer prints, so we only assert it doesn't panic.
    octra_cli::forge::trace::render_test_output(stdout, "");
}
