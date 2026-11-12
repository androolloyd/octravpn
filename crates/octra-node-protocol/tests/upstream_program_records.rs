use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    aml::{
        compiler::protocol,
        parser, scope,
        source::{self, Syntax},
    },
    contract,
    program_record::source::{Error, Sources},
    program_wire::Source,
};
use std::fmt::Write as _;
fn sources(body: &[u8], compiler: &[u8], loops: bool) -> Sources {
    Sources {
        main: b"main.aml".to_vec(),
        files: vec![Source {
            path: b"main.aml".to_vec(),
            body: body.to_vec(),
        }],
        compiler: compiler.to_vec(),
        loops,
    }
}
const BASIC:&[u8]=b"contract Record { state { n: int } constructor() { self.n = 0 } view fn read(): int { return self.n } }";
#[test]
fn canonical_source_record_roundtrip_and_code_binding() {
    let input = sources(BASIC, b"protocol", false);
    let encoded = STANDARD.encode(input.encode());
    assert_eq!(Sources::decode(encoded.as_bytes()).unwrap(), input);
    let (code, _) = input.compile(true).unwrap();
    let record = input.verify(true, false, &code).unwrap();
    assert_eq!(record.source, BASIC);
    octra_node_protocol::program_record::source::record_scope(&code, &record).unwrap();
    let mut damaged = code;
    damaged[0] ^= 1;
    assert!(input.verify(true, false, &damaged).is_err());
    let mut noncanonical = encoded.into_bytes();
    noncanonical.push(b'\n');
    assert!(Sources::decode(&noncanonical).is_err());
    let duplicate=STANDARD.encode(b"{\"main\":\"main.aml\",\"files\":[],\"compiler\":\"protocol\",\"loops\":false,\"loops\":false}");
    assert!(Sources::decode(duplicate.as_bytes()).is_err());
    assert!(sources(BASIC, b"historical", false).compile(true).is_err());
}
#[test]
fn scope_publication_rejects_escaped_locals() {
    let body = br"contract Scope { enum Choice { First } public fn run(): int {
        let kept = 1
        match Choice.First { Choice.First => { let kept = 2 } }
        let padding = 0
        let separate = 7
        kept = 9
        return separate
    } }";
    for (syntax, compiler) in [
        (Syntax::Source, b"source".as_slice()),
        (Syntax::Forms, b"forms"),
    ] {
        let old = source::compile(body, syntax, false).unwrap();
        let current = source::compile_metered(body, syntax, true, true).unwrap();
        assert_ne!(old.octb, current.octb);
        assert!(
            matches!(sources(body,compiler,false).verify(true,false,&old.octb),Err(Error::Invalid(reason)) if reason==b"program source scope differs")
        );
        sources(body, compiler, true)
            .verify(true, false, &current.octb)
            .unwrap();
    }
}
#[test]
fn inactive_limits_and_unused_constant_graph_remain_distinct() {
    let ast =
        parser::parse(b"contract C { const a: int = b const b: int = a fn f(): int { return 1 } }")
            .unwrap();
    assert_eq!(
        scope::check_consts(&ast).unwrap_err(),
        b"constant dependency is cyclic"
    );
    let mut text = String::from("contract Limit {");
    for index in 0..257 {
        write!(text, " fn f{index}(): int {{ return 1 }}").unwrap();
    }
    text.push('}');
    let old = protocol::compile(text.as_bytes(), protocol::Options::default()).unwrap();
    assert!(old.error.is_none(), "{:?}", old.error);
    let current = protocol::compile(
        text.as_bytes(),
        protocol::Options {
            metered: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        current.error.as_deref(),
        Some(b"Program function limit exceeded".as_slice())
    );
}
#[test]
fn vm_root_encoding_checks_entire_root() {
    let raw = [0xab; 32];
    assert_eq!(contract::tree_hash(&raw).unwrap(), raw);
    assert_eq!(
        contract::tree_hash("AB".repeat(32).as_bytes()).unwrap(),
        raw
    );
    let mut wide = "ab".repeat(64).into_bytes();
    assert_eq!(contract::tree_hash(&wide).unwrap(), raw);
    wide[127] = b'g';
    assert!(contract::tree_hash(&wide).is_err());
    assert!(contract::tree_hash(b"root").is_err());
}
