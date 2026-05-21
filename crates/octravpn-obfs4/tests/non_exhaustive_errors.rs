//! Forward-compat enforcement for public `#[non_exhaustive]` error
//! enums in `octravpn-obfs4`.

#![allow(clippy::needless_pass_by_value)] // intentional: matching consumes the value

use octravpn_obfs4::{FrameError, HandshakeError};

#[deny(unreachable_patterns)]
#[test]
fn public_error_enums_are_non_exhaustive() {
    fn check_handshake(e: HandshakeError) -> &'static str {
        match e {
            HandshakeError::TooShort(_) => "short",
            HandshakeError::BadMac => "mac",
            HandshakeError::BadAuth => "auth",
            _ => "future",
        }
    }
    assert_eq!(check_handshake(HandshakeError::BadMac), "mac");

    fn check_frame(e: FrameError) -> &'static str {
        match e {
            FrameError::Incomplete { .. } => "inc",
            FrameError::BadTag => "tag",
            FrameError::BadInnerLen { .. } => "inner",
            FrameError::PayloadTooLarge(_) => "big",
            _ => "future",
        }
    }
    assert_eq!(check_frame(FrameError::BadTag), "tag");
}
