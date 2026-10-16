// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Shared native P2p_conn / gRPC listener retry policy.
use std::time::Duration;
pub fn delay(attempt: u32, error: &std::io::Error) -> Option<Duration> {
    use rustix::io::Errno as E;
    let code = error.raw_os_error()?;
    let retry = [
        E::INTR,
        E::AGAIN,
        E::CONNABORTED,
        E::NETDOWN,
        E::NETUNREACH,
        E::HOSTDOWN,
        E::HOSTUNREACH,
        E::NOPROTOOPT,
        E::OPNOTSUPP,
        E::MFILE,
        E::NFILE,
        E::NOBUFS,
        E::NOMEM,
        E::PROTO,
    ]
    .iter()
    .any(|error| error.raw_os_error() == code);
    #[cfg(target_os = "linux")]
    let retry = retry || code == E::NONET.raw_os_error();
    retry.then(|| Duration::from_secs_f64((0.01 * f64::from(1_u32 << attempt.min(7))).min(1.0)))
}
