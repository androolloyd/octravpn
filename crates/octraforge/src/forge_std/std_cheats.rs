//! Composite convenience cheats from `StdCheats`.
//!
//! These wrap multiple low-level cheats into one ergonomic call.
//! Foundry analogues:
//!   - `hoax(addr)` = `deal(addr, 1 ether)` + `prank(addr)`
//!   - `hoax(addr, balance)` = `deal(addr, balance)` + `prank(addr)`
//!   - `makeAddr("label")` = create labeled wallet, return address

use octravpn_core::address::Address;

use crate::{wallet::Wallet, ForgeCtx};

impl ForgeCtx {
    /// Deal a default 1 OCT balance to `addr` and prank as `addr` once.
    pub fn hoax(&mut self, addr: impl Into<String> + AsRef<str>) {
        let s = addr.into();
        self.deal(&s, 1_000_000); // 1 OCT in OU (6 decimals)
        self.prank(s);
    }

    /// Deal `balance` to `addr` and prank as `addr` once.
    pub fn hoax_with(&mut self, addr: impl Into<String> + AsRef<str>, balance: u64) {
        let s = addr.into();
        self.deal(&s, balance);
        self.prank(s);
    }

    /// Generate a labeled address. The keypair is discarded — call
    /// `make_wallet` if you need it.
    pub fn make_addr(&mut self, label: impl Into<String>) -> Address {
        let label = label.into();
        let (w, _kp) = Wallet::create_labeled(&label);
        let addr_str = w.address.display().to_string();
        self.label(addr_str, label);
        w.address
    }

    /// Generate a labeled wallet (address + keypair).
    pub fn make_wallet(&mut self, label: impl Into<String>) -> Wallet {
        let label_s = label.into();
        let (w, _kp) = Wallet::create_labeled(&label_s);
        self.label(w.address.display().to_string(), label_s);
        w
    }
}
