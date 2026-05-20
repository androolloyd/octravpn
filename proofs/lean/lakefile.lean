import Lake
open Lake DSL

package octravpn where
  -- toolchain pinned in lean-toolchain
  leanOptions := #[⟨`pp.unicode.fun, true⟩, ⟨`autoImplicit, false⟩]

@[default_target]
lean_lib OctraVPN where
  roots := #[`OctraVPN]

@[default_target]
lean_lib OctraVPN_V2 where
  roots := #[`OctraVPN_V2]

@[default_target]
lean_lib OctraVPN_V3 where
  roots := #[`OctraVPN_V3]

@[default_target]
lean_lib OctraVPN_Rust where
  roots := #[`OctraVPN_Rust]

@[default_target]
lean_lib WireProtocol where
  roots := #[`WireProtocol]
