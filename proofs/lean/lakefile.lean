import Lake
open Lake DSL

package octravpn where
  -- toolchain pinned in lean-toolchain
  leanOptions := #[⟨`pp.unicode.fun, true⟩, ⟨`autoImplicit, false⟩]

@[default_target]
lean_lib OctraVPN where
  roots := #[`OctraVPN]
