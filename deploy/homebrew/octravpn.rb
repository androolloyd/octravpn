# Homebrew formula template for OctraVPN.
#
# Publish at homebrew-tap repo as `Formula/octravpn.rb`.
#
# Install:
#   brew tap octra-labs/octravpn
#   brew install octravpn          # client only
#   brew install octravpn-node     # node + service

class Octravpn < Formula
  desc "OctraVPN client — decentralized VPN on Octra"
  homepage "https://github.com/octra-labs/octravpn"
  url "https://github.com/octra-labs/octravpn/archive/refs/tags/v#{version}.tar.gz"
  # The actual sha256 + version are filled in by the release workflow.
  sha256 "REPLACE_ME_AT_RELEASE_TIME"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/octra-labs/octravpn.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/octravpn-client")
  end

  test do
    output = shell_output("#{bin}/octravpn --help")
    assert_match "OctraVPN client", output
  end
end
