# Homebrew formula for octravpn-node (validator-side daemon).
#
# Installs the launchd plist alongside the binary so `brew services start
# octravpn-node` works.

class OctravpnNode < Formula
  desc "OctraVPN validator-side node daemon"
  homepage "https://github.com/octra-labs/octravpn"
  url "https://github.com/octra-labs/octravpn/archive/refs/tags/v#{version}.tar.gz"
  sha256 "REPLACE_ME_AT_RELEASE_TIME"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/octra-labs/octravpn.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/octravpn-node")
    (etc/"octravpn").mkpath
    (var/"log").mkpath
  end

  service do
    run [opt_bin/"octravpn-node", "--config", etc/"octravpn/node.toml", "run"]
    keep_alive true
    run_type :immediate
    log_path var/"log/octravpn-node.log"
    error_log_path var/"log/octravpn-node.err.log"
  end

  test do
    output = shell_output("#{bin}/octravpn-node --help")
    assert_match "octravpn-node", output
  end
end
