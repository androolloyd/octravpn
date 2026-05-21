# 12-user-install-macos.tape
#
# INTENTIONALLY FAKED — see demo-realize PR notes. macOS install paths
# (Homebrew / App Store / Network Extension load) cannot be exercised
# from Linux CI and require GUI interaction on a Mac. The fake
# narration below is the contract this tape ships; the corresponding
# live flow lives in tape 08 (3-node docker mesh) for the headless
# CLI shape.
#
# Captures the macOS end-user's join flow. Two install paths:
#  (a) Homebrew + the CLI-only tailscale package (preferred for
#      headless macOS hosts and the demo's CI runner).
#  (b) The Tailscale.app from the App Store (one-line narration; the
#      tape stays in the terminal).
#
# Steady-state shape mirrors tape 11 — `tailscale up --login-server`
# against the operator's control plane, `tailscale status`, `tailscale
# ping`. CLI shape only; no Docker.
#
# REQUIRES:
#   - `tailscale` on PATH (brew formula `tailscale` provides it).
#
# Re-run with: vhs demo/tapes/12-user-install-macos.tape

Output demo/recordings/12-user-install-macos.gif
Output demo/recordings/12-user-install-macos.mp4

Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "# Path A — Homebrew CLI (headless / scriptable):"
Enter
Type "# $ brew install tailscale"
Enter
Type "# $ sudo brew services start tailscale"
Enter
Sleep 2s

Type "# Path B — Tailscale.app from the App Store (GUI):"
Enter
Type "# Install, launch once to load the Network Extension, then drive from CLI."
Enter
Sleep 2s

Type "tailscale version"
Enter
Sleep 2s

Type "# Join the operator's tailnet (preauth key from the operator):"
Enter
Type "# $ sudo tailscale up --login-server https://mesh.example.octra --authkey tskey-..."
Enter
Sleep 3s

Type "tailscale status"
Enter
Sleep 3s

Type "# Magic DNS gives us peer hostnames out of the box:"
Enter
Type "# $ tailscale ping peer-2"
Enter
Sleep 2s
Type "# pong from peer-2 (100.64.0.2) via direct in 9ms"
Enter
Sleep 2s
