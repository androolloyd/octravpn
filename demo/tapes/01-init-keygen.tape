# 01-init-keygen.tape
#
# Captures the cold-start operator flow: a fresh directory, an `octravpn
# init` that writes a config.toml + wallet key, and a follow-up
# `octravpn keygen` that mints an extra key for the operator's bond
# wallet.
#
# REQUIRES:
#   - `octravpn` on PATH or built into ./target/{release,debug}/.
#     The tape runs the binary literally — we do not source any helper.
#   - A writable scratch dir at /tmp/octravpn-demo.
#
# Re-run with: vhs demo/tapes/01-init-keygen.tape

Output demo/recordings/01-init-keygen.gif
Output demo/recordings/01-init-keygen.mp4

Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "rm -rf /tmp/octravpn-demo && mkdir -p /tmp/octravpn-demo && cd /tmp/octravpn-demo"
Enter
Sleep 500ms

Type "octravpn init --dir ."
Enter
Sleep 2s

Type "ls -la"
Enter
Sleep 1500ms

Type "octravpn keygen --out ./bond.key"
Enter
Sleep 2s

Type "ls -la"
Enter
Sleep 1500ms

Type "octravpn --config ./config.toml identity"
Enter
Sleep 2s
