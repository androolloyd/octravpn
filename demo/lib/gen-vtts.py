#!/usr/bin/env python3
"""Generate narration for the current 23 demo tapes, using only the standard library.

Cues describe the commands and their qualification limits. Timing is drafted
from visible typing duration plus explicit Sleeps, excluding command runtime
and Enter latency. Align against fresh recordings before publishing narration.
Historical VTT files with other names are left untouched and never regenerated.
Tapes 02/16/21 use the checked-in demo/lib/negative-checks.py helper.

Run from the repository root. Use --output-dir to generate in a temporary
folder without changing tracked media.
"""

import argparse
from pathlib import Path


CUES = {'00-master-tour': [(0, 3, 'Recorded output, replayed as a trailer.'),
                    (3, 5.5, 'Deployment and policy captures.'),
                    (5.5, 8, 'Peer status and ping captures.'),
                    (8, 10.5, 'Audit output is replayed.'),
                    (10.5, 13, 'Asset fetch output follows.'),
                    (13, 16.5, 'Run segment tapes for live checks.')],
 '01-init-keygen': [(0, 7, 'Start a throwaway key-generation container.'),
                    (12, 20, 'Clear the scratch directory, then run client initialization.'),
                    (22, 27, 'List the generated files.'),
                    (28, 35, 'Generate a demonstration bond key and inspect the directory.'),
                    (36, 43, 'Identity prints a wallet address; it does not register it.'),
                    (43, 48, 'Remove the fixture; this tape transfers no funds.')],
 '02-portal-fetch': [(0,
                      8,
                      'Start the sealed-asset portal fixture against the configured public devnet.'),
                     (18, 26, 'RPC availability and the demo Circle are external dependencies.'),
                     (63, 73, 'Probe local health and resolve the fixture Circle ID.'),
                     (78, 88, 'Request the sealed policy using the demonstration passphrase.'),
                     (95, 105, 'Fetch headers, save the policy, and inspect the local file.'),
                     (108,
                      117,
                      'The sealed control requires a successful fetch, then exact decrypt exit five '
                      'with no plaintext.'),
                     (118, 123, 'Stop the portal fixture.')],
 '03-audit-replay': [(0, 8, 'Prepare eight synthetic audit records and an empty receipt journal.'),
                     (18, 27, 'Replay the fixture records in the terminal.'),
                     (32, 41, 'Request JSON output for the same synthetic records.'),
                     (45, 54, 'Run the HMAC verifier and inspect its result.'),
                     (55, 59, 'An empty journal does not exercise live receipt progression.'),
                     (59, 62, 'Remove the fixture.')],
 '04-mesh-preauth': [(0, 8, 'Start the local mesh fixture and admin endpoint.'),
                     (20, 28, 'This tape demonstrates minting; it does not redeem the new keys.'),
                     (124, 131, "Local minting creates a key outside the running daemon's store."),
                     (137, 146, 'Remote minting sends a request to the running daemon.'),
                     (151, 160, 'The reusable variant requests a twenty-four-hour lifetime.'),
                     (176,
                      186,
                      'Send the equivalent preauthorization request through the admin HTTP API.'),
                     (192, 198, 'Remove the fixture after inspecting the returned keys.')],
 '05-v3-smoke': [(0, 8, 'This tape runs the historical v3 contract lifecycle smoke.'),
                 (13, 21, 'It uses a configured devnet endpoint and a funded fixture wallet.'),
                 (35, 43, 'The script deploys main-v3 and submits Circle registration.'),
                 (60, 68, 'Tailnet and session calls use the historical v3 interface.'),
                 (85, 95, 'Claim and confirmation inputs are not proof of traffic delivery.'),
                 (110, 118, 'The replay compares a hash chain with contract state.'),
                 (140, 150, 'Inspect transaction checks, overclaim rejection, and anchor rotation.'),
                 (170,
                  180,
                  'This historical smoke does not qualify the current prepaid client or a Mainnet '
                  'launch.')],
 '06-tailscale-interop': [(0, 7, 'Stock Tailscale joins this local test control plane.'),
                          (10, 18, "Two containers use the fixture's preauthorization key."),
                          (30, 38, "Native Rust DERP shares the control server's HTTPS listener."),
                          (52, 60, 'Certificate setup is local to this Docker fixture.'),
                          (75, 84, 'The harness requests registration and waits for peer visibility.'),
                          (102, 110, 'Tailscale ping is the reachability check.'),
                          (130, 139, 'Read the final result; timing varies with container startup.'),
                          (161, 171, 'This mesh test does not purchase traffic or settle OCT.')],
 '07-headscale-cli': [(0, 8, 'Start the mesh fixture with its embedded admin CLI.'),
                      (20,
                       28,
                       'These commands manage control-plane users and keys, not traffic purchases.'),
                      (124, 134, 'Create Alice and inspect the command result.'),
                      (136, 144, 'List users before choosing the target user for a key.'),
                      (146, 155, "The key command requests user ID one; check that user's identity."),
                      (160, 168, 'List nodes registered with the fixture.'),
                      (169, 173, 'Remove the local mesh.')],
 '08-3node-mesh': [(0, 5, 'Start the three-peer fixture.'),
                   (7, 12, 'Native DERP shares the mesh control listener.'),
                   (13, 18, "Inspect peer one's view of the roster."),
                   (20, 26, 'Query machine status through the mounted admin API.'),
                   (28, 33, 'Mesh membership is separate from paid traffic admission.'),
                   (34, 40, 'Teardown ends this local interoperability fixture.')],
 '09-traffic-patterns': [(0, 8, 'Bring up the local three-peer mesh.'),
                         (11, 20, "Read peer two and peer three's assigned tailnet addresses."),
                         (25, 35, "Request peer one's ping to peer two and inspect the result."),
                         (39, 49, 'Repeat the ping toward peer three.'),
                         (56, 65, 'Start a fixed HTTP responder on peer two.'),
                         (67, 77, 'Send a GET through tailscale nc; this is peer traffic.'),
                         (79, 88, 'Read the admin policy; no paid settlement is exercised.'),
                         (91, 98, 'Remove the local mesh.')],
 '10-metrics-grafana': [(0, 7, 'Start the mesh and analytics containers.'),
                        (10, 16, 'Read Prometheus-format metrics.'),
                        (19, 25, 'Inspect the analytics health response.'),
                        (28, 35, 'Query session counts in one-minute buckets.'),
                        (39, 45, 'Query preauthorization counts in the same format.'),
                        (48, 57, 'The node metrics probe is optional and includes a fallback message.'),
                        (58,
                         64,
                         "This fixture's empty audit directory does not establish paid traffic "
                         'accounting.'),
                        (65, 69, 'Remove the fixture.')],
 '11-user-install-linux': [(0, 5, 'Linux instruction tour; installation is not performed here.'),
                           (5, 10, 'Package installation lines are shell comments.'),
                           (11, 15, "Only the installed client's version is queried."),
                           (16, 22, 'Login server and preauthorization examples remain comments.'),
                           (24, 29, "The next live command inspects the runner's existing status."),
                           (30, 34, 'Peer ping is an instruction, not an executed check.'),
                           (35, 39.5, 'The displayed pong is a comment, not reachability evidence.')],
 '12-user-install-macos': [(0, 5, 'macOS setup instructions; Homebrew commands are comments.'),
                           (7, 12, 'The App Store path is also a written instruction.'),
                           (13, 16, 'Version queries inspect the available CLI.'),
                           (17, 23, 'The example join command is not run.'),
                           (24, 28, "Status inspects the runner's current environment."),
                           (29, 33, 'The peer ping example remains commented out.'),
                           (33.5, 37.5, 'The pictured pong does not demonstrate a macOS connection.')],
 '13-user-ssh-peer': [(0, 7, 'The SSH fixture starts three stock Tailscale peers.'),
                      (16, 24, 'Traffic uses the local mesh; paid exit service is outside this test.'),
                      (122, 132, "Inspect peer one's roster and peer two's tailnet address."),
                      (143, 153, 'Dropbear and a temporary SSH key prepare the target.'),
                      (167, 177, "Copy the public key to peer two's authorized keys."),
                      (183, 193, "Read peer two's address for this fixture connection."),
                      (195, 205, 'SSH uses tailscale nc as its proxy; check for session_ok.'),
                      (211, 216, 'Teardown removes the fixture containers.')],
 '14-user-web-traffic': [(0, 7, 'Three peer containers form the local mesh fixture.'),
                         (20, 28, 'This tape exercises peer HTTP, not a paid internet exit.'),
                         (122, 130, "Read peer two's assigned tailnet address."),
                         (135, 145, 'A netcat loop prepares a fixed HTTP response on port 8080.'),
                         (150, 160, 'Send GET through tailscale nc and inspect the returned body.'),
                         (163, 173, 'Send HEAD over the same path and inspect the status line.'),
                         (174,
                          182,
                          'The exit-node section is commentary; it executes no internet traffic.'),
                         (183, 188, 'Remove the fixture after the peer HTTP requests.')],
 '15-user-oct-url-public': [(0, 8, 'Despite its filename, this is a sealed-asset portal CLI fixture.'),
                            (18, 26, 'It depends on the configured public devnet RPC and demo Circle.'),
                            (62, 72, "Probe local portal health and read the fixture's Circle ID."),
                            (79, 89, 'Request opening index.html with the demonstration passphrase.'),
                            (94, 102, 'Fetch CSS with response headers.'),
                            (105, 114, 'Fetch JSON with the same configured passphrase.'),
                            (120, 130, 'Write the binary asset and inspect the local file size.'),
                            (133,
                             139,
                             'Commands can mask errors; inspect their output before assuming success.')],
 '16-user-oct-url-sealed': [(0,
                             8,
                             'This terminal fixture requests sealed Circle assets from public devnet.'),
                            (18,
                             26,
                             'The passphrase is supplied by environment, not a browser interaction.'),
                            (63, 73, 'Probe portal health and read the Circle ID.'),
                            (77, 87, 'Fetch the sealed JSON asset and inspect the response.'),
                            (91,
                             101,
                             'open-url requests opening the same asset; no browser is recorded.'),
                            (104,
                             113,
                             'The negative control requires the same asset to decrypt with the correct '
                             'passphrase.'),
                            (114,
                             123,
                             'Wrong-passphrase success requires exact exit five, the decrypt '
                             'diagnostic, and no plaintext.'),
                            (124, 130, 'Teardown follows; this tape does not qualify paid traffic.')],
 '17-operator-onboarding': [(0, 8, 'This is the historical operator CLI against a mock RPC.'),
                            (18,
                             26,
                             'Container readiness is not public-chain deployment or paid-service '
                             'qualification.'),
                            (63, 73, "The key-sealing command uses the fixture's passphrase."),
                            (77, 87, 'Attempt a legacy bond of one billion OU in the mock environment.'),
                            (90, 99, 'Attempt endpoint registration; these commands can mask errors.'),
                            (103, 110, 'Inspect the running process list.'),
                            (113, 122, 'Run health checks and inspect the reported result.'),
                            (123, 128, 'Stop the mock stack.')],
 '18-tailnet-owner-policy': [(0, 6, 'Start the local three-peer control-plane fixture.'),
                             (8, 15, 'Write an example policy for traffic from Alice to Bob.'),
                             (16, 20, 'The rule is directional; it does not grant reverse traffic.'),
                             (22, 31, 'Run the embedded policy checker and inspect its output.'),
                             (33, 42, "Submit the policy through the fixture's admin HTTP API."),
                             (46, 54, 'Request the current policy; inspect any reported errors.'),
                             (58,
                              68,
                              'List nodes; this tape does not test packet-level policy enforcement.'),
                             (69, 74, 'Remove the mesh fixture.')],
 '19-circle-update-atomic': [(0, 8, 'Prepare Circle requests against the configured public devnet RPC.'),
                             (18,
                              26,
                              'Public RPC availability and write credentials determine whether requests '
                              'can succeed.'),
                             (63, 73, 'Read the demo Circle ID from the running container.'),
                             (79, 89, 'Write the replacement policy payload inside the fixture.'),
                             (95, 105, 'Dry-run describes the requested update without broadcasting.'),
                             (113,
                              123,
                              'Commit requests blob writes and the anchor update; inspect the result.'),
                             (132,
                              141,
                              'List orphan candidates; masked command exits do not prove an empty '
                              'result.'),
                             (143, 147, 'Remove the devnet fixture.')],
 '20-pvac-rotation': [(0, 8, 'Start the separate PVAC sidecar fixture.'),
                      (18, 26, 'This tape runs IPC operations; it does not submit a chain transaction.'),
                      (95, 105, 'The version probe has a fallback message, not a version assertion.'),
                      (112,
                       122,
                       'Send keygen a fixed demonstration seed and show a truncated response.'),
                      (132, 142, "Request the sidecar's AES known-answer test over JSON IPC."),
                      (144, 152, 'Broadcast and RPC-limit notes are comments, not executed checks.'),
                      (154, 159, 'Stop the sidecar fixture.')],
 '21-audit-verify': [(0, 8, 'Prepare eight synthetic audit records and an empty receipt journal.'),
                     (18,
                      26,
                      'Run the clean verifier, then modify only the first record while keeping valid '
                      'JSON.'),
                     (27, 34, 'Both verifications use the original HMAC key explicitly.'),
                     (35,
                      42,
                      'Require clean exit zero, then exact exit one and a line-one MAC mismatch.'),
                     (43,
                      49,
                      'Missing files, parse errors, and unexpected success cannot satisfy this negative '
                      'control.'),
                     (49.5, 52, 'Local audit checks do not prove delivery.')],
 '22-headscale-cli-tour': [(0, 7, 'Start the embedded Headscale CLI fixture.'),
                           (10, 18, 'Attempt user creation and request the user list.'),
                           (28, 37, "List nodes registered with the fixture's control plane."),
                           (40,
                            49,
                            'Request a reusable key for user ID one; verify which user that is.'),
                           (52, 60, 'The next key listing selects Alice by name.'),
                           (62, 71, 'Request the stored policy and inspect any reported errors.'),
                           (73,
                            82,
                            'Tailnet status is an attempted admin call, not a paid-service check.'),
                           (83, 88, 'Remove the fixture.')]}


def timestamp(seconds):
    total = round(seconds * 1000)
    hours, remainder = divmod(total, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    secs, millis = divmod(remainder, 1000)
    return f"{hours:02}:{minutes:02}:{secs:02}.{millis:03}"


def render_vtt(path, cues):
    if not 6 <= len(cues) <= 10:
        raise ValueError(f"{path.name}: expected six to ten short cues")
    lines = ["WEBVTT", ""]
    previous_end = 0
    for start, end, text in cues:
        if not (previous_end <= start < end and end - start <= 10):
            raise ValueError(f"{path.name}: overlapping/invalid cue timing")
        if not text or len(text) > 100 or any(char in text for char in "\r\n"):
            raise ValueError(f"{path.name}: invalid cue text")
        lines += [f"{timestamp(start)} --> {timestamp(end)}", f"narrator: {text}", ""]
        previous_end = end
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("demo/recordings"))
    parser.add_argument("--check", action="store_true", help="verify checked-in narration without writing files")
    args = parser.parse_args()
    current = {path.stem for path in Path("demo/tapes").glob("*.tape")}
    if current != set(CUES):
        raise ValueError(f"cue/tape names differ: {sorted(current.symmetric_difference(CUES))}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, cues in sorted(CUES.items()):
        path = args.output_dir / f"{name}.vtt"
        content = render_vtt(path, cues)
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                raise ValueError(f"{path.name}: narration differs from cue table")
        else:
            path.write_text(content, encoding="utf-8")
        print(f"{path.name}: {len(cues)} cues, last cue ends {cues[-1][1]:.1f}s")


if __name__ == "__main__":
    main()
