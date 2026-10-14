"""Retain the existing Single-mode canonical-order bug fix on either pinned layout."""
from pathlib import Path

path = Path("node_runtime/consensus_epoch_apply_source.ml")
source = path.read_text()
variants = [
    ("  | None -> selected deps.rules ~epoch:request.epoch_id (deps.staging_txs ()) []",
     "  | None ->\n    let txs = Transaction.consensus_order (deps.staging_txs ()) in\n    selected deps.rules ~epoch:request.epoch_id txs []"),
    ("""    let txs = deps.staging_txs () |> List.filter (fun tx ->
      Result.is_ok (Octra_core.Tx_envelope.check_rule deps.rules
        ~epoch:request.epoch_id [tx])) in""",
     """    let txs = deps.staging_txs () |> List.filter (fun tx ->
      Result.is_ok (Octra_core.Tx_envelope.check_rule deps.rules
        ~epoch:request.epoch_id [tx])) |> Transaction.consensus_order in"""),
]
for old, new in variants:
    if source.count(old) == 1:
        path.write_text(source.replace(old, new))
        print("Single staging canonical-order patch applied")
        break
    if source.count(new) == 1:
        print("Single staging is already canonical")
        break
else:
    raise SystemExit("upstream staging-order patch drift")
