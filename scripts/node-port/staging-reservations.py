"""Off-chain staging correction: refresh reservations against canonical balance."""
from pathlib import Path

SOURCE = 'lib/core/tx_staging.ml'
BEFORE = '''  end else if Hashtbl.mem virtual_balances addr
              && Hashtbl.mem virtual_nonces addr then
    Ok ()
  else
    Error "staging sender state is inconsistent"'''
AFTER = '''  end else if Hashtbl.mem virtual_balances addr
              && Hashtbl.mem virtual_nonces addr then begin
    let balance = match lookup addr with
      | Some (balance, _) -> balance | None -> Z.zero in
    let reserved = sender_entries addr
      |> List.fold_left (fun total entry ->
        Z.add total (public_balance_cost entry.tx)) Z.zero in
    Hashtbl.replace virtual_balances addr (Z.sub balance reserved);
    Ok ()
  end else
    Error "staging sender state is inconsistent"'''
REPLACEMENTS = {SOURCE: [{'before': BEFORE, 'after': AFTER,
    'purpose': 'Refresh pending reservations after canonical account changes; execution and consensus unchanged.'}]}

def apply(root):
    path = Path(root) / SOURCE
    source = path.read_text()
    if source.count(AFTER) == 1:
        return
    if source.count(BEFORE) != 1:
        raise RuntimeError('upstream staging reservation patch drift')
    path.write_text(source.replace(BEFORE, AFTER))

if __name__ == '__main__':
    apply('.')
