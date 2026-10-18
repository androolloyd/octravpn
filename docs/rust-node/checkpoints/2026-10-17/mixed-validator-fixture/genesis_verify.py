"""Independent bounded fixture genesis, OCE1/QC and cold SQLite checks.

Only the explicit four-validator, unweighted, Prior-application test profile is
accepted. Native/Rust execution remains responsible for all state transitions.
"""
import base64
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import struct


def require(value, message):
    if not value:
        raise RuntimeError(message)


def pairs(rows):
    value = {}
    for key, item in rows:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'nonfinite JSON'))


def load(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024 * 1024,
            'invalid bounded input')
    return decode(path.read_bytes())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def b64(raw):
    return base64.b64decode(raw, validate=True)


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def bytes32(value):
    require(type(value) is list and len(value) == 32
            and all(type(x) is int and 0 <= x <= 255 for x in value), 'expected exact serialized StateRoot')
    return bytes(value)


def genesis_root(genesis):
    require(set(genesis['chain']) == {'chain_id', 'genesis_root'}, 'only actual Rust Genesis shape accepted')
    return bytes32(genesis['chain']['genesis_root']).hex()


def address(public):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    raw = hashlib.sha256(public).digest()
    number, output = int.from_bytes(raw, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        output = alphabet[digit] + output
    output = '1' * (len(raw) - len(raw.lstrip(b'\0'))) + output
    return 'oct' + output.rjust(44, '1')


def verify_configs(directory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    directory = Path(directory)
    genesis = load(directory / 'genesis.json')
    require(genesis.get('activated_applications') is False
            and genesis['chain']['chain_id'].startswith('octra-rust-local-')
            and type(genesis['time']) in [int, float] and math.isfinite(genesis['time'])
            and len(genesis['validators']) == 4, 'only explicit private default devnet profile accepted')
    validators, configs = {}, []
    for index, encoded in enumerate(genesis['validators']):
        addr, public = encoded.split(':')
        public = b64(public)
        require(len(public) == 32 and address(public) == addr and addr not in validators, 'invalid validator authority')
        validators[addr] = public
        config = load(directory / f'node-{index}' / 'config.json')
        require(config['genesis'] == genesis and config['voting'] is True
                and config['compute_provider'] is False
                and all(config.get(k) is None for k in ['vpn', 'payments', 'mesh', 'gateway']),
                'fixture must preserve actual default devnet configuration')
        key = Path(config['key'])
        require(key.is_file() and not key.is_symlink() and key.stat().st_mode & 0o077 == 0,
                'private key ownership differs')
        raw = key.read_bytes()
        require(len(raw) == 32, 'private key format differs')
        derived = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        require(derived == public, 'validator key does not match actual genesis authority')
        for field in ['p2p', 'rpc', 'browser', 'control', 'tunnel']:
            require(config[field].startswith('127.0.0.1:'), 'fixture address must remain loopback')
        configs.append(config)
    require(len(set(validators.values())) == 4, 'duplicate public key')
    faucet = directory / 'faucet.key'
    require(faucet.is_file() and not faucet.is_symlink() and faucet.stat().st_mode & 0o077 == 0,
            'private faucet ownership differs')
    faucet_raw = faucet.read_bytes()
    require(len(faucet_raw) == 32, 'private faucet format differs')
    funded = Ed25519PrivateKey.from_private_bytes(faucet_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    require(funded == b64(genesis['funded_public']), 'faucet authority differs from funded genesis account')
    return genesis, configs, validators


def framed(value):
    return str(len(value)).encode() + b':' + value + b'\n'


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def tree_hash(leaves):
    root = {}
    for path, value in leaves.items():
        node = root
        for step in path[:-1]:
            node = node.setdefault(step, {})
            require(type(node) is dict, 'tree/contents overlap')
        require(path[-1] not in node, 'duplicate leaf')
        node[path[-1]] = value

    def digest(node):
        if type(node) is bytes:
            return hashlib.blake2b(b'B' + node).digest()
        require(len(node) <= 256, 'fixture verifier supports flat small directories only')
        image = bytearray(b'N' + varint(len(node)))
        for name in sorted(node, reverse=True):
            value = node[name]
            image.extend(bytes([0 if type(value) is dict else 1]) + varint(len(name)) + name + digest(value))
        return hashlib.blake2b(image).digest()
    return digest(root).hex()


def expected_leaves(genesis):
    commitment = dict(chain_id=genesis['chain']['chain_id'], time=genesis['time'], validators=genesis['validators'],
        profile='devnet_full_v1', proposal_activation=2, receipts_activation=0,
        upstream='7f9be4489870645cfcc95439638cde40f5da9f50')
    commitment = {key: commitment[key] for key in sorted(commitment)}
    account = dict(balance='100000000000', nonce=0, public_key=genesis['funded_public'],
                   encrypted_balance=None, decrypt_allowance='0')
    path = hashlib.sha256(b'octra:asset_path:v1\0' + struct.pack('>I', 11) + b'/index.html').hexdigest()
    body = b'<!doctype html><html><meta charset=utf-8><title>Octra Rust devnet</title><h1>Octra Rust devnet</h1><p>This Circle asset is served from the committed state of your local Rust node.</p><p>VPN escrow is not configured on this development chain.</p></html>'
    meta = dict(path_key=path, canonical_path='/index.html', content_type='text/html', encoding='identity',
        size_bytes=str(len(body)), blob_hash=hashlib.sha256(body).hexdigest(), body_mode='public_resources',
        plaintext_hash=None, key_id=None, padding_class=None, resource_key=path, locator_mode='path',
        slot_ref=None, activate_after_epoch=None, expire_after_epoch=None, metadata_mode='reveal')
    circle = genesis['circle'].encode()
    return {(b'meta', b'local_devnet'): compact(commitment), (b'meta', b'last_epoch'): b'0',
        (b'meta', b'emission_remaining'): b'0', (b'meta', b'total_supply'): b'100000000000',
        (b'accounts', address(b64(genesis['funded_public'])).encode(), b'data'): compact(account),
        (b'circles', circle, b'browser', b'mode'): b'gateway_allowed',
        (b'circles', circle, b'resources', b'mode'): b'public_resources',
        (b'circles', circle, b'assets', b'by_hash', path.encode(), b'meta'): compact(meta),
        (b'circles', circle, b'assets', b'by_hash', path.encode(), b'body_b64'): base64.b64encode(body)}


def verify_genesis_proof(genesis, proof):
    expected = expected_leaves(genesis)
    actual = {}
    for row in proof['leaves']:
        path = tuple(b64(step) for step in row['path'])
        require(path not in actual, 'duplicate native genesis path')
        actual[path] = b64(row['value'])
    require(actual == expected, 'independent native/Rust genesis leaves differ')
    ledger = tree_hash(expected)
    epoch_hash = hashlib.sha256(framed(b'octra:eic:epoch:v1') + b'0\n0\n').hexdigest()
    index = hashlib.sha256(framed(b'octra:eic:root:v1')
        + framed(hashlib.sha256(b'octra:eic:genesis:v1').hexdigest().encode()) + framed(epoch_hash.encode())).hexdigest()
    # Native EIC.root_hex takes the first64 hex characters of a longer
    # storage-root string; retain the full Blake2b512 ledger hash separately.
    folded = hashlib.sha256(framed(b'octra:eic:state-root:v1')
        + framed(ledger[:64].encode()) + framed(index[:64].encode())).hexdigest()
    require(proof['ledger_root'] == ledger and proof['epoch_index_root'] == index
            and proof['folded_root'] == folded == genesis_root(genesis), 'independent native/Rust genesis commitment differs')
    return {'leaf_count': len(actual), 'ledger_root': ledger, 'epoch_index_root': index, 'folded_root': folded}


class Reader:
    def __init__(self, raw):
        require(len(raw) <= 32 * 1024 * 1024, 'oversized OCE1')
        self.raw, self.at = raw, 0

    def take(self, size):
        require(0 <= size <= len(self.raw) - self.at, 'truncated OCE1')
        value = self.raw[self.at:self.at + size]
        self.at += size
        return value

    def integer(self, size):
        return int.from_bytes(self.take(size), 'big')

    def string(self, limit):
        size = self.integer(4)
        require(size <= limit, 'oversized OCE1 field')
        return self.take(size)

    def finish(self):
        require(self.at == len(self.raw), 'OCE1 trailing bytes')


def domain_hash(domain, value):
    return hashlib.sha256(domain + b'\0' + value).digest()


def header_transaction_root(hashes):
    # ACTIVE Consensus_proposal.tx_list_hash / C_engine.tx_list_hash_for_header:
    # Hash_domain.hash("octra:tx_list:v1", concatenated lowercase HEX).
    # The generic C_hash.tx_list_hash OCE1-list API is a separate function.
    require(type(hashes) is list and all(type(value) is str and len(value) == 64
            and value == value.lower() and len(bytes.fromhex(value)) == 32 for value in hashes),
            'noncanonical fixture transaction hash')
    return domain_hash(b'octra:tx_list:v1', ''.join(hashes).encode('ascii')).hex()


def verify_certificate(raw, validators, chain, with_parent=True):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    r = Reader(raw)
    chain_raw, epoch, round_ = r.string(128), r.integer(8), r.integer(4)
    start = r.at
    version = r.integer(2)
    require(version in [3, 4] and 0 <= round_ <= 1_000_000, 'unsupported fixture certificate')
    header_chain, header_epoch = r.string(128), r.integer(8)
    previous, txlist, receipts, state = [r.take(32) for _ in range(4)]
    parent_hash = r.take(32) if version == 4 else bytes(32)
    creator, txid = r.string(128).decode(), r.integer(8)
    timestamp = struct.unpack('>d', r.take(8))[0]
    header_raw = raw[start:r.at]
    proposal = r.take(32)
    require(chain_raw == header_chain == chain.encode() and epoch == header_epoch
            and creator in validators and math.isfinite(timestamp) and timestamp > 0
            and proposal == domain_hash(b'octra:epoch_proposal_id:v' + str(version).encode(), header_raw),
            'certificate header/proposal binding differs')
    count = r.integer(4)
    require(3 <= count <= 4, 'four-validator quorum absent')
    signers = []
    for _ in range(count):
        vote_start = r.at
        vote_chain, vote_epoch, vote_round, kind, voted = r.string(128), r.integer(8), r.integer(4), r.integer(1), r.take(32)
        signed_raw = raw[vote_start:r.at]
        signer, signature = r.string(128).decode(), r.string(64)
        require(signer in validators and signer not in signers and len(signature) == 64
                and (vote_chain, vote_epoch, vote_round, kind, voted) == (chain_raw, epoch, round_, 2, proposal),
                'invalid/duplicate precommit identity')
        Ed25519PublicKey.from_public_bytes(validators[signer]).verify(signature, domain_hash(b'octra:vote:v2', signed_raw))
        signers.append(signer)
    parent = None
    if with_parent and version == 4:
        present = r.integer(1)
        require(present == 1, 'v4 authenticated parent absent')
        parent_raw = r.string(20 * 1024 * 1024)
        require(domain_hash(b'octra:parent_commit:v1', parent_raw) == parent_hash, 'parent commitment differs')
        pr = Reader(parent_raw)
        cert, authority = pr.string(16 * 1024 * 1024), pr.string(4 * 1024 * 1024)
        pr.finish()
        parent = verify_certificate(cert, validators, chain, False)
        require(parent['epoch'] + 1 == epoch and parent['state_root'] == previous.hex()
                and parent['signers'] == sorted(parent['signers']), 'parent QC is not canonical/consecutive')
        vr = Reader(authority)
        require(vr.integer(1) == 0 and vr.integer(4) == 4, 'unexpected fixture validator policy')
        actual = {}
        for _ in range(4):
            addr, key, weight = vr.string(128).decode(), vr.string(32), vr.string(256)
            require(addr not in actual and weight == b'1', 'duplicate/weighted fixture authority')
            actual[addr] = key
        vr.finish()
        require(actual == validators, 'parent validator authority differs')
    r.finish()
    return {'epoch': epoch, 'commit_round': round_, 'protocol': version, 'creator': creator,
        'prev_state_root': previous.hex(), 'state_root': state.hex(), 'tx_list_hash': txlist.hex(),
        'receipt_root': receipts.hex(), 'txid_hi': txid if txid < 1 << 63 else txid - (1 << 64),
        'timestamp': timestamp, 'proposal_id': proposal.hex(), 'header_sha256': hashlib.sha256(header_raw).hexdigest(),
        'signers': signers, 'parent_proposal_id': parent['proposal_id'] if parent else None,
        'wire_sha256': hashlib.sha256(raw).hexdigest()}


def qc_negative_controls(raw, validators, chain):
    """Mutate a genuinely finalized v4 certificate; every mutation must refuse."""
    positive = verify_certificate(raw, validators, chain)
    require(positive['protocol'] == 4, 'actual v4 parent certificate required for controls')
    r = Reader(raw)
    r.string(128); r.take(8 + 4)
    r.take(2); r.string(128); r.take(8 + 32 + 32 + 32)
    state_start = r.at
    r.take(32 + 32); r.string(128); r.take(8 + 8 + 32)
    count = r.integer(4)
    positions = []
    for _ in range(count):
        r.string(128); r.take(8 + 4 + 1 + 32)
        signer_start = r.at + 4
        signer = r.string(128)
        signature_start = r.at + 4
        r.string(64)
        positions.append((signer_start, signer, signature_start))
    require(r.integer(1) == 1, 'actual authenticated parent required')
    parent_start = r.at + 4
    parent = r.string(20 * 1024 * 1024)
    r.finish()
    require(len(parent) > 4, 'truncated actual parent')
    first, second = positions[:2]
    require(len(first[1]) == len(second[1]) == 47, 'actual validator address format differs')
    foreign = address(bytes(32)).encode()
    require(foreign.decode() not in validators and len(foreign) == 47, 'control foreign signer is not distinct')
    mutations = {
        'tampered-signature': (first[2], bytes([raw[first[2]] ^ 1])),
        'tampered-chain': (4, bytes([raw[4] ^ 1])),
        'tampered-header': (state_start, bytes([raw[state_start] ^ 1])),
        'tampered-parent': (parent_start + 4, bytes([raw[parent_start + 4] ^ 1])),
        'duplicate-signer': (second[0], first[1]),
        'nonmember-signer': (first[0], foreign),
    }
    results = []
    for name, (offset, replacement) in mutations.items():
        candidate = raw[:offset] + replacement + raw[offset + len(replacement):]
        require(candidate != raw, 'control did not change actual certificate')
        try:
            verify_certificate(candidate, validators, chain)
        except Exception as error:
            results.append({'control': name, 'refused': True, 'exception_type': type(error).__name__,
                'mutated_wire_sha256': hashlib.sha256(candidate).hexdigest(), 'offset': offset})
        else:
            raise RuntimeError('independent QC verifier accepted ' + name)
    require(verify_certificate(raw, validators, chain) == positive, 'original certificate changed during controls')
    return {'actual_positive_certificate_sha256': hashlib.sha256(raw).hexdigest(),
        'actual_positive_verified': True, 'all_six_mutations_refused': len(results) == 6, 'controls': results,
        'scope': 'Independent fixture verifier controls derived from a real finalized QC; no additional Rust test cases.'}


def read_rust_store(data, genesis, validators):
    database = Path(data) / 'canonical.db'
    require(database.is_file(), 'Rust canonical database absent')
    con = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
    try:
        con.execute('BEGIN')
        identity = con.execute('SELECT chain,anchor FROM node_identity WHERE id=0').fetchone()
        require(identity is not None and decode(identity[0]) == genesis['chain'], 'Rust canonical chain differs')
        history = []
        previous_txid = -1
        for sequence, head_raw, cert in con.execute('SELECT sequence,head,certificate FROM node_epochs ORDER BY sequence'):
            head = decode(head_raw)
            require(head['cursor']['sequence'] == sequence and head['cursor']['epoch'] == sequence, 'Rust cursor differs')
            if sequence == 0:
                require(bytes32(head['cursor']['state_root']).hex() == genesis_root(genesis), 'Rust genesis root differs')
                continue
            checked = verify_certificate(cert, validators, genesis['chain']['chain_id'])
            require(checked['epoch'] == sequence and checked['state_root'] == bytes32(head['cursor']['state_root']).hex()
                    and checked['txid_hi'] == head['txid_hi'], 'Rust authenticated head differs')
            receipt_rows = con.execute('SELECT receipts FROM node_consensus_receipts WHERE sequence=?',
                                       (sequence,)).fetchall()
            require(len(receipt_rows) == 1 and decode(receipt_rows[0][0]) == []
                    and checked['receipt_root'] == domain_hash(b'octra:preverify_receipt_root:v1', bytes(4)).hex(),
                    'Rust Standard-only receipt storage/root differs')
            event = con.execute('SELECT epoch,parent_root,root,events FROM exex_committed_epoch WHERE sequence=?',
                                (f'{sequence:016x}',)).fetchall()
            require(len(event) == 1 and int(event[0][0], 16) == sequence
                    and bytes(event[0][1]).hex() == checked['prev_state_root']
                    and bytes(event[0][2]).hex() == checked['state_root'], 'Rust immutable ExEx binding differs')
            transactions = decode(event[0][3])
            require(type(transactions) is list, 'Rust transaction events shape differs')
            require(len(transactions) == checked['txid_hi'] - previous_txid,
                    'Rust ExEx transaction range differs')
            tx_json = []
            for offset, item in enumerate(transactions, 1):
                require(type(item) is dict and set(item) ==
                        {'txid', 'hash', 'proof', 'identity', 'transaction', 'receipt'}
                        and type(item['txid']) is int and item['txid'] == previous_txid + offset
                        and item['proof'] == 'exact' and item['receipt'] is None,
                        'Rust Standard ExEx record schema/identity/receipt differs')
                identity_bytes = b64(item['identity'])
                transaction_bytes = b64(item['transaction'])
                require(identity_bytes == transaction_bytes
                        and hashlib.sha256(identity_bytes).hexdigest() == item['hash'],
                        'Rust ExEx exact transaction hash/preimage differs')
                payload = decode(transaction_bytes)
                mandatory = {'from', 'to_', 'amount', 'nonce', 'ou', 'timestamp', 'signature', 'op_type'}
                optional = {'public_key', 'message', 'encrypted_data'}
                require(type(payload) is dict and set(payload) == mandatory | optional
                        and payload['op_type'] == 'standard'
                        and all(payload[key] is None or type(payload[key]) is str for key in optional),
                        'Rust Standard transaction preimage fields differ')
                # Native Transaction.hash includes all three null optionals;
                # Transaction.to_yojson omits exactly the absent optionals.
                normalized = {key: value for key, value in payload.items()
                              if key not in optional or value is not None}
                tx_json.append(compact(normalized).decode('utf-8'))
            require(header_transaction_root([item['hash'] for item in transactions]) == checked['tx_list_hash'],
                    'Rust ExEx identities differ from certified transaction hash list')
            previous_txid = checked['txid_hi']
            history.append({**checked, 'txs_json': tx_json,
                'receipts': [], 'retained_row_sha256': hashlib.sha256(
                    head_raw + cert + event[0][3] + receipt_rows[0][0]).hexdigest()})
        return history
    finally:
        con.close()
