"""Offline canary routing and independently pinned devnet identity."""
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
AUTHORITY_FILE = ROOT / 'docs/rust-node/network-authority.json'
MAINNET_RPC = 'https://octra.network/rpc'
DEVNET_RPC = 'https://devnet.octrascan.io/rpc'
DEVNET_CHAIN_ID = 'octra-devnet-9871-cluster'
DEVNET_RPC_PROVENANCE = {
    'repository': 'https://github.com/octra-labs/lite_node',
    'upstream_commit': '7f9be4489870645cfcc95439638cde40f5da9f50',
    'path': 'controls/lib/validator_config.py',
    'sha256': 'e189f2fdd742955b09b847af888ee8baea208818d6faf3eafc33a413ca1608ca',
    'line': 877,
    'scope': 'Official CLI RPC routing default; network authority is pinned separately.',
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def bounded_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('network authority inputs must be regular public files')
    with path.open('rb') as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('network authority input exceeds 64 KiB')
    return data


def devnet(network_env):
    if network_env is None:
        raise ValueError('devnet requires the independently pinned --network-env file')
    authority_raw = bounded_file(AUTHORITY_FILE)
    authority = json.loads(authority_raw)
    raw = bounded_file(network_env)
    env_sha = hashlib.sha256(raw).hexdigest()
    if env_sha != authority['sha256']:
        raise ValueError('devnet network.env SHA256 differs from adopted authority')
    fields = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not key or key in fields:
            raise ValueError('malformed or duplicate network.env field')
        fields[key] = value
    checkpoint = authority['checkpoint']
    expected = {
        'OCTRA_CHAIN_ID': authority['chain_id'],
        'OCTRA_CONSENSUS_CONFIG_HASH': authority['config_hash'],
        'OCTRA_CHECKPOINT_EPOCH': str(checkpoint['epoch']),
        'OCTRA_CHECKPOINT_STATE_ROOT': checkpoint['state_root'],
        'OCTRA_CHECKPOINT_TXID_HI': str(checkpoint['txid_hi']),
    }
    if any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError('devnet network.env identity differs from adopted authority')
    return {
        'network': 'devnet',
        'rpc_url': DEVNET_RPC,
        'chain_id': authority['chain_id'],
        'config_hash': authority['config_hash'],
        'origin': {'kind': 'checkpoint', **checkpoint},
        'network_env_sha256': env_sha,
        'authority': {
            'repository': authority['repository'],
            'upstream_commit': authority['upstream_commit'],
            'path': authority['path'],
            'sha256': authority['sha256'],
            'declaration_sha256': hashlib.sha256(authority_raw).hexdigest(),
        },
        'rpc_provenance': DEVNET_RPC_PROVENANCE,
    }


def select(target, network='mainnet', network_env=None, allow_unset_mainnet=False):
    if not isinstance(target, dict):
        raise ValueError('candidate target must be an object')
    if network not in ('mainnet', 'devnet'):
        raise ValueError('unknown canary network mode')
    if target.get('network', 'mainnet') != network:
        raise ValueError('explicit network mode differs from candidate target')
    if network == 'devnet':
        expected = devnet(network_env)
        if target.get('genesis_root'):
            raise ValueError('devnet checkpoint origin must not be labeled genesis')
        for key in ('rpc_url', 'chain_id', 'config_hash', 'origin', 'network_env_sha256'):
            if target.get(key) != expected[key]:
                raise ValueError('devnet candidate target mismatch: ' + key)
        for key in ('authority', 'rpc_provenance'):
            if key in target and target[key] != expected[key]:
                raise ValueError('devnet candidate target mismatch: ' + key)
        return expected
    if network_env is not None:
        raise ValueError('--network-env is only valid for explicit devnet mode')
    rpc_url = target.get('rpc_url') or None
    if rpc_url != MAINNET_RPC and not (allow_unset_mainnet and rpc_url is None):
        raise ValueError('mainnet canary requires the reviewed mainnet RPC')
    origin = target.get('origin') or {}
    if not isinstance(origin, dict):
        raise ValueError('candidate origin must be an object')
    if target.get('chain_id') == DEVNET_CHAIN_ID or origin.get('kind') == 'checkpoint':
        raise ValueError('mainnet mode cannot use the adopted devnet checkpoint target')
    return {'network': 'mainnet', 'rpc_url': rpc_url, 'chain_id': target.get('chain_id') or None,
            'genesis_root': target.get('genesis_root') or None}


def intent_target(target, network='mainnet', network_env=None, owner=False):
    selected = select(target, network, network_env, allow_unset_mainnet=True)
    if owner:
        selected['owner'] = target.get('owner') or None
    return selected
