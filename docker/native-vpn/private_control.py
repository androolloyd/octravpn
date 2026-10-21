"""Fresh offline TLS identities for the isolated multi-hop control gate."""
import hashlib
import pathlib
import subprocess


def identities(directory):
    directory.mkdir(mode=0o700)
    config = directory / 'ca.cnf'
    config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca_ext\n'
                      '[dn]\nCN=Octranet isolated route CA\n[ca_ext]\n'
                      'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')

    def run(*argv):
        subprocess.run(['openssl', *map(str, argv)], check=True, capture_output=True, timeout=30)

    run('req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
        '-config', config, '-keyout', directory / 'ca.key', '-out', directory / 'ca.pem')
    report = {'ca_sha256': hashlib.sha256((directory / 'ca.pem').read_bytes()).hexdigest(), 'hosts': {}}
    for serial, role in enumerate(['entry', 'exit'], 1):
        target = directory / role
        target.mkdir(mode=0o700)
        host = role + '.octra.invalid'
        extensions = target / 'server.cnf'
        extensions.write_text('[server_ext]\nbasicConstraints=critical,CA:FALSE\n'
                              'keyUsage=critical,digitalSignature,keyEncipherment\n'
                              'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + host + '\n')
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=' + host,
            '-keyout', target / 'server.key', '-out', target / 'server.csr')
        run('x509', '-req', '-in', target / 'server.csr', '-CA', directory / 'ca.pem',
            '-CAkey', directory / 'ca.key', '-set_serial', serial, '-sha256', '-days', '1',
            '-extfile', extensions, '-extensions', 'server_ext', '-out', target / 'server.crt')
        (target / 'ca.pem').write_bytes((directory / 'ca.pem').read_bytes())
        for path in target.iterdir():
            path.chmod(0o600)
        report['hosts'][role] = {'hostname': host, 'certificate_sha256': hashlib.sha256((target / 'server.crt').read_bytes()).hexdigest()}
    (directory / 'ca.key').chmod(0o600)
    return report
