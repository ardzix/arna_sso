"""Run uploaded clean source archives against disposable isolated PostgreSQL.

Invoke over authorized SSH: python3 - BASE_TAR CHANGES_TAR < this script.
No live service, DB, network, credentials, or customer records are modified.
"""
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time


def run(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=180, **kwargs)


def main():
    archives = [Path(value).resolve() for value in sys.argv[1:]]
    if len(archives) != 2 or any(path.parent != Path('/tmp') or not path.name.startswith('ols-gift-sso-') or path.suffix != '.tar' for path in archives):
        raise ValueError('Expected exact task-owned /tmp archives.')
    suffix = secrets.token_hex(6)
    network = 'ols-gift-test-' + suffix
    database = network + '-pg'
    password = secrets.token_urlsafe(32)
    service = json.loads(subprocess.check_output(['docker', 'service', 'inspect', 'sso_service'], text=True))[0]
    image = service['Spec']['TaskTemplate']['ContainerSpec']['Image']
    try:
        with tempfile.TemporaryDirectory(prefix='ols-gift-sso-test-') as folder:
            root = Path(folder)
            for archive in archives:
                with tarfile.open(archive) as tar:
                    for member in tar.getmembers():
                        target = (root / member.name).resolve()
                        if not target.is_relative_to(root) or member.issym() or member.islnk():
                            raise ValueError('Unsafe source member.')
                    tar.extractall(root)
            if any(root.glob('*.pem')) or (root / '.env').exists():
                raise ValueError('No runtime credentials may enter the test context.')
            subprocess.check_call(['docker', 'network', 'create', '--internal', network], stdout=subprocess.DEVNULL)
            pg_image = json.loads(subprocess.check_output(['docker', 'inspect', 'postgres'], text=True))[0]['Image']
            subprocess.check_call(['docker', 'run', '-d', '--name', database, '--network', network,
                                   '-e', 'POSTGRES_PASSWORD=' + password, '-e', 'POSTGRES_DB=ols_gift_isolated',
                                   pg_image], stdout=subprocess.DEVNULL)
            for _ in range(30):
                if run(['docker', 'exec', database, 'pg_isready', '-U', 'postgres']).returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Isolated PostgreSQL did not become ready.')
            result = run(['docker', 'run', '--rm', '--network', network,
                          '--mount', f'type=bind,source={root},target=/usr/src/app,readonly',
                          '-e', 'GIFT_TEST_POSTGRES_HOST=' + database,
                          '-e', 'GIFT_TEST_POSTGRES_PASSWORD=' + password,
                          '--entrypoint', 'python', image, 'scripts/test_gift_registration.py'])
            print(result.stdout)
            print(result.stderr)
            print(json.dumps({'test_exit_code': result.returncode, 'production_runtime_modified': False,
                              'production_customer_writes': 0, 'test_runtime_digest': image}))
            return result.returncode
    finally:
        run(['docker', 'rm', '-f', database])
        run(['docker', 'network', 'rm', network])
        for archive in archives:
            archive.unlink(missing_ok=True)


if __name__ == '__main__':
    sys.exit(main())
