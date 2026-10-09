"""SSO-owned manager release gates. Run on the already approved production manager.

python3 deploy/release.py {build,roll,verify} FULL_MAIN_COMMIT
No credentials in source, image, command output, or release evidence.
Manager registry authentication is inherited only into a temporary private config.
Never removes/recreates the existing sso_service. Retains previous specs for rollback.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

SERVICE = "sso_service"
REPOSITORY = "ardzix/arna_sso"
SOURCE = Path('/root/Project/arna_sso')
BASE = Path('/root/arnatech-releases')


def run(args, *, timeout=120, input=None, visible=False, env=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout, env=env)
    if visible:
        # Only explicitly non-secret build and isolated-test commands use this.
        print(result.stdout[-14000:], flush=True)
        print(result.stderr[-14000:], flush=True)
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:3]) + '; inspect private manager context')
    return result.stdout


def write_private(path, data):
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    path.chmod(0o600)


def inspect_service():
    return json.loads(run(['docker', 'service', 'inspect', SERVICE]))[0]


def wait_task(service, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ids = run(['docker', 'service', 'ps', '-q', service]).splitlines()
        if ids:
            task = json.loads(run(['docker', 'inspect', ids[0]]))[0]
            status = task['Status']
            if status['State'] == 'complete' and status.get('ContainerStatus', {}).get('ExitCode') == 0:
                return task['ID']
            if status['State'] in ('failed', 'rejected', 'shutdown'):
                raise RuntimeError('One-off gate failed; no rollout performed')
        time.sleep(2)
    raise RuntimeError('One-off gate timed out; no rollout performed')


def test_image(image):
    suffix = os.urandom(6).hex()
    net = 'sso-gift-ci-' + suffix
    db = net + '-pg'
    import secrets
    password = secrets.token_urlsafe(32)
    pg_image = json.loads(run(['docker', 'inspect', 'postgres']))[0]['Image']
    try:
        run(['docker', 'network', 'create', '--internal', net])
        run(['docker', 'run', '-d', '--name', db, '--network', net,
             '-e', 'POSTGRES_PASSWORD=' + password, '-e', 'POSTGRES_DB=ols_gift_isolated', pg_image])
        for _ in range(30):
            if subprocess.run(['docker', 'exec', db, 'pg_isready', '-U', 'postgres'], capture_output=True).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Isolated test database unavailable')
        run(['docker', 'run', '--rm', '--network', net,
             '-e', 'GIFT_TEST_POSTGRES_HOST=' + db, '-e', 'GIFT_TEST_POSTGRES_PASSWORD=' + password,
             '--entrypoint', 'python', image, 'scripts/test_gift_registration.py'], timeout=300, visible=True)
    finally:
        subprocess.run(['docker', 'rm', '-f', db], capture_output=True)
        subprocess.run(['docker', 'network', 'rm', net], capture_output=True)


def build(commit, folder):
    run(['git', '-C', str(SOURCE), 'fetch', 'origin', 'main'])
    current = run(['git', '-C', str(SOURCE), 'rev-parse', 'origin/main']).strip()
    if current != commit:
        raise RuntimeError('Selected commit must be the current remote main')
    source = folder / 'source'
    if source.exists():
        raise RuntimeError('Release source already exists; use recorded artifact, never overwrite')
    source.mkdir(mode=0o700)
    archive = folder / 'source.tar'
    run(['git', '-C', str(SOURCE), 'archive', '--format=tar', '-o', str(archive), commit])
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk() or not (source / member.name).resolve().is_relative_to(source):
                raise ValueError('Unsafe source member')
        tar.extractall(source)
    archive.unlink()
    if list(source.glob('*.pem')) or (source / '.env').exists():
        raise RuntimeError('Source archive contains runtime credentials')
    tag = REPOSITORY + ':ols-gift-' + commit[:12]
    run(['docker', 'build', '--label', 'org.opencontainers.image.revision=' + commit, '-t', tag, str(source)], timeout=1800, visible=True)
    # Reject any secret-bearing files or legacy build-time injected variables.
    probe = 'from pathlib import Path;import os;p=Path("/usr/src/app");assert not (p/".env").exists();assert not list(p.rglob("*.pem"));assert not os.environ.get("SECRET_KEY");assert not os.environ.get("DB_PASSWORD");print("Clean image verified")'
    run(['docker', 'run', '--rm', '--entrypoint', 'python', tag, '-c', probe], visible=True)
    test_image(tag)
    with tempfile.TemporaryDirectory(prefix='sso-registry-', dir=folder) as config:
        shutil.copyfile('/root/.docker/config.json', Path(config) / 'config.json')
        os.chmod(Path(config) / 'config.json', 0o600)
        env = dict(os.environ, DOCKER_CONFIG=config)
        run(['docker', 'push', tag], timeout=300, visible=True, env=env)
        run(['docker', 'pull', tag], timeout=180, env=env)
    info = json.loads(run(['docker', 'image', 'inspect', tag]))[0]
    digests = [value for value in info['RepoDigests'] if value.startswith(REPOSITORY + '@sha256:')]
    if len(digests) != 1 or info['Architecture'] != 'amd64':
        raise RuntimeError('Published artifact digest/platform unresolved')
    record = {'commit': commit, 'tag': tag, 'digest': digests[0], 'platform': 'linux/amd64', 'tests': 'passed', 'status': 'published'}
    write_private(folder / 'release.json', record)
    print(json.dumps(record), flush=True)


def roll(commit, folder):
    record = json.loads((folder / 'release.json').read_text())
    if record['commit'] != commit or record['tests'] != 'passed':
        raise RuntimeError('Untested or wrong artifact')
    old = inspect_service()
    write_private(folder / 'previous-service.json', old)
    cs = old['Spec']['TaskTemplate']['ContainerSpec']
    if cs.get('Mounts'):
        raise RuntimeError('Runtime mounts changed since inspected baseline; review before proceeding')
    environment = dict(value.split('=', 1) for value in cs.get('Env', []))
    names = run(['docker', 'ps', '--filter', 'label=com.docker.swarm.service.name=' + SERVICE, '--format', '{{.Names}}']).splitlines()
    if len(names) != 2:
        raise RuntimeError('Expected two healthy baseline replicas')
    if cs.get('Secrets'):
        if environment.get('SSO_RUNTIME_SECRET_PATH') != '/run/secrets/sso_runtime':
            raise RuntimeError('Unknown runtime secret layout; review before proceeding')
        environment = json.loads(run(['docker', 'exec', names[0], 'python', '-c', 'from pathlib import Path;print(Path("/run/secrets/sso_runtime").read_text())']))
    if not all(environment.get(name) for name in ('SECRET_KEY', 'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD')):
        raise RuntimeError('Incomplete existing runtime configuration')
    if environment.get('DEBUG', '').lower() not in ('false', '0'):
        raise RuntimeError('Production debug must be disabled')
    keys = {}
    for kind in ('PRIVATE', 'PUBLIC'):
        path = environment.get('JWT_' + kind + '_KEY_PATH', kind.lower() + '.pem')
        if not path.startswith('/'):
            path = '/usr/src/app/' + path
        keys[kind] = run(['docker', 'exec', names[0], 'python', '-c', 'from pathlib import Path;import sys;sys.stdout.write(Path(sys.argv[1]).read_text())', path])
    fingerprint = hashlib.sha256(keys['PUBLIC'].encode()).hexdigest()
    secret_names = {kind: 'sso-ols-gift-' + kind.lower() + '-' + commit[:12] for kind in ('runtime', 'private', 'public')}
    environment['JWT_PRIVATE_KEY_PATH'] = '/run/secrets/sso_jwt_private'
    environment['JWT_PUBLIC_KEY_PATH'] = '/run/secrets/sso_jwt_public'
    environment['DB_CONNECT_TIMEOUT_SECONDS'] = '5'
    values = {'runtime': json.dumps(environment), 'private': keys['PRIVATE'], 'public': keys['PUBLIC']}
    for kind, name in secret_names.items():
        run(['docker', 'secret', 'create', name, '-'], input=values[kind])
    options = ['--env', 'SSO_RUNTIME_SECRET_PATH=/run/secrets/sso_runtime', '--network', 'production']
    for kind, target in [('runtime', 'sso_runtime'), ('private', 'sso_jwt_private'), ('public', 'sso_jwt_public')]:
        options += ['--secret', 'source=' + secret_names[kind] + ',target=' + target + ',mode=0400']
    migrate = 'sso-gift-migrate-' + commit[:12]
    try:
        run(['docker', 'service', 'create', '--detach=true', '--with-registry-auth', '--name', migrate, '--restart-condition', 'none',
             '--limit-memory', '384M', '--entrypoint', 'python', *options, record['digest'], 'manage.py', 'migrate', '--noinput'])
        task = wait_task(migrate)
        record['migration_task'] = task
        record['migration'] = 'complete_exit_0'
        write_private(folder / 'release.json', record)
    finally:
        subprocess.run(['docker', 'service', 'rm', migrate], capture_output=True)
    update = ['docker', 'service', 'update', '--with-registry-auth', '--image', record['digest'],
              '--update-parallelism', '1', '--update-order', 'stop-first', '--update-delay', '10s',
              '--update-monitor', '30s', '--update-failure-action', 'rollback',
              '--rollback-parallelism', '1', '--rollback-order', 'stop-first', '--stop-grace-period', '60s',
              '--health-cmd', 'python /usr/src/app/deploy/healthcheck.py', '--health-interval', '15s',
              '--health-timeout', '6s', '--health-retries', '3', '--health-start-period', '60s']
    for key in dict(value.split('=', 1) for value in cs.get('Env', [])):
        update += ['--env-rm', key]
    for secret in cs.get('Secrets') or []:
        update += ['--secret-rm', secret['SecretID']]
    update += ['--env-add', 'SSO_RUNTIME_SECRET_PATH=/run/secrets/sso_runtime']
    for kind, target in [('runtime', 'sso_runtime'), ('private', 'sso_jwt_private'), ('public', 'sso_jwt_public')]:
        update += ['--secret-add', 'source=' + secret_names[kind] + ',target=' + target + ',mode=0400']
    update += [SERVICE]
    # Same image/API + queue role as baseline. stop-first avoids an extra 4-worker
    # qcluster under the inspected manager's limited free memory.
    run(update, timeout=420)
    record.update(status='deployed', secrets=secret_names, public_key_fingerprint=fingerprint,
                  configuration_source='immutable full runtime Swarm secret; previous-service.json retained privately')
    write_private(folder / 'release.json', record)
    verify(commit, folder)


def verify(commit, folder):
    record = json.loads((folder / 'release.json').read_text())
    info = inspect_service()
    # Docker's update progress can finish before the final monitor window does.
    deadline = time.monotonic() + 90
    while info.get('UpdateStatus', {}).get('State') == 'updating' and time.monotonic() < deadline:
        time.sleep(3)
        info = inspect_service()
    if info['Spec']['TaskTemplate']['ContainerSpec']['Image'] != record['digest']:
        raise RuntimeError('Wrong live digest')
    if info.get('UpdateStatus', {}).get('State') != 'completed':
        raise RuntimeError('Rollout not completed')
    names = run(['docker', 'ps', '--filter', 'label=com.docker.swarm.service.name=' + SERVICE, '--format', '{{.Names}}']).splitlines()
    if len(names) != 2:
        raise RuntimeError('Replica convergence failure')
    for name in names:
        c = json.loads(run(['docker', 'inspect', name]))[0]
        if c['State'].get('Health', {}).get('Status') != 'healthy':
            raise RuntimeError('Replica is not healthy')
        probe = 'from pathlib import Path;args=[p.read_bytes().replace(b"\\0",b" ") for p in Path("/proc").glob("[0-9]*/cmdline") if p.exists()];assert any(a.startswith(b"uwsgi ") for a in args);assert any(b"manage.py qcluster" in a and a.startswith(b"python ") for a in args);print("API and queue roles running")'
        run(['docker', 'exec', name, 'python', '-c', probe])
    for path in ('/health/live', '/health/ready'):
        run(['curl', '-fsS', '--max-time', '12', 'https://sso.arnatech.id' + path])
    record['status'] = 'verified'
    write_private(folder / 'release.json', record)
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    phase, commit = sys.argv[1:]
    if phase not in ('build', 'roll', 'verify') or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Expected phase and full selected main commit')
    BASE.mkdir(mode=0o700, exist_ok=True)
    folder = BASE / ('sso-ols-gift-' + commit[:12])
    folder.mkdir(mode=0o700, exist_ok=True)
    # Serialize against other releases using this durable entrypoint.
    import fcntl
    with (BASE / 'sso-release.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        {'build': build, 'roll': roll, 'verify': verify}[phase](commit, folder)
