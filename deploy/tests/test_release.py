"""Release regressions using synthetic specs, no Docker/production credentials."""
import importlib.util
import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sso_manager_release', Path(__file__).resolve().parents[1] / 'release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.commit = 'a' * 40
        self.digest = release.REPOSITORY + '@sha256:' + 'b' * 64
        self.record = {'commit': self.commit, 'digest': self.digest, 'tests': 'passed', 'status': 'published'}
        release.write_private(self.folder / 'release.json', self.record)

    def baseline(self):
        return {'Spec': {'TaskTemplate': {'ContainerSpec': {
            'Image': 'synthetic-old-image',
            'Env': ['SSO_RUNTIME_SECRET_PATH=/run/secrets/sso_runtime'],
            'Secrets': [{'SecretID': 'id-' + kind, 'SecretName': 'name-' + kind, 'File': {'Name': target}}
                        for kind, target in [('runtime', 'sso_runtime'), ('private', 'sso_jwt_private'), ('public', 'sso_jwt_public')]]}}}}

    def simulate_roll(self, baseline, created):
        def docker(args, **kwargs):
            if args[:2] == ['docker', 'ps']:
                return 'synthetic-api-1\nsynthetic-api-2\n'
            if args[:2] == ['docker', 'exec']:
                if '/run/secrets/sso_runtime' in args[-1]:
                    return json.dumps({'SECRET_KEY': 'synthetic', 'DB_HOST': 'synthetic', 'DB_NAME': 'synthetic',
                                       'DB_USER': 'synthetic', 'DB_PASSWORD': 'synthetic', 'DEBUG': 'false',
                                       'JWT_PRIVATE_KEY_PATH': '/run/secrets/sso_jwt_private',
                                       'JWT_PUBLIC_KEY_PATH': '/run/secrets/sso_jwt_public'})
                return 'synthetic-key-material'
            if args[:3] == ['docker', 'secret', 'create']:
                self.assertNotIn(args[3], created)
                created.add(args[3])
            if args[:3] == ['docker', 'service', 'update']:
                removed = [args[i + 1] for i, value in enumerate(args) if value == '--secret-rm']
                targets = [item['File']['Name'] for item in baseline['Spec']['TaskTemplate']['ContainerSpec']['Secrets']
                           if item['SecretName'] not in removed]
                for i, value in enumerate(args):
                    if value == '--secret-add':
                        targets.append(dict(part.split('=', 1) for part in args[i + 1].split(','))['target'])
                if len(targets) != len(set(targets)):
                    raise RuntimeError('Docker rejects conflicting secret targets')
            return ''
        return docker

    def test_roll_replaces_secret_mounts_without_duplicate_targets(self):
        baseline = self.baseline()
        with patch.object(release, 'inspect_service', return_value=baseline), \
             patch.object(release, 'run', side_effect=self.simulate_roll(baseline, set())), \
             patch.object(release, 'wait_task', return_value='synthetic-migration'), \
             patch.object(release, 'verify') as verify, patch.object(release.subprocess, 'run'):
            release.roll(self.commit, self.folder)
        verify.assert_called_once()
        self.assertEqual(json.loads((self.folder / 'release.json').read_text())['migration'], 'complete_exit_0')

    def test_retry_uses_fresh_immutable_secrets_and_preserves_original_snapshot(self):
        baseline = self.baseline()
        created = set()
        with patch.object(release, 'inspect_service', return_value=baseline), \
             patch.object(release, 'run', side_effect=self.simulate_roll(baseline, created)), \
             patch.object(release, 'wait_task', return_value='synthetic-migration'), \
             patch.object(release, 'verify'), patch.object(release.subprocess, 'run'):
            release.roll(self.commit, self.folder)
            snapshot = (self.folder / 'previous-service.json').read_bytes()
            release.roll(self.commit, self.folder)
        self.assertEqual(len(created), 6)
        self.assertEqual((self.folder / 'previous-service.json').read_bytes(), snapshot)
        self.assertEqual(len(list(self.folder.glob('previous-service-*.json'))), 1)

    def build_reply(self, revision):
        def docker(args, **kwargs):
            if 'rev-parse' in args:
                return self.commit
            if args[:3] == ['docker', 'image', 'inspect']:
                return json.dumps([{'Architecture': 'amd64', 'RepoDigests': [self.digest],
                                    'Config': {'Labels': {'org.opencontainers.image.revision': revision}}}])
            return ''
        return docker

    def test_repeat_build_reuses_verified_digest_even_when_source_folder_exists(self):
        (self.folder / 'source').mkdir()
        with patch.object(release, 'run', side_effect=self.build_reply(self.commit)) as run:
            release.build(self.commit, self.folder)
        self.assertFalse(any(call.args[0][:2] == ['docker', 'build'] for call in run.call_args_list))

    def test_repeat_build_rejects_artifact_with_wrong_revision(self):
        with patch.object(release, 'run', side_effect=self.build_reply('c' * 40)):
            with self.assertRaisesRegex(RuntimeError, 'does not match'):
                release.build(self.commit, self.folder)

    def test_repeat_build_rejects_record_without_successful_tests(self):
        release.write_private(self.folder / 'release.json', {**self.record, 'tests': 'failed'})
        with patch.object(release, 'run', side_effect=self.build_reply(self.commit)):
            with self.assertRaisesRegex(RuntimeError, 'tested artifact'):
                release.build(self.commit, self.folder)

    def test_failure_diagnostics_are_saved_without_command_or_secret_input(self):
        diagnostic = self.folder / 'rollout-error.json'
        result = CompletedProcess([], 1, stdout='', stderr='Synthetic conflicting target')
        with patch.object(release.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as error:
                release.run(['docker', 'service', 'update', '--env-add', 'synthetic-private-value'],
                            input='synthetic-private-input', diagnostic_path=diagnostic)
        self.assertEqual(json.loads(diagnostic.read_text())['stderr'], result.stderr)
        self.assertNotIn('synthetic-private-value', diagnostic.read_text() + str(error.exception))
        self.assertNotIn('synthetic-private-input', diagnostic.read_text() + str(error.exception))


if __name__ == '__main__':
    unittest.main()
