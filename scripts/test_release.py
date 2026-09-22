import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import check_changesets
import publish


class ChangesetTests(unittest.TestCase):
    def test_valid(self):
        check_changesets.valid('---\ndefault: major\n---\nHarden rate limiting.')

    def test_invalid_entries(self):
        for header in ['"default": patch', 'barnacle-rs: patch', 'default: pach', '', 'default: 0.4.0',
                       'default: patch\ndefault: minor']:
            with self.subTest(header=header), self.assertRaises(ValueError):
                check_changesets.valid(f'---\n{header}\n---\nDescription')

    def test_description_required(self):
        with self.assertRaises(ValueError):
            check_changesets.valid('---\ndefault: patch\n---\n')

    def test_old_changeset_does_not_cover_new_code(self):
        # merge-base, changed files, files at head
        responses = ['base\n', 'src/lib.rs\n', 'src/lib.rs\n.changeset/old.md\n']
        with patch.object(check_changesets, 'git', side_effect=responses):
            with self.assertRaisesRegex(ValueError, 'Add a changeset'):
                check_changesets.check('base', 'head')

    def test_new_changeset_covers_code(self):
        responses = ['base\n', 'src/lib.rs\n.changeset/new.md\n', 'src/lib.rs\n.changeset/new.md\n',
                     '---\ndefault: patch\n---\nFix counting']
        with patch.object(check_changesets, 'git', side_effect=responses):
            check_changesets.check('base', 'head')

    def test_tests_and_docs_are_exempt(self):
        responses = ['base\n', 'tests/redis_store_tests.rs\nREADME.md\n', 'tests/redis_store_tests.rs\n']
        with patch.object(check_changesets, 'git', side_effect=responses):
            check_changesets.check('base', 'head')

    def test_release_metadata_only_is_exempt(self):
        before = '[package]\nversion = "0.3.1"\n[dependencies]\naxum = "0.8"\n[dev-dependencies]\nreqwest = "0.12"'
        strip = check_changesets.manifest_without_release_metadata
        self.assertEqual(strip(before), strip(before.replace('0.3.1', '0.4.0').replace('0.12', '0.13')))
        self.assertNotEqual(strip(before), strip(before.replace('0.8', '0.9')))


class PublishTests(unittest.TestCase):
    def test_skips_published_version(self):
        with patch.object(publish, 'published', return_value=True), patch.object(publish.subprocess, 'run') as run:
            publish.publish('barnacle-rs', '0.4.0')
            run.assert_not_called()
        with patch.object(publish, 'published', return_value=False), patch.object(publish.subprocess, 'run') as run:
            publish.publish('barnacle-rs', '0.4.0')
            run.assert_called_once_with(['cargo', 'publish', '--locked'], cwd=publish.ROOT, check=True)

    def test_registry_failure_stops_publication(self):
        error = urllib.error.HTTPError('url', 503, 'unavailable', {}, None)
        with patch.object(publish.urllib.request, 'urlopen', side_effect=error), patch.object(publish.subprocess, 'run') as run:
            with self.assertRaises(urllib.error.HTTPError):
                publish.publish('barnacle-rs', '0.4.0')
            run.assert_not_called()

    def test_only_404_means_absent(self):
        error = urllib.error.HTTPError('url', 404, 'missing', {}, None)
        with patch.object(publish.urllib.request, 'urlopen', side_effect=error):
            self.assertFalse(publish.published('barnacle-rs', '0.4.0'))
        for yanked in [False, True]:
            payload = io.BytesIO(json.dumps({'version': {'num': '0.4.0', 'yanked': yanked}}).encode())
            with patch.object(publish.urllib.request, 'urlopen', return_value=payload):
                if yanked:
                    with self.assertRaises(ValueError):
                        publish.published('barnacle-rs', '0.4.0')
                else:
                    self.assertTrue(publish.published('barnacle-rs', '0.4.0'))

    def test_plan_requires_prepared_changesets_and_notes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.changeset').mkdir()
            pending = root / '.changeset/pending.md'
            pending.write_text('pending')
            with self.assertRaises(ValueError):
                publish.plan(root)
            pending.unlink()
            (root / 'Cargo.toml').write_text('[package]\nname = "barnacle-rs"\nversion = "0.4.0"')
            (root / 'CHANGELOG.md').write_text('## 0.4.0 (2026-09-22)\n')
            self.assertEqual(publish.plan(root), ('barnacle-rs', '0.4.0'))
            (root / 'CHANGELOG.md').write_text('## 0.3.1\n')
            with self.assertRaises(ValueError):
                publish.plan(root)


if __name__ == '__main__':
    unittest.main()
