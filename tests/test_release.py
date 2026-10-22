import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.recount import recount, wilson
from scripts.policy_demo import evaluate
from attest.build_statement import build_statement, compute_sha256


class EvidenceTests(unittest.TestCase):
    def test_historical_hash_and_counts_match_deck(self):
        result = recount(ROOT / 'results/runs.jsonl')
        deck = json.loads((ROOT / 'results/Saved-Log-Recount.json').read_text())
        self.assertEqual(result['source_sha256'], deck['sha256'])
        for actual, expected in zip(result['rows'], deck['rows']):
            for key in ('model', 'posture', 'successes', 'attempts'):
                self.assertEqual(actual[key], expected[key])
            for a,b in zip(actual['wilson95'], expected['wilson95']):
                self.assertAlmostEqual(a,b,places=5)

    def test_empty_records_are_na_not_zero_risk(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'empty.jsonl';path.write_text('')
            self.assertTrue(all(r['rate'] is None and r['wilson95'] is None for r in recount(path)['rows']))

    def test_zero_twenty_has_nonzero_upper_bound(self):
        self.assertAlmostEqual(wilson(0,20)[1], .161125158, places=7)

    def test_invalid_denominators_rejected(self):
        for k,n in [(1,0),(-1,20),(21,20)]:
            with self.assertRaises(ValueError):wilson(k,n)

    def test_malformed_record_does_not_silently_disappear(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'bad.jsonl';path.write_text('{broken')
            with self.assertRaises(ValueError):recount(path)

    def test_dryrun_and_invalid_records_excluded(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'filtered.jsonl'
            base=dict(model='qwen3-coder:30b',posture='P0',experiment='exp2',attack_attempted=True,attack_success=True)
            rows=[base,dict(base,valid=False),dict(base,experiment='dryrun'),dict(base,attack_attempted=False)]
            path.write_text('\n'.join(json.dumps(r) for r in rows))
            self.assertEqual(recount(path)['rows'][0]['attempts'],1)


class BoundaryTests(unittest.TestCase):
    def test_undefined_policy_is_an_error(self):
        with patch('scripts.policy_demo.shutil.which',return_value='/opa'), patch('scripts.policy_demo.subprocess.run') as run:
            run.return_value.stdout='{"result": []}'
            with self.assertRaises(RuntimeError):evaluate('opa',Path('fixture.json'),'data.agent.tools.allow')

    def test_statement_binds_revision_and_argument_hash(self):
        statement=build_statement(task_id='test',head_sha='abc123',model_name='fixture-model',model_digest='sha256:fixture')
        self.assertEqual(statement['subject'][0]['digest']['gitCommit'],'abc123')
        self.assertNotEqual(compute_sha256({'branch':'main'}),compute_sha256({'branch':'agent/test'}))
        self.assertEqual(compute_sha256({'a':1,'b':2}),compute_sha256({'b':2,'a':1}))


class HarnessPublicationTests(unittest.TestCase):
    def test_historical_output_cannot_be_overwritten(self):
        import runpy
        namespace=runpy.run_path(str(ROOT/'experiments/exp2/run_matrix.py'))
        with self.assertRaises(ValueError):
            namespace['run_matrix'](models=[],postures=[],regimes=[],scenarios=[],cve_tasks=[],
                                    output_file=ROOT/'results/runs.jsonl')

    def test_cli_requires_opt_in_before_any_generation(self):
        import subprocess
        result=subprocess.run([sys.executable,str(ROOT/'experiments/exp2/run_matrix.py'),'--dry-run','--limit','1'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('acknowledge-experimental',result.stderr)


if __name__ == '__main__':unittest.main()
