"""Pure metadata/default/guard tests; never execute a fixture or scanner."""
import ast,contextlib,copy,hashlib,importlib.util,io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
sys.path.insert(0,str(HERE));import verify_source6062 as V
spec=importlib.util.spec_from_file_location('source6062_repro_adapter',HERE/'repro/run_suite.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
class Tests(unittest.TestCase):
    def test_exported_source_full_pin(self):
        p=HERE/'source/deploy/security-scanner/scanner.py';self.assertEqual(p.stat().st_size,V.SOURCE_BYTES);self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),V.SOURCE_SHA);self.assertEqual(V.held(p)['sha256'],V.SOURCE_SHA)
    def test_three_suites_counts_and_pins(self):
        self.assertEqual(list(A.SUITES),['missing47','p4_84_delta','ascii34']);self.assertEqual(sum(x['count']for x in A.SUITES.values()),165);self.assertEqual(A.CANDIDATE,V.SOURCE_SHA)
        for row in A.SUITES.values():self.assertEqual(hashlib.sha256((HERE/'repro'/row['file']).read_bytes()).hexdigest(),row['sha256']);self.assertEqual(hashlib.sha256((HERE/'repro/baselines'/row['baseline']).read_bytes()).hexdigest(),row['baselineSHA256'])
    def test_helpers_and_guard_unchanged(self):
        raw=(HERE/'repro/suite47/fixture_helpers.py').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b')
        self.assertEqual(raw,(HERE/'repro/suite84/fixture_helpers.py').read_bytes());self.assertEqual(raw,(HERE/'repro/suite34/fixture_helpers.py').read_bytes())
        t=ast.parse(raw);f=next(n for n in t.body if isinstance(n,ast.FunctionDef)and n.name=='environment');self.assertIn("for name in ('/probe', '/baseline', '/candidate')",ast.unparse(f))
    def test_prior_165_observations_separate_not_adoption(self):
        v=json.loads((HERE/'known-165-receipts-index.json').read_bytes());self.assertEqual(len(v['rows']),3);self.assertEqual(sum(x['passed']for x in v['rows']),165)
        self.assertTrue(all(x['cleanupSuccess']and x['existingNineUnchanged']for x in v['rows']));self.assertFalse(v['activeNative200Read'])
        q=json.loads((HERE/'qualification-pending.json').read_bytes());self.assertEqual(q['native200']['status'],'PENDING');self.assertEqual(q['APP']['status'],'PENDING');self.assertFalse(q['adopted'])
    def test_default_verifier_has_zero_source_IO(self):
        out=io.StringIO()
        with patch.object(Path,'read_bytes',side_effect=AssertionError('read forbidden')),patch.object(Path,'open',side_effect=AssertionError('open forbidden')),contextlib.redirect_stdout(out):self.assertEqual(V.main([]),0)
        self.assertEqual(json.loads(out.getvalue())['sourceFilesRead'],0)
    def test_explicit_install_confirmation_required(self):
        with patch.object(V,'held',side_effect=AssertionError('source read forbidden')):
            with self.assertRaisesRegex(ValueError,'explicit-installed-source-confirmation-required'):V.main(['--verify-source','--source','C:/not-read/scanner.py'])
    def test_suite_default_has_zero_source_IO(self):
        out=io.StringIO()
        with patch.object(Path,'read_bytes',side_effect=AssertionError('read forbidden')),patch.object(Path,'open',side_effect=AssertionError('open forbidden')),contextlib.redirect_stdout(out):self.assertEqual(A.main([]),0)
        self.assertEqual(json.loads(out.getvalue())['mode'],'DESCRIBE')
    def test_suite_windows_execute_refuses_before_source_read(self):
        with patch.object(A.sys,'platform','win32'),patch.object(A,'source',side_effect=AssertionError('source read forbidden')):
            with self.assertRaisesRegex(ValueError,'linux-low-uid'):A.main(['--execute','--root-idle-confirmed','--deadline','1'])
    def test_package_copy_cannot_be_installed_source(self):
        p=HERE/'source/deploy/security-scanner/scanner.py'
        with self.assertRaisesRegex(ValueError,'package-copy-is-not-installed-source'):V.verify_source(p)
    def test_wrong_source_SHA_refused(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'scanner.py';p.write_text('# harmless CODE metadata negative\n',encoding='ascii')
            with self.assertRaisesRegex(ValueError,'source-full-sha'):V.held(p)
    def test_source_changed_during_binding_refused(self):
        p=Path(tempfile.gettempdir())/'external-installed/scanner.py';a={'path':str(p),'identity':[1]};b={'path':str(p),'identity':[2]}
        with patch.object(Path,'resolve',lambda p,*a,**k:p),patch.object(V,'held',side_effect=[a,b]):
            with self.assertRaisesRegex(ValueError,'source-changed-during-binding'):V.verify_source(p)
    def test_snapshot_source_identity_and_previous_binding(self):
        with tempfile.TemporaryDirectory()as d:
            source=Path(d)/'installed/scanner.py';q=Path(d)/'snapshot/scanner.py';a={'path':str(source),'identity':[1],'sha256':V.SOURCE_SHA};b={'path':str(q),'identity':[2],'sha256':V.SOURCE_SHA}
            previous=Path(d)/'previous.json';old={'scope':'INSTALLED_SOURCE_VERIFIED_SNAPSHOT_METADATA_ONLY','status':'VERIFIED','source':a,'snapshot':b};previous.write_text(json.dumps(old),encoding='ascii')
            with patch.object(Path,'resolve',lambda p,*a,**k:p),patch.object(Path,'iterdir',return_value=iter([q])),patch.object(V,'held',side_effect=[a,b,a]):out=V.verify_source(source,q,previous)
            self.assertEqual(out['source'],a);self.assertEqual(out['snapshot'],b);self.assertFalse(out['adoptionEstablishedByVerifier'])
    def test_snapshot_extra_file_refused(self):
        p=Path(tempfile.gettempdir())/'installed/scanner.py';q=Path(tempfile.gettempdir())/'snapshot/scanner.py'
        with patch.object(Path,'resolve',lambda p,*a,**k:p),patch.object(V,'held',return_value={'sha256':V.SOURCE_SHA}),patch.object(Path,'iterdir',return_value=iter([q,q.parent/'extra.txt'])):
            with self.assertRaisesRegex(ValueError,'snapshot-directory-not-single-code-file'):V.verify_source(p,q)
    def test_no_source_execution_in_verifier(self):
        t=ast.parse((HERE/'verify_source6062.py').read_bytes())
        calls=[n for n in ast.walk(t)if isinstance(n,ast.Call)]
        self.assertFalse(any(isinstance(n.func,ast.Name)and n.func.id in{'exec','eval','compile','__import__'}for n in calls))
        self.assertFalse(any(isinstance(n,ast.Import)and any(x.name in{'subprocess','torch','pickle'}for x in n.names)for n in ast.walk(t)))
if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    print(json.dumps({'status':'PASS'if result.wasSuccessful()else'FAIL','tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'scope':'SOURCE_METADATA_AND_DEFAULT_GUARDS_ONLY','fixtureGenerated':False,'scannerExecuted':False,'VMExecuted':False,'DockerExecuted':False},sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful()else 1)
