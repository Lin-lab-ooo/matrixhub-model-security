"""Fourteen metadata/default guards only; bind final packet paths/schema before use.

No scanner module, fixture builder, VM, serialized artifact, network or Docker run.
This scratch template is deliberately PENDING and cannot claim a packet PASS.
"""
import ast,contextlib,hashlib,importlib.util,io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
# Parent supplies final closed packet schema/paths. Do not silently infer them.
TEST_BINDING={'verifier': 'verify_source_b2.py', 'suite165': 'repro/run_suite.py', 'suite40': 'repro40/linux_v7_tar_tests.py', 'suite12': 'repro12/run_holdout.py', 'contract': 'repro-contract.json', 'qualification': 'qualification-pending.json'}

def entry(relative,name):
    p=HERE/relative;spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if TEST_BINDING is None:raise ValueError('metadata-test-binding-pending')
        cls.V=entry(TEST_BINDING['verifier'],'b2_packet_verifier')
        cls.A=entry(TEST_BINDING['suite165'],'b2_real_repro165_entry')
        cls.T=entry(TEST_BINDING['suite40'],'b2_real_tar40_entry')
        cls.L=entry(TEST_BINDING['suite12'],'b2_real_holdout12_entry')
        cls.contract=json.loads((HERE/TEST_BINDING['contract']).read_bytes())

    def test_01_exported_source_full_pin(self):
        V=self.V;p=HERE/'source/deploy/security-scanner/scanner.py'
        self.assertEqual(p.stat().st_size,V.SOURCE_BYTES);self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),V.SOURCE_SHA);self.assertEqual(V.held(p)['sha256'],V.SOURCE_SHA)

    def test_02_exact_217_assertions_source_bindings(self):
        A=self.A;V=self.V
        self.assertEqual(list(A.SUITES),['missing47','p4_84_delta','ascii34']);self.assertEqual([x['count']for x in A.SUITES.values()],[47,84,34]);self.assertEqual(A.CANDIDATE,V.SOURCE_SHA)
        self.assertEqual(40+sum(x['count']for x in A.SUITES.values())+12,217)
        base=HERE/Path(TEST_BINDING['suite165']).parent
        for row in A.SUITES.values():
            self.assertEqual(hashlib.sha256((base/row['file']).read_bytes()).hexdigest(),row['sha256']);self.assertEqual(hashlib.sha256((base/'baselines'/row['baseline']).read_bytes()).hexdigest(),row['baselineSHA256'])
        self.assertEqual(self.L.CANDIDATE,V.SOURCE_SHA);self.assertEqual(self.T.CANDIDATE_SHA,V.SOURCE_SHA);self.assertEqual(len(self.T.CASES),40)
        # Final schema is explicit; 217 is assertions, never number of models.
        self.assertEqual(self.contract['totalPlanned'],217);self.assertEqual([x['count']for x in self.contract['groups']],[40,47,84,34,12]);self.assertEqual(json.loads((HERE/'known-current-receipts-index.json').read_bytes())['modelsRepresentedByStaticAssertions'],0)

    def test_03_helpers_and_frozen_guard(self):
        base=HERE/Path(TEST_BINDING['suite165']).parent
        raw=(base/'suite47/fixture_helpers.py').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b')
        self.assertEqual(raw,(base/'suite84/fixture_helpers.py').read_bytes());self.assertEqual(raw,(base/'suite34/fixture_helpers.py').read_bytes())
        t=ast.parse(raw);f=next(n for n in t.body if isinstance(n,ast.FunctionDef)and n.name=='environment');self.assertIn("for name in ('/probe', '/baseline', '/candidate')",ast.unparse(f))

    def test_04_qualification_pending_not_models_or_adoption(self):
        q=json.loads((HERE/TEST_BINDING['qualification']).read_bytes())
        index=json.loads((HERE/'known-current-receipts-index.json').read_bytes());self.assertEqual(index['staticAssertions'],217);self.assertEqual(index['staticGroups'],[40,47,84,34,12]);self.assertEqual(len(index['rows']),7);self.assertFalse(index['activeNative200Read']);self.assertFalse(index['APP6Read']);self.assertTrue(all(x['cleanupSuccess']and x['existingNineUnchanged']for x in index['rows']));self.assertEqual(q['native200']['status'],'PENDING');self.assertEqual(q['APP']['status'],'PENDING');self.assertFalse(q['adopted']);self.assertEqual(json.loads((HERE/'known-current-receipts-index.json').read_bytes())['modelsRepresentedByStaticAssertions'],0)

    def test_05_default_verifier_zero_source_IO(self):
        out=io.StringIO()
        with patch.object(Path,'read_bytes',side_effect=AssertionError('read forbidden')),patch.object(Path,'open',side_effect=AssertionError('open forbidden')),contextlib.redirect_stdout(out):self.assertEqual(self.V.main([]),0)
        self.assertEqual(json.loads(out.getvalue())['sourceFilesRead'],0)

    def test_06_external_source_confirmation_required(self):
        with patch.object(self.V,'held',side_effect=AssertionError('source read forbidden')):
            with self.assertRaisesRegex(ValueError,'explicit-installed-source-confirmation-required'):self.V.main(['--verify-source','--source','C:/not-read/scanner.py'])

    def test_07_real_entry_defaults_zero_source_IO(self):
        for module in [self.A,self.T,self.L]:
            out=io.StringIO()
            with patch.object(Path,'read_bytes',side_effect=AssertionError('read forbidden')),patch.object(Path,'open',side_effect=AssertionError('open forbidden')),patch.object(sys,'argv',['entry.py']),contextlib.redirect_stdout(out):
                # Existing holdout parser uses sys.argv; the other entries accept optional argv.
                self.assertEqual(module.main(),0)
            value=json.loads(out.getvalue());self.assertIn(value.get('mode',value.get('status')),{'DESCRIBE'})

    def test_08_windows_execute_refuses_before_source(self):
        with patch.object(self.A.sys,'platform','win32'),patch.object(self.A,'source',side_effect=AssertionError('source read forbidden')):
            with self.assertRaisesRegex(ValueError,'linux-low-uid'):self.A.main(['--execute','--root-idle-confirmed','--deadline','1'])

    def test_09_packet_copy_not_installed_source(self):
        with self.assertRaisesRegex(ValueError,'package-copy-is-not-installed-source'):self.V.verify_source(HERE/'source/deploy/security-scanner/scanner.py')

    def test_10_wrong_source_full_SHA(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'scanner.py';p.write_text('# harmless CODE metadata negative\n',encoding='ascii')
            with self.assertRaisesRegex(ValueError,'source-full-sha'):self.V.held(p)

    def test_11_source_changed_binding(self):
        p=Path(tempfile.gettempdir())/'external-installed/scanner.py';a={'path':str(p),'identity':[1]};b={'path':str(p),'identity':[2]}
        with patch.object(Path,'resolve',lambda p,*a,**k:p),patch.object(self.V,'held',side_effect=[a,b]):
            with self.assertRaisesRegex(ValueError,'source-changed-during-binding'):self.V.verify_source(p)

    def test_12_snapshot_and_previous_binding(self):
        V=self.V
        with tempfile.TemporaryDirectory()as d:
            source=Path(d)/'installed/scanner.py';q=Path(d)/'snapshot/scanner.py';a={'path':str(source),'identity':[1],'sha256':V.SOURCE_SHA};b={'path':str(q),'identity':[2],'sha256':V.SOURCE_SHA}
            previous=Path(d)/'previous.json';previous.write_text(json.dumps({'scope':'INSTALLED_SOURCE_VERIFIED_SNAPSHOT_METADATA_ONLY','status':'VERIFIED','source':a,'snapshot':b}),encoding='ascii')
            with patch.object(Path,'resolve',lambda p,*a,**k:p),patch.object(Path,'iterdir',return_value=iter([q])),patch.object(V,'held',side_effect=[a,b,a]):out=V.verify_source(source,q,previous)
            self.assertEqual(out['source'],a);self.assertEqual(out['snapshot'],b);self.assertFalse(out['adoptionEstablishedByVerifier'])

    def test_13_snapshot_extra_and_closed_allowlist(self):
        V=self.V;p=Path(tempfile.gettempdir())/'installed/scanner.py';q=Path(tempfile.gettempdir())/'snapshot/scanner.py'
        with patch.object(Path,'resolve',lambda p,*a,**k:p),patch.object(V,'held',return_value={'sha256':V.SOURCE_SHA}),patch.object(Path,'iterdir',return_value=iter([q,q.parent/'extra.txt'])):
            with self.assertRaisesRegex(ValueError,'snapshot-directory-not-single-code-file'):V.verify_source(p,q)
        # Real closed-tree verifier on harmless metadata; no package mutation.
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);good=root/'README.txt';good.write_text('harmless metadata only\n',encoding='ascii');body=good.read_bytes()
            (root/'allowlist.json').write_text(json.dumps({'schema':1,'files':[{'path':'README.txt','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}]}),encoding='ascii')
            with patch.object(V,'HERE',root):
                self.assertEqual(V.verify_package()['status'],'VERIFIED')
                (root/'UNLISTED.txt').write_text('metadata extra\n',encoding='ascii')
                with self.assertRaisesRegex(ValueError,'allowlist-exact-tree'):V.verify_package()

    def test_14_verifier_never_executes_source(self):
        t=ast.parse((HERE/TEST_BINDING['verifier']).read_bytes());calls=[n for n in ast.walk(t)if isinstance(n,ast.Call)]
        self.assertFalse(any(isinstance(n.func,ast.Name)and n.func.id in{'exec','eval','compile','__import__'}for n in calls));self.assertFalse(any(isinstance(n,ast.Import)and any(x.name in{'subprocess','torch','pickle'}for x in n.names)for n in ast.walk(t)))

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    print(json.dumps({'status':'PASS'if result.wasSuccessful()else'FAIL','tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'scope':'B2_PACKET_METADATA_AND_DEFAULT_GUARDS_ONLY','fixtureGenerated':False,'scannerExecuted':False,'VMExecuted':False,'DockerExecuted':False},sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful()else 1)
