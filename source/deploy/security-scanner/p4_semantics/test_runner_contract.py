"""Pure runner ownership/cleanup contracts plus harmless OS-pipe tests.
Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0

No Docker, scanner/component import, model or serialized fixture generation.
"""
import contextlib,hashlib,importlib.util,io,json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch

DRIVER_SHA='7c0f1801f084d8ed9fc059b4b023e316bf785439019bc817a38c92ac4c4cce6d'
HERE=Path(__file__).resolve().parent
_source=HERE/'run_container_tests.py'
_raw=_source.read_bytes()
if hashlib.sha256(_raw).hexdigest()!=DRIVER_SHA:raise ValueError('test-driver-pin')
_spec=importlib.util.spec_from_file_location('frozen_runner_contract_target',_source)
D=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(D)
CID='a'*64;OTHER='b'*64;RID='c'*32;NAME='matrixhub-semantics-'+RID;IMAGE='sha256:'+'d'*64

class EngineMock:
    """Only metadata commands; never executes an external process."""
    def __init__(self,cid=CID,identity=None,labels=None,names=None,ids=None,remain=False,engine_change=False):
        self.cid=cid;self.present=bool(cid);self.identity=identity;self.labels=labels;self.names=names;self.ids=ids;self.remain=remain;self.engine_change=engine_change;self.calls=[];self.removes=[];self.info_calls=0
    def command(self,args):
        args=list(args);self.calls.append(args)
        if args[0]=='ps':
            key=args[-1]
            if key.startswith('label='):values=self.labels if self.labels is not None else ([self.cid] if self.present else [])
            elif key.startswith('name='):values=self.names if self.names is not None else ([self.cid] if self.present else [])
            elif key.startswith('id='):values=self.ids if self.ids is not None else ([self.cid] if self.present and key=='id='+self.cid else [])
            else:raise AssertionError('unbounded-selector')
            return 0,('\n'.join(values)+'\n').encode(),b''
        if args[0]=='info':
            self.info_calls+=1;return 0,('engine-2' if self.engine_change and self.info_calls>1 else 'engine-1').encode(),b''
        if args[0]=='inspect':
            value=self.identity if self.identity is not None else {'id':self.cid,'name':'/'+NAME,'image':IMAGE,'owner':RID}
            return 0,json.dumps(value).encode() if isinstance(value,dict) else value,b''
        if args[0]=='rm':
            assert args==['rm','-f',self.cid];self.removes.append(args[-1]);self.present=self.remain;return 0,b'',b''
        raise AssertionError('unexpected-engine-command')
    def no_global_mutations(self):
        assert all(x[0] in {'ps','info','inspect','rm'} and 'prune' not in x for x in self.calls)

class OwnershipAndCleanup(unittest.TestCase):
    def clean(self,e,attempted=True,confirmed=False,expected=None):
        try:return D.cleanup_created(e.command,RID,NAME,IMAGE,attempted,confirmed,expected)
        finally:e.no_global_mutations()
    def test_no_create_attempt_is_clean_without_engine_calls(self):
        e=EngineMock();self.assertEqual(self.clean(e,False),{'createdAttempted':False,'ownedAbsent':True});self.assertEqual(e.calls,[])
    def test_unknown_create_empty_is_not_claimed_clean(self):
        e=EngineMock(cid=None)
        with self.assertRaisesRegex(ValueError,'create-outcome-unconfirmed'):self.clean(e)
        self.assertEqual(e.removes,[])
    def test_unknown_timeout_can_recover_only_exact_triple(self):
        e=EngineMock();r=self.clean(e);self.assertEqual(r['removedId'],CID);self.assertTrue(r['ownedAbsent']);self.assertFalse(r['creationConfirmed']);self.assertEqual(e.removes,[CID])
    def test_confirmed_exact_cid_is_removed(self):
        e=EngineMock();r=self.clean(e,confirmed=True,expected=CID);self.assertTrue(r['creationConfirmed']);self.assertEqual(e.removes,[CID])
    def test_confirmed_replacement_same_triple_is_never_removed(self):
        e=EngineMock(cid=OTHER)
        with self.assertRaisesRegex(ValueError,'cleanup-container-replaced'):self.clean(e,confirmed=True,expected=CID)
        self.assertEqual(e.removes,[]);self.assertFalse(any(x[0]=='inspect' for x in e.calls))
    def test_confirmed_absence_also_queries_original_full_cid(self):
        e=EngineMock(cid=None);r=self.clean(e,confirmed=True,expected=CID);self.assertEqual(r['confirmedId'],CID);self.assertIn(['ps','-a','-q','--no-trunc','--filter','id='+CID],e.calls)
    def test_confirmed_hidden_original_cid_prevents_false_absence(self):
        e=EngineMock(cid=None,ids=[CID])
        with self.assertRaisesRegex(ValueError,'confirmed-container-still-exists'):self.clean(e,confirmed=True,expected=CID)
        self.assertEqual(e.removes,[])
    def test_confirmation_context_must_have_attempt_and_full_cid(self):
        for attempted,confirmed,expected in [(False,True,CID),(True,True,None),(True,True,'abc'),(True,False,CID)]:
            e=EngineMock()
            with self.assertRaisesRegex(ValueError,'cleanup-confirmed-cid-context'):self.clean(e,attempted,confirmed,expected)
            self.assertEqual(e.calls,[])
    def test_wrong_owner_name_image_or_full_id_cannot_be_removed(self):
        good={'id':CID,'name':'/'+NAME,'image':IMAGE,'owner':RID}
        for field,value in [('owner','foreign'),('name','/foreign'),('image','sha256:'+'e'*64),('id',OTHER)]:
            e=EngineMock(identity=dict(good,**{field:value}))
            with self.assertRaisesRegex(ValueError,'owned-container-identity'):self.clean(e)
            self.assertEqual(e.removes,[])
    def test_label_name_disagreement_never_removes(self):
        e=EngineMock(labels=[CID],names=[OTHER])
        with self.assertRaisesRegex(ValueError,'cleanup-owner-name-agreement'):self.clean(e)
        self.assertEqual(e.removes,[])
    def test_multiple_or_truncated_selected_cids_never_remove(self):
        for selected in [[CID,OTHER],['a'*63],['A'*64]]:
            e=EngineMock(labels=selected,names=selected)
            with self.assertRaisesRegex(ValueError,'cleanup-selected-cids'):self.clean(e)
            self.assertEqual(e.removes,[])
    def test_post_remove_presence_is_failure(self):
        e=EngineMock(remain=True)
        with self.assertRaisesRegex(ValueError,'cleanup-absence'):self.clean(e)
        self.assertEqual(e.removes,[CID])
    def test_changed_engine_after_owned_removal_is_failure(self):
        e=EngineMock(engine_change=True)
        with self.assertRaisesRegex(ValueError,'cleanup-same-engine'):self.clean(e)
        self.assertEqual(e.removes,[CID])
    def test_failed_engine_query_prevents_removal(self):
        e=EngineMock()
        def command(args):
            if args[0]=='info':raise TimeoutError('fixed-mock-timeout')
            return e.command(args)
        with self.assertRaises(TimeoutError):D.cleanup_created(command,RID,NAME,IMAGE,True,False)
        self.assertEqual(e.removes,[])
    def test_inspect_rejects_short_cid_before_command(self):
        with self.assertRaisesRegex(ValueError,'owned-full-cid'):D.inspect_owned(lambda _:self.fail('command'),'a'*63,RID,NAME,IMAGE)
    def test_duplicate_identity_json_keys_are_rejected(self):
        raw=b'{"id":"'+CID.encode()+b'","owner":"one","owner":"two"}'
        with self.assertRaisesRegex(ValueError,'duplicate-json'):D.inspect_owned(lambda _:(0,raw,b''),CID,RID,NAME,IMAGE)

class MainEngineMock:
    def __init__(self,mode='success',clock=None):self.mode=mode;self.clock=clock;self.calls=[];self.records=[];self.present=False;self.number=0;self.rid=None;self.name=None;self.cid=None;self.image=IMAGE;self.script=None;self.cleanup_seconds=[]
    def bounded(self,argv,env,seconds,stdout_cap=131072,stderr_cap=32768):
        args=list(argv[5:]);self.calls.append(args);D.need(seconds>0,'operation-deadline')
        if args[0]=='image':return 0,self.image.encode(),b''
        if args[0]=='create':
            self.number+=1;self.cid=('a' if self.number==1 else 'b')*64;self.name=args[args.index('--name')+1];self.rid=args[args.index('--label')+1].split('=',1)[1];self.script='p4' if '/probe/linux_p4_tests.py' in args else 'ascii'
            self.present=self.mode!='unknown-empty'
            if self.mode.startswith('unknown-'):raise TimeoutError('fixed-create-timeout')
            if self.mode=='truncated-create':return 0,b'abc',b''
            return 0,self.cid.encode(),b''
        if args[0]=='inspect':
            if args[2]=='{{.State.ExitCode}}':return 0,b'0',b''
            owner='foreign' if self.mode=='wrong-prestart-owner' else self.rid
            return 0,json.dumps({'id':self.cid,'name':'/'+self.name,'image':self.image,'owner':owner}).encode(),b''
        if args[0]=='start':
            if self.mode=='business-timeout':self.clock[0]=91;raise TimeoutError('fixed-business-timeout')
            count=84 if self.script=='p4' else 34
            if self.mode=='replacement':self.cid='e'*64
            return 0,json.dumps({'status':'PASS','tests':count,'passed':count,'candidateSHA256':D.SOURCE,'AVRun':False}).encode(),b''
        if args[0]=='ps':
            self.cleanup_seconds.append(seconds);key=args[-1]
            selected=self.present and ((key.startswith('label=') and key.endswith('='+self.rid)) or key=='name=^/'+self.name+'$' or key=='id='+self.cid)
            return 0,(self.cid+'\n').encode() if selected else b'',b''
        if args[0]=='info':self.cleanup_seconds.append(seconds);return 0,b'engine-fixed',b''
        if args[0]=='rm':self.cleanup_seconds.append(seconds);assert args==['rm','-f',self.cid];self.present=False;return 0,b'',b''
        raise AssertionError('unexpected-Docker-operation')

class MainContracts(unittest.TestCase):
    def run_main(self,mode):
        clock=[0.0];engine=MainEngineMock(mode,clock)
        with tempfile.TemporaryDirectory(prefix='semantic-runner-contract-') as tmp:
            base=Path(tmp);fake_docker=base/'docker-not-executed';fake_docker.write_text('metadata only; never executed',encoding='utf-8');output=base/'output'
            endpoint='npipe:////./pipe/dockerDesktopLinuxEngine' if D.os.name=='nt' else 'unix:///var/run/docker.sock'
            argv=['--execute','--heavy-idle-confirmed','--docker',str(fake_docker),'--engine',endpoint,'--image',IMAGE,'--output',str(output)]
            with patch.object(D,'bounded_process',side_effect=engine.bounded),patch.object(D.time,'monotonic',side_effect=lambda:clock[0]),patch('sys.stdout',io.StringIO()),patch.object(D,'cleanup_created',wraps=D.cleanup_created) as cleanup:
                rc=D.main(argv);calls=list(cleanup.call_args_list)
            summary=json.loads((output/'summary.json').read_bytes());records=[json.loads(p.read_bytes()) for p in output.glob('*.json') if p.name!='summary.json']
            self.assertFalse(any('prune' in c for c in engine.calls));return rc,summary,records,engine,calls
    def test_default_describe_has_no_source_or_docker_io(self):
        with patch.object(D,'digest',side_effect=AssertionError('source')),patch.object(D.Path,'is_file',side_effect=AssertionError('file-I/O')),patch.object(D,'bounded_process',side_effect=AssertionError('Docker')),patch('sys.stdout',io.StringIO()) as stream:
            self.assertEqual(D.main([]),0);value=json.loads(stream.getvalue());self.assertFalse(value['sourceRead']);self.assertFalse(value['dockerCalled'])
    def test_idle_confirmation_required_before_io(self):
        with patch.object(D.Path,'is_file',side_effect=AssertionError('I/O')),patch.object(D,'bounded_process',side_effect=AssertionError('Docker')):
            with self.assertRaisesRegex(ValueError,'explicit-idle-confirmation'):D.main(['--execute'])
    def test_real_main_success_two_suites_owned_cleanup(self):
        rc,result,records,engine,cleanup=self.run_main('success');self.assertEqual(rc,0);self.assertEqual(result['status'],'PASS');self.assertEqual(len(records),2)
        self.assertEqual(sorted(x['result']['passed'] for x in records),[34,84]);self.assertEqual([x['passed'] for x in result['suites']],[84,34]);self.assertTrue(all(x['cleanupSuccess'] for x in records))
        self.assertTrue(all(c.args[-2] is True and len(c.args[-1])==64 for c in cleanup));self.assertEqual(len([x for x in engine.calls if x[0]=='start']),2)
        for args in [x for x in engine.calls if x[0]=='create']:
            self.assertEqual(args[args.index('--network')+1],'none');self.assertIn('--read-only',args);self.assertEqual(args[args.index('--pull')+1],'never')
        for index,args in enumerate(engine.calls):
            if args[0]=='start':
                create_at=max(i for i,c in enumerate(engine.calls[:index]) if c[0]=='create')
                self.assertTrue(any(c[0]=='inspect' and '"owner"' in c[2] for c in engine.calls[create_at+1:index]))
    def test_unknown_create_empty_stays_failed_unclean(self):
        rc,result,records,engine,cleanup=self.run_main('unknown-empty');self.assertEqual(rc,2);self.assertFalse(records[0]['cleanupSuccess']);self.assertEqual(len(records),1);self.assertFalse(any(x[0] in {'rm','start'} for x in engine.calls));self.assertTrue(cleanup[0].args[-3]);self.assertFalse(cleanup[0].args[-2]);self.assertIsNone(cleanup[0].args[-1])
    def test_unknown_create_recovered_triple_is_clean_but_suite_failed(self):
        rc,result,records,engine,cleanup=self.run_main('unknown-recovered');self.assertEqual(rc,2);self.assertEqual(result['status'],'FAIL');self.assertTrue(records[0]['cleanupSuccess']);self.assertFalse(records[0]['cleanup']['creationConfirmed']);self.assertFalse(any(x[0]=='start' for x in engine.calls))
    def test_truncated_create_cid_is_not_trusted(self):
        rc,result,records,engine,cleanup=self.run_main('truncated-create');self.assertEqual(rc,2);self.assertTrue(records[0]['cleanupSuccess']);self.assertIsNone(cleanup[0].args[-1]);self.assertFalse(any(x[0]=='start' for x in engine.calls))
    def test_prestart_bad_owner_never_starts(self):
        rc,result,records,engine,cleanup=self.run_main('wrong-prestart-owner');self.assertEqual(rc,2);self.assertFalse(any(x[0]=='start' for x in engine.calls));self.assertFalse(records[0]['cleanupSuccess'])
    def test_confirmed_replacement_is_not_removed_by_main(self):
        rc,result,records,engine,cleanup=self.run_main('replacement');self.assertEqual(rc,2);self.assertFalse(records[0]['cleanupSuccess']);self.assertFalse(any(x[0]=='rm' for x in engine.calls));self.assertEqual(cleanup[0].args[-1],'a'*64)
    def test_cleanup_uses_independent_budget_after_business_timeout(self):
        rc,result,records,engine,cleanup=self.run_main('business-timeout');self.assertEqual(rc,2);self.assertTrue(records[0]['cleanupSuccess']);self.assertEqual(records[0]['wholeSeconds'],91)
        self.assertTrue(engine.cleanup_seconds);self.assertTrue(all(0<s<=24 for s in engine.cleanup_seconds));self.assertFalse(any(x[0]=='create' for x in engine.calls[engine.calls.index(next(x for x in engine.calls if x[0]=='start'))+1:]))

STATS={'processes':0,'readers':0,'leakedProcesses':0,'leakedReaders':0}


def bounded_suite(D):
 class BoundedProcess(unittest.TestCase):
  @contextlib.contextmanager
  def observed(self):
   children=[];readers=[];real_popen=D.subprocess.Popen;real_thread=D.threading.Thread
   def popen(*args,**kw):
    p=real_popen(*args,**kw);children.append(p);STATS["processes"]+=1;return p
   def thread(*args,**kw):
    t=real_thread(*args,**kw);readers.append(t);STATS["readers"]+=1;return t
   try:
    with patch.object(D.subprocess,"Popen",side_effect=popen),patch.object(D.threading,"Thread",side_effect=thread):
     yield children,readers
   finally:
    leaked_p=[p for p in children if p.poll()is None];leaked_t=[t for t in readers if t.is_alive()]
    STATS["leakedProcesses"]+=len(leaked_p);STATS["leakedReaders"]+=len(leaked_t)
    # Rescue exact owned children after collecting failure evidence, never unrelated processes.
    for p in leaked_p:p.kill();p.wait(timeout=5)
    for t in readers:t.join(2)
    self.assertEqual(leaked_p,[],"bounded_process returned/raised with live owned child")
    self.assertEqual(leaked_t,[],"bounded_process returned/raised with live reader")
    self.assertEqual(len(readers),2*len(children))
    for p in children:
     self.assertIsNotNone(p.returncode);self.assertTrue(p.stdout.closed);self.assertTrue(p.stderr.closed)
  def call(self,code,seconds=3,stdout_cap=131072,stderr_cap=32768):
   # Minimal fixed environment. No host account/proxy/Docker environment is read.
   return D.bounded_process([sys.executable,"-I","-B","-c",code],{"SYSTEMROOT":"C:/Windows"} if sys.platform=="win32" else {},seconds,stdout_cap,stderr_cap)
  def test_normal_bounded_stdout_and_stderr(self):
   with self.observed():
    code,out,err=self.call("import os;os.write(1,b'ordinary stdout');os.write(2,b'ordinary stderr')")
   self.assertEqual((code,out,err),(0,b"ordinary stdout",b"ordinary stderr"))
  def test_exact_caps_accepted(self):
   with self.observed():
    code,out,err=self.call("import os;os.write(1,b'O'*4096);os.write(2,b'E'*2048)",stdout_cap=4096,stderr_cap=2048)
   self.assertEqual(code,0);self.assertEqual(out,b"O"*4096);self.assertEqual(err,b"E"*2048)
  def test_nonzero_exit_preserves_bounded_output(self):
   with self.observed():
    code,out,err=self.call("import os,sys;os.write(2,b'controlled exit');sys.exit(7)")
   self.assertEqual((code,out,err),(7,b"",b"controlled exit"))
  def test_live_stdout_overflow_kills_and_joins(self):
   with self.observed():
    with self.assertRaisesRegex(ValueError,"bounded-(process|output)-failed"):
     self.call("import os,time;os.write(1,b'S'*512);time.sleep(10)",stdout_cap=128)
  def test_live_stderr_overflow_kills_and_joins(self):
   with self.observed():
    with self.assertRaisesRegex(ValueError,"bounded-(process|output)-failed"):
     self.call("import os,time;os.write(2,b'E'*512);time.sleep(10)",stderr_cap=128)
  def test_fast_exit_stdout_overflow_still_rejected(self):
   for _ in range(3):
    with self.observed():
     with self.assertRaisesRegex(ValueError,"bounded-(process|output)-failed"):
      self.call("import os;os.write(1,b'F'*256)",stdout_cap=16)
  def test_fast_exit_stderr_overflow_still_rejected(self):
   for _ in range(3):
    with self.observed():
     with self.assertRaisesRegex(ValueError,"bounded-(process|output)-failed"):
      self.call("import os;os.write(2,b'F'*256)",stderr_cap=16)
  def test_deadline_kills_reaps_child_and_joins_readers(self):
   start=time.monotonic()
   with self.observed():
    with self.assertRaisesRegex(ValueError,"bounded-process-failed"):
     self.call("import time;time.sleep(10)",seconds=.15)
   self.assertLess(time.monotonic()-start,5)
  def test_nonpositive_seconds_refuses_before_Popen(self):
   for seconds in [0,-1,-.01,float("nan")]:
    with patch.object(D.subprocess,"Popen",side_effect=AssertionError("Popen-must-not-run")) as popen:
     with self.assertRaisesRegex(ValueError,"operation-deadline"):
      D.bounded_process(["not-executed"],{},seconds)
     popen.assert_not_called()
  def test_empty_output_with_zero_caps_is_bounded(self):
   with self.observed():
    self.assertEqual(self.call("pass",stdout_cap=0,stderr_cap=0),(0,b"",b""))
 return unittest.defaultTestLoader.loadTestsFromTestCase(BoundedProcess)

def load_tests(loader, tests, pattern):
    tests.addTests(bounded_suite(D))
    return tests

if __name__=='__main__':
    unittest.main()
