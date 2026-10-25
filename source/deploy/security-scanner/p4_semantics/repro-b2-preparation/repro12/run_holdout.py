"""Independent frozen-source static holdout. All fixtures are Linux RAM-only."""
import argparse,ast,hashlib,io,json,os,pickletools,struct,stat,sys,tempfile,time,warnings,zipfile
from pathlib import Path
BASELINE='8bffc514fa56b14b506c57629f4970a3197133f7a7d0b0a62348d392a125e05f'
CANDIDATE='b2e80d9544f0c5dd313d3758107ea6069b0c0a742cd7f78030901aabea7ffda6'
HELPER='7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b'
FROZEN47='e05fbbcf55d9c5565cb1c99f5e8aefdb3b71f772ca49b0341379802bbff6dbc8'
PLAN_SHA256='ff241b441c223617210ae2f4dab45e4258add88c1a61d4716a2db2d7f34bf45a'
SCOPE='INDEPENDENT_EXISTS_POSITIVE_MISSING_STATIC_HOLDOUT12_NOT_FULLAV_OR_ADOPTION'
def need(v,c):
 if not v:raise ValueError(c)
def load(path,pin,name,H=None):
 if H:raw=H.bounded_sha(path,pin)
 else:
  p=Path(path);need(not p.is_symlink()and all(not q.is_symlink()for q in p.parents),'initial-source-nolinks');before=p.lstat()
  with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as f:first=os.fstat(f.fileno());raw=f.read(512001);last=os.fstat(f.fileno())
  after=p.lstat();stamp=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  need(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and 0<len(raw)<=512000 and stamp(before)==stamp(first)==stamp(last)==stamp(after),'initial-source-held-identity')
 need(0<len(raw)<=512000 and hashlib.sha256(raw).hexdigest()==pin,'fixed-source-pin')
 m=type(sys)(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');parser.add_argument('--deadline',type=int);parser.add_argument('--root-idle-confirmed',action='store_true');a=parser.parse_args()
 if not a.execute:print(json.dumps({'status':'DESCRIBE','scope':SCOPE,'inputFilesRead':False,'DockerExecuted':False,'fixturesGenerated':0}));return 0
 need(sys.platform=='linux'and os.geteuid()==os.getegid()==65532 and a.root_idle_confirmed is True and type(a.deadline)is int and 0<a.deadline-time.time()<=120,'linux-only-fresh-root')
 H=load('/probe/fixture_helpers.py',HELPER,'holdout_fixed_H');cap=H.environment(a.deadline,True)
 B=load('/baseline/scanner.py',BASELINE,'holdout_frozen_8b',H);C=load('/candidate/scanner.py',CANDIDATE,'holdout_frozen_6062',H)
 F=load('/probe/frozen47.py',FROZEN47,'holdout_frozen_fixture_definitions',H)
 plan=json.loads(H.bounded_sha('/probe/plan.json',PLAN_SHA256));need(type(plan)is dict and len(plan['cases'])==12 and plan['baselineSHA256']==BASELINE and plan['candidateSHA256']==CANDIDATE,'fixed-plan')
 tree=ast.parse(H.bounded_sha('/probe/frozen47.py',FROZEN47));run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run');names={'P4Builder','modern_wire','SpecBuilder','metadata','package'};nodes=[n for n in run.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names];need(len(nodes)==5,'five-frozen-builder-definitions')
 # B is explicitly the already frozen8b module, not the old47 default7cd.
 # These definitions run only after all source pins and the full H guard.
 space={'H':H,'cap':cap,'B':B,'io':io,'pickletools':pickletools,'struct':struct,'sys':sys,'zipfile':zipfile,'warnings':warnings,'need':need};exec(compile(ast.Module(body=nodes,type_ignores=[]),'five-fixed-47-definitions','exec'),space)
 def package(raw,members,first):
  need(sys.platform=='linux'and cap is not None,'linux-generation')
  entries=[('archive/data.pkl',raw),('archive/version',b'3\n')];entries=members+entries if first else entries+members
  out=io.BytesIO()
  with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED,allowZip64=False)as archive:
   for name,value in entries:
    z=zipfile.ZipInfo(name,(1980,1,1,0,0,0));z.external_attr=0o100600<<16;archive.writestr(z,value)
  return out.getvalue()
 def witness(module,path):
  with path.open('rb')as stream:v=module.observe_protocol4_storage_mismatch(stream,dict(F.LIMITS))
  if v is None:return None
  if type(v)is module._MissingStorageRecord:return'MISSING'
  if type(v)is module._StorageLengthMismatch:return'LENGTH'
  return'UNEXPECTED_WITNESS'
 records=[];total=0
 with tempfile.TemporaryDirectory(prefix='exists-holdout-',dir='/tmp')as tmp:
  for row in plan['cases']:
   need(time.time()<a.deadline,'holdout-deadline')
   metadata=space['metadata'](row['specs']);members=[('archive/data/'+m['key'],bytes(m['bytes']))for m in row['members']]
   blob=package(metadata,members,row['recordsFirst']);total+=len(blob);need(len(blob)<=4096 and total<=1<<20,'aggregate-fixture-bound')
   path=Path(tmp)/(row['id']+'.pt');path.write_bytes(blob);digest=hashlib.sha256(blob).hexdigest();size=len(blob);del blob
   old=F.outcome(B,path,dict(F.LIMITS));new=F.outcome(C,path,dict(F.LIMITS));ow=witness(B,path);nw=witness(C,path)
   known=all(x['code']not in {'UNEXPECTED_OPERATION','UNCLASSIFIED_INCOMPLETE'}and x['operation']!='OTHER'for x in [old,new])and ow!='UNEXPECTED_WITNESS'and nw!='UNEXPECTED_WITNESS'
   if row['expected']=='new_deny':ok=known and ow is None and old['complete']and old['code']is None and old['highCriticalFindings']==0 and nw=='MISSING'and not new['complete']and new['code']=='invalid_serialization'
   elif row['expected']=='same_deny':ok=known and old==new and ow==nw=='MISSING'and not new['complete']and new['code']=='invalid_serialization'
   elif row['expected']=='same_unproven':ok=known and old==new and ow is nw is None
   else:raise ValueError('fixed-plan-expectation')
   need(path.stat().st_size==size and hashlib.sha256(path.read_bytes()).hexdigest()==digest,'same-file-postSHA')
   records.append({'id':row['id'],'passed':bool(ok),'expected':row['expected'],'fixtureBytes':size,'fixtureSHA256':digest,'baseline':old,'candidate':new,'baselineWitness':ow,'candidateWitness':nw,'sameInputPrePostSHA':True});path.unlink()
 H.bounded_sha('/baseline/scanner.py',BASELINE);H.bounded_sha('/candidate/scanner.py',CANDIDATE);H.bounded_sha('/probe/frozen47.py',FROZEN47);H.bounded_sha('/probe/fixture_helpers.py',HELPER);H.bounded_sha('/probe/plan.json',PLAN_SHA256)
 result={'schema':1,'status':'PASS'if all(x['passed']for x in records)else'FAIL','scope':SCOPE,'tests':12,'passed':sum(x['passed']for x in records),'baselineSHA256':BASELINE,'candidateSHA256':CANDIDATE,'planSHA256':PLAN_SHA256,'fixtureBytesGenerated':total,'records':records,'sameInputComparison':True,'fullStaticInspectorAndObserverBothReal':True,'AVRun':False,'modelLoaded':False,'qualifiedAcceptance':False,'sourceAdopted':False,'old165OracleClaimed':False}
 encoded=json.dumps(result,sort_keys=True);need(len(encoded.encode())<=128<<10,'bounded-output');print(encoded);return 0 if result['status']=='PASS'else 2
if __name__=='__main__':
 try:raise SystemExit(main())
 except SystemExit:raise
 except BaseException as error:
  allowed={'ValueError','OSError','TimeoutError','MemoryError','KeyboardInterrupt'};print(json.dumps({'schema':1,'status':'REFUSED','scope':SCOPE,'exceptionType':type(error).__name__ if type(error).__name__ in allowed else'OTHER','qualifiedAcceptance':False,'rawExceptionExported':False}));raise SystemExit(2)
