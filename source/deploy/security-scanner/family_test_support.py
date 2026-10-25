# Copyright The MatrixHub Authors.
# Licensed under the Apache License, Version 2.0.
"""Portable public metadata fixtures and harmless token facade; no model loading.
Default scanner dependency is this product directory's scanner.py. The source-only
C runner may supply MATRIXHUB_FAMILY_TEST_SCANNER_SOURCE; exact B2 SHA is mandatory
before importing it. No .pth, model, rule database or account is opened.
"""
import contextlib,copy,hashlib,importlib.util,json,os,socketserver,sys,time,types
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
FIXTURES=HERE/'family_fixtures'
def load_verified(name,path,pin):
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('reviewed-public-source-pin')
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
P=load_verified('family_projection_under_test',HERE/'safe_weight_family_projection.py','be9d81d509a14939ce03bb7cfa8a2bf034676bc24a79da9f590df4cdf4471714')
SCANNER_PATH=Path(os.environ.get('MATRIXHUB_FAMILY_TEST_SCANNER_SOURCE',str(HERE/'scanner.py')))
def forbidden_resource(*args,**kwargs):raise AssertionError('pure tests forbid resource changes')
resource_stub=types.ModuleType('resource');resource_stub.setrlimit=forbidden_resource;resource_stub.getrlimit=forbidden_resource
class UnavailableUnixServer:
 def __init__(self,*args,**kwargs):raise AssertionError('pure tests forbid server construction')
with patch.dict(sys.modules,{'resource':resource_stub}),patch.object(socketserver,'UnixStreamServer',UnavailableUnixServer,create=True):
 REAL_SCANNER=load_verified('unchanged_b2_metadata_only',SCANNER_PATH,P.SOURCE_SHA)
bundle_raw=(FIXTURES/'expected_bundle.json').read_bytes()
if hashlib.sha256(bundle_raw).hexdigest()!='f6804cf33028ae34d794ae5e0476da8dd4bb6c40953f78fd06371295bb94b4d4':raise ValueError('reviewed-complete-bundle-fixture')
BUNDLE=json.loads(bundle_raw)

class OriginalFailure(Exception):pass
class Global:
 def __init__(self,module,symbol):self.name=(module,symbol)
class Map:
 def __init__(self,ordered=False):self.ordered,self.items,self.state=ordered,{},None
class List:
 def __init__(self):self.items=[]
class Storage:
 def __init__(self,key="0",kind="FloatStorage",numel=2):
  self.key,self.kind,self.numel,self.width=key,kind,numel,4
class Tensor:
 def __init__(self,storage,offset,shape,stride,hooks,metadata=None):
  self.storage,self.offset,self.shape,self.stride=storage,offset,shape,stride
  self.hooks,self.metadata=hooks,metadata
class Parameter:pass
class Base:
 """Only a harmless token facade; not a reimplementation qualification."""
 MARK=object()
 def __init__(self,limits):
  self.limits,self.max_slots=limits,65536
  self.stack,self.marks,self.maps,self.tensors=[],[],[],[]
  self.nodes,self.edges=0,0
 def budget(self,nodes=0,edges=0):
  self.nodes+=nodes;self.edges+=edges
  if self.nodes+self.edges+len(self.stack)>self.max_slots:raise OriginalFailure()
 def need(self,n):
  if len(self.stack)<n:raise OriginalFailure()
 def push(self,value):self.stack.append(value)
 def pop(self,n=1):
  self.need(n);values=self.stack[-n:];del self.stack[-n:]
  return values[0]if n==1 else values
 def marked(self):
  if not self.marks:raise OriginalFailure()
  index=self.marks.pop();out=self.stack[index+1:];del self.stack[index:];return out
 def mapping(self,ordered=False):
  value=Map(ordered);self.maps.append(value);return value
 def reduce(self,target,args):
  if target.name==("collections","OrderedDict"):
   if args:raise OriginalFailure()
   return self.mapping(True)
  if target.name!=("torch._utils","_rebuild_tensor_v2")or len(args)not in(6,7):raise OriginalFailure()
  storage,offset,shape,stride,grad,hooks=args[:6]
  metadata=args[6]if len(args)==7 else None
  effect=None if metadata is None else False if type(metadata)is Map and not metadata.items else True
  value=Tensor(storage,offset,shape,stride,hooks,effect);self.tensors.append(value);return value
 def persistent(self,value):
  self.last_pid=value
  return Storage(value[2],value[1].name[1],value[4])
 def final_tokens(self,root):pass
 def apply(self,name,arg):raise OriginalFailure()
S=types.SimpleNamespace(LegacyGlobal=Global,LegacyMap=Map,LegacyList=List,
 LegacyStorage=Storage,LegacyTensor=Tensor,_ZipParameter=Parameter,
 _ZipParameterMachine=Base,LegacyTorchError=OriginalFailure,
 _PARAMETER_SYMBOL=("torch._utils","_rebuild_parameter"),
 NESTED_DESERIALIZATION_SYMBOL=("torch.storage","_load_from_bytes"),
 LEGACY_GLOBALS={("collections","OrderedDict"),("torch._utils","_rebuild_tensor_v2"),("torch","FloatStorage")},
 known_dangerous_reference=lambda pair:pair in{("os","system"),("builtins","eval")})
LIMITS={"max_members":256,"max_pickle_opcodes":65536,"max_pickle_argument":32768}
Machine=P.machine_class(S)
def build_tensor(machine,key="0",metadata=None,shape=(2,),stride=(1,),numel=2):
 storage=Storage(key,numel=numel);hooks=Map(True)
 return machine.reduce(Global("torch._utils","_rebuild_tensor_v2"),
                       (storage,0,shape,stride,False,hooks,metadata))
def root_for(machine,tensor=None):
 selected=machine.mapping(True);selected.items["weight"]=build_tensor(machine)if tensor is None else tensor
 root=machine.mapping();root.items["state_dict"]=selected
 return root,selected

def text(value):
 raw=value.encode('utf-8');assert len(raw)<256
 return b'\x8c'+bytes([len(raw)])+raw
def glob(module,name):return b'c'+module.encode()+b'\n'+name.encode()+b'\n'
def integer(n):assert 0<=n<256;return b'K'+bytes([n])
ORDERED=glob('collections','OrderedDict')+b')R'
def tensor(key='0',numel=2,offset=0,stride=1,kind='FloatStorage',device='cpu'):
 storage=b'('+text('storage')+glob('torch',kind)+text(key)+text(device)+integer(numel)+b'tQ'
 return glob('torch._utils','_rebuild_tensor_v2')+b'('+storage+integer(offset)+integer(numel)+b'\x85'+integer(stride)+b'\x85\x89'+ORDERED+b'tR'
def metadata(name='weight',numel=2,extra=None,**kw):
 # Protocol4 opcodes are passive bytes interpreted solely by the finite B2 VM.
 raw=b'\x80\x04}'+text('state_dict')+ORDERED+b'q\x00'+text(name)+tensor(numel=numel,**kw)+b'ss'
 if extra is not None:raw+=text('non_exported')+extra+b's'
 return raw+b'.'
A=metadata(extra=glob('trusted_inert_fixture','TrainingMetadata')+b')R')
B=metadata('different_weight',3,extra=glob('trusted_inert_fixture','OtherMetadata')+b')R')
def profile(slot,raw):
 return {'slot':slot,'status':'READY','inputSHA256':hashlib.sha256(('SYNTHETIC-NOT-AN-ARCHIVE-'+slot).encode()).hexdigest(),
         'inputBytes':1024 if slot=='reference' else 2048,'dataPickleSHA256':P.sha(raw),'dataPickleBytes':len(raw),
         'originNamespace':'test','originRepository':'test/public-'+slot,'originRevision':('a' if slot=='reference' else 'b')*40,
         'originVersionEvidenceSHA256':('9' if slot=='reference' else '8')*64,
         'originBlobPath':slot+'.pth','sourceAVScope':'PURE_METADATA_TEST_ONLY','sourceAVFullScope':'PURE_FULL_AV_SHAPE_ONLY',
         'sourceAVCaseId':slot}
@contextlib.contextmanager
def approved_metadata_fixture(raw_a=A,raw_b=B):
 registry=P.canonical({'schema':1,'profiles':[profile('reference',raw_a),profile('independent',raw_b)]})
 with patch.multiple(P,TRUSTED_PROFILES_RAW=registry,TRUSTED_PROFILES_SHA256=P.sha(registry)):
  yield
def binding(slot='reference'):
 prof=P.trusted_profile(slot)
 out={'schema':1,'profileSlot':slot,'profileSHA256':P.sha(P.canonical(prof)),'projectionPolicySHA256':P.policy_sha256(),
      'versionAuthority':P.VERSION_AUTHORITY}
 out.update({k:prof[v]for k,v in P._UPSTREAM_BINDINGS})
 out.update({k:prof[k]for k in P._IDENTITY_KEYS});return out
def context(slot='reference'):
 raw=P.canonical(binding(slot));return P._Context(time.time()+60,'e'*64,P.policy_sha256(),slot,raw,P.sha(raw))
def parse(raw,slot='reference'):
 ctx=context(slot);limits=dict(BUNDLE['evidence']['limits'],max_pickle_opcodes=P.MAX_SLOTS,max_pickle_argument=P.MAX_METADATA)
 with patch.object(P.sys,'platform','linux'):
  return P.machine_class(REAL_SCANNER)(limits).parse_projection(raw,ctx)
def av_fixture(slot='reference'):
 source=binding(slot);raw_binding=P.canonical(source);prof=P.trusted_profile(slot)
 case={'id':prof['sourceAVCaseId'],'sha256':source['inputSHA256'],'bytes':source['inputBytes'],'executionStatus':'EXECUTED',
       'failure':None,'technicalPass':True,'fullWorkerResultAvailable':True,'heldFDPrePostUnchanged':True,
       'prePostIdentityUnchanged':True,'recoveryFullScanPassed':True,
       'observation':{'httpStatus':200,'protocolValid':True,'identityMatched':True,'generationMatched':True,'requestError':None,
         'complete':False,'admission':'deny','coverageCodes':['unsupported_container_or_serialization'],
         'rules':['pickle.unknown-global'],'severities':['medium']}}
 full={'scope':prof['sourceAVFullScope'],'status':'PASS','fullAV':True,'failure':None,'sourceSHA256':P.SOURCE_SHA,
       'generation':P.REFERENCE_GEN,'ownedProcessesAbsent':True,'forcedKills':0,'rules':BUNDLE['evidence']['rules'],
       'bundle':BUNDLE['bundle'],'cases':[case]}
 receipt={'scope':prof['sourceAVScope'],'status':'PASS','existingNineUnchanged':True,'failure':None,'cleanup':{'success':True},
          'runId':'1'*32,'finishedUnix':1000,'imageId':'sha256:'+'2'*64,'sourceBindingSHA256':P.sha(raw_binding),
          'sourceBinding':source,'inner':{'fullAV':full}}
 expected={'receiptSHA256':P.sha(P.canonical(receipt)),'generation':P.REFERENCE_GEN,'rulesSHA256':P.sha(P.canonical(full['rules'])),
           'limitsSHA256':P.sha(P.canonical(BUNDLE['evidence']['limits'])),'runId':receipt['runId'],'imageId':receipt['imageId'],
           'completeBundleEvidence':BUNDLE,'sourceBindingSHA256':P.sha(raw_binding)}
 return receipt,expected,raw_binding
def check_av(receipt,expected,source,now=1001,slot='reference'):
 raw=P.canonical(receipt);expected=dict(expected,receiptSHA256=P.sha(raw))
 return P.validate_source_av_receipt_metadata(raw,expected,now,source,P.sha(source),slot)
