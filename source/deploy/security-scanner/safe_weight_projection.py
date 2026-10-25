# Copyright The MatrixHub Authors.
# Licensed under the Apache License, Version 2.0.
"""Fixed-profile quarantined static projection, NOT a loader or disinfector.
Original .pth stays denied; NEW safetensors needs independent complete AV/format
scan and version admission. No reducers or model-named imports are executed.
"""
import hashlib,io,json,math,os,re,stat,sys,time,zipfile
from pathlib import Path
PROFILE="sasrec-static-f32-approved-device-literals-to-cpu-projection-v3"
SOURCE_SHA="b2e80d9544f0c5dd313d3758107ea6069b0c0a742cd7f78030901aabea7ffda6"
INPUT_SHA="8de480042d929e1a1b8c22770a2c39179d2cedb1bc4c5e3439bedd8dedb935d6"
INPUT_BYTES=486423
REFERENCE_GEN="da770656a449a7a076262708a4c594cc37ac53c7fd9c535883ed34ce6f953103"
PICKLE_SHA="cd53522a3d95ea1f179777ca66ab8a40e380849df2ed1af74e1663e7ee36981e"
PICKLE_BYTES=18816
MAX_METADATA=32768
MAX_SLOTS=65536
MAX_REFS=128
MAX_TENSORS=256
MAX_OUTPUT=2<<20
CHUNK=64<<10
_SEAL=object()
_CODES=frozenset("""profile source_av_required source_av_binding source_av_not_clean
source_av_stale source_av_shape source_av_scope runtime_guard deadline source_fd
source_changed source_digest source_module metadata_identity metadata_stream
metadata_budget global_analysis dangerous_reference dynamic_callable
known_constructor_opcode parameter_unsupported opaque_write opaque_state
unsupported_opcode mapping_key duplicate_key graph_budget opaque_export escaped_export
root_state_dict tensor_profile source_location source_location_conflict source_location_closure duplicate_storage zip_layout zip_metadata storage_closure
storage_size storage_crc output_budget output_directory output_exists output_identity
output_changed proof_consumed proof_binding missing_dependency plan_changed internal""".split())
class ProjectionError(Exception):
 def __init__(self,code):
  self.code=code if code in _CODES else "internal"
  super().__init__(self.code)
def need(ok,code):
 if not ok:raise ProjectionError(code)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def is_sha(v):return type(v)is str and re.fullmatch("[a-f0-9]{64}",v)is not None
def stamp(s):return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def decode(raw):
 def unique(pairs):
  out={}
  for k,v in pairs:need(k not in out,"source_av_shape");out[k]=v
  return out
 try:return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ProjectionError("source_av_shape")))
 except(ValueError,UnicodeError):raise ProjectionError("source_av_shape")from None

def projection_policy():
 return{"profile":PROFILE,"sourceScannerSHA256":SOURCE_SHA,"sourceScannerGeneration":REFERENCE_GEN,"inputSHA256":INPUT_SHA,"inputBytes":INPUT_BYTES,
        "dataPickleSHA256":PICKLE_SHA,"dataPickleBytes":PICKLE_BYTES,"maxMetadataBytes":MAX_METADATA,
        "maxSlots":MAX_SLOTS,"maxGlobals":MAX_REFS,"maxTensors":MAX_TENSORS,"maxOutputBytes":MAX_OUTPUT,
        "sourceDeviceTags":"exact cpu, cuda, mps OR canonical cuda:n; ASCII n 0..255","outputDevice":"cpu","deviceCodeExecuted":False,"dtype":"F32","denseCanonicalStride":True,"storageOffset":0,
        "fullStorageOnly":True,"parameterSupported":False,"duplicateStorageSupported":False,
        "negativeViewSupported":False,"opaqueExportSupported":False,"sourceAVFreshSeconds":1800,
        "originalAdmission":"deny","derivedState":"QUARANTINE_REQUIRES_INDEPENDENT_FULL_SCAN",
        "originalExecutionSemanticsEquivalent":False}
def policy_sha256():return sha(canonical(projection_policy()))
def module_source_sha256(expected):
 need(is_sha(expected),"source_module");path=Path(__file__)
 need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),"source_module")
 before=path.stat()
 with path.open("rb")as stream:
  held=os.fstat(stream.fileno());raw=stream.read((128<<10)+1);after=os.fstat(stream.fileno())
 need(stat.S_ISREG(held.st_mode)and held.st_nlink==1 and len(raw)<=128<<10 and
      stamp(before)==stamp(held)==stamp(after)==stamp(path.stat())and sha(raw)==expected,"source_module")
 return expected

def describe():
 return{"status":"SOURCE_PREPARED_NOT_EXECUTED","profile":PROFILE,"inputSHA256":INPUT_SHA,"inputBytes":INPUT_BYTES,"dataPickleSHA256":PICKLE_SHA,"dataPickleBytes":PICKLE_BYTES,"originalCheckpointAdmission":"deny","derivedArtifactState":"QUARANTINE_REQUIRES_INDEPENDENT_FULL_SCAN","modelDeserialized":False,"originalExecutionSemanticsEquivalent":False,"claim":"fixed stored-weight-byte projection; not model disinfection","projectionPolicySHA256":policy_sha256(),"defaultArtifactIO":False}
class Opaque:
 __slots__=("args","state","built","kind")
 def __init__(self,args,kind):self.args,self.state,self.built,self.kind=args,None,False,kind
class FiniteSet:
 __slots__=("items","frozen")
 def __init__(self,items=(),frozen=False):self.items,self.frozen=list(items),frozen
def closure(roots,children,mutable,limit=MAX_SLOTS):
 """Iterative alias closure, traversing immutable-container descendants."""
 need(type(limit)is int and 0<limit<=MAX_SLOTS,"graph_budget")
 todo,visited,result=list(roots),set(),set();operations=0
 while todo:
  node=todo.pop();identity=id(node)
  if identity in visited:continue
  visited.add(identity);operations+=1;need(operations<=limit,"graph_budget")
  if mutable(node):result.add(identity)
  edges=children(node)
  need(type(edges)in(list,tuple)and operations+len(todo)+len(edges)<=limit,"graph_budget")
  todo.extend(edges)
 return result
def check_escape(selected,escaped,children,mutable,limit=MAX_SLOTS):
 chosen=closure(selected,children,mutable,limit)
 need(not chosen.intersection(closure(escaped,children,mutable,limit)),"escaped_export")
 return chosen
def validate_dense_tensor(t,S):
 need(type(t)is S.LegacyTensor,"tensor_profile");storage=t.storage
 need(type(storage)is S.LegacyStorage and storage.kind=="FloatStorage"and storage.width==4 and type(storage.numel)is int and storage.numel>=0,"tensor_profile")
 need(type(t.offset)is int and t.offset==0 and type(t.shape)is tuple and type(t.stride)is tuple and len(t.shape)==len(t.stride)<=64 and all(type(x)is int and 0<=x<=(1<<63)-1 for x in t.shape+t.stride),"tensor_profile")
 # A consumed negative-view marker cannot be preserved by copying raw bytes.
 need(t.metadata is None or t.metadata is False,"tensor_profile")
 expected,product=[],1
 for size in reversed(t.shape):
  expected.append(product);need(size==0 or product<=((1<<63)-1)//size,"tensor_profile");product*=size
 need(tuple(reversed(expected))==t.stride and product==storage.numel,"tensor_profile")
 need(type(t.hooks)is S.LegacyMap and t.hooks.ordered and not t.hooks.items and t.hooks.state is None,"tensor_profile")
 return{"dtype":"F32","shape":list(t.shape),"bytes":product*4,"storageKey":storage.key}



def validated_device_tag(value):
 # A literal label in an archive, NOT a request to construct/query a device.
 need(type(value)is str,"source_location")
 if value in("cpu","cuda","mps"):return value
 match=re.fullmatch(r"cuda:(0|[1-9][0-9]{0,2})",value,flags=re.ASCII)
 need(match is not None and int(match.group(1))<=255,"source_location")
 return value

def machine_class(S):
 """Trusted-module factory. Direct token methods have no artifact IO."""
 class Machine(S._ZipParameterMachine):
  def __init__(self,limits):
   super().__init__(limits);self.escapes,self.dependencies,self.seen_globals=[],{},set();self.original_devices={}
  def global_token(self,module,symbol):
   need(type(module)is str and type(symbol)is str and len(module)<=256 and len(symbol)<=256 and re.fullmatch(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*",module)is not None and re.fullmatch(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*",symbol)is not None,"global_analysis")
   pair=(module,symbol);need(pair!=S._PARAMETER_SYMBOL,"parameter_unsupported")
   need(not S.known_dangerous_reference(pair)and pair!=S.NESTED_DESERIALIZATION_SYMBOL,"dangerous_reference")
   self.seen_globals.add(pair);need(len(self.seen_globals)<=MAX_REFS,"metadata_budget");self.budget(nodes=1)
   return S.LegacyGlobal(module,symbol)
  def setitems(self,target,pairs):
   need(type(target)is S.LegacyMap and len(pairs)%2==0,"opaque_write")
   for i in range(0,len(pairs),2):
    k,v=pairs[i:i+2]
    need((type(k)is str and len(k)<=1024)or(type(k)is int and -(1<<63)<=k<(1<<63)),"mapping_key")
    need(k not in target.items,"duplicate_key");self.budget(edges=2);target.items[k]=v
  def persistent(self,value):
   need(type(value)is tuple and len(value)==5,"tensor_profile")
   tag,kind,key,location,numel=value
   need(type(tag)is str and tag=="storage"and type(kind)is S.LegacyGlobal and
        kind.name==("torch","FloatStorage")and type(key)is str and
        re.fullmatch(r"[0-9]{1,32}",key,flags=re.ASCII)is not None and
        type(numel)is int and 0<=numel<=(1<<64)-1,"tensor_profile")
   original=validated_device_tag(location)
   need(key not in self.original_devices or self.original_devices[key]==original,"source_location_conflict")
   if key not in self.original_devices:
    need(len(self.original_devices)<self.limits["max_members"],"metadata_budget")
    self.budget(nodes=1,edges=2)
   self.original_devices[key]=original
   # PyTorch writes numeric storage payload bytes to ZIP on CPU; location is
   # retained only as validated provenance. Never import/query a device backend.
   return super().persistent((tag,kind,key,"cpu",numel))
  def _opaque(self,args,kind):
   need(type(args)is tuple,"dynamic_callable");self.budget(nodes=1,edges=1+len(args))
   value=Opaque(args,kind);self.escapes.append(args);need(len(self.escapes)<=MAX_SLOTS,"graph_budget")
   return value
  def reduce(self,target,args):
   need(type(target)is S.LegacyGlobal and type(args)is tuple,"dynamic_callable")
   need(target.name!=S._PARAMETER_SYMBOL,"parameter_unsupported")
   if target.name in {("collections","OrderedDict"),("torch._utils","_rebuild_tensor_v2")}:
    # Known-invalid constructor semantics must not fall back to opaque data.
    value=super().reduce(target,args)
    if type(value)is S.LegacyTensor:
     # Keep consumed metadata maps, not only their frozen None/False/True effect.
     self.dependencies[id(value)]=args;self.budget(edges=len(args))
    return value
   need(target.name not in S.LEGACY_GLOBALS,"known_constructor_opcode")
   return self._opaque(args,"REDUCE")
  def apply(self,name,argument):
   if name in {"NEWOBJ","NEWOBJ_EX"}:
    need(name=="NEWOBJ","unsupported_opcode");target,args=self.pop(2)
    need(type(target)is S.LegacyGlobal,"dynamic_callable")
    need(target.name not in S.LEGACY_GLOBALS and target.name!=S._PARAMETER_SYMBOL,"known_constructor_opcode")
    self.push(self._opaque(args,"NEWOBJ"))
   elif name=="BUILD":
    state=self.pop();self.need(1);target=self.stack[-1]
    if type(target)is Opaque:
     need(not target.built,"opaque_state");target.state,target.built=state,True
     self.escapes.append(state);self.budget(edges=1)
    else:self.push(state);super().apply(name,argument)
   elif name in {"BINFLOAT","FLOAT"}:
    need(type(argument)is float and math.isfinite(argument),"metadata_stream");self.push(argument)
   elif name in {"BINBYTES","SHORT_BINBYTES","BINBYTES8"}:
    need(type(argument)is bytes and len(argument)<=MAX_METADATA,"metadata_budget");self.push(argument)
   elif name=="EMPTY_SET":self.budget(nodes=1);self.push(FiniteSet())
   elif name in {"ADDITEMS","FROZENSET"}:
    values=self.marked()
    if name=="FROZENSET":self.budget(nodes=1,edges=len(values));self.push(FiniteSet(values,True))
    else:
     self.need(1);target=self.stack[-1]
     need(type(target)is FiniteSet and not target.frozen and len(target.items)+len(values)<=self.limits["max_members"],"opaque_write")
     self.budget(edges=len(values));target.items.extend(values)
   elif name=="POP":self.pop()
   elif name=="DUP":self.need(1);self.push(self.stack[-1])
   else:super().apply(name,argument)
  def children(self,node):
   if type(node)is S.LegacyMap:return list(node.items.values())+([]if node.state is None else[node.state])
   if type(node)in(S.LegacyList,FiniteSet):return node.items
   if type(node)is tuple:return list(node)
   if type(node)is Opaque:return[node.args]+([]if not node.built else[node.state])
   if type(node)is S.LegacyTensor:
    need(id(node)in self.dependencies,"missing_dependency")
    return[node.storage,node.hooks,self.dependencies[id(node)]]
   if type(node)is S._ZipParameter:raise ProjectionError("parameter_unsupported")
   return[]
  def mutable(self,node):
   return type(node)in(S.LegacyMap,S.LegacyList,S.LegacyTensor,S.LegacyStorage,S._ZipParameter,Opaque,FiniteSet)
  def select(self,root):
   need(type(root)is S.LegacyMap and not root.ordered and root.state is None and "state_dict"in root.items,"root_state_dict")
   selected=root.items["state_dict"]
   need(type(selected)is S.LegacyMap and (selected.state is None or selected.ordered),"root_state_dict")
   need(0<len(selected.items)<=MAX_TENSORS and all(type(k)is str and 0<len(k)<=1024 and k!="__metadata__"for k in selected.items),"root_state_dict")
   for key in selected.items:
    try:key.encode("utf-8","strict")
    except UnicodeError:raise ProjectionError("mapping_key")from None
   try:self.final_tokens(selected)
   except S.LegacyTorchError:raise ProjectionError("tensor_profile")from None
   tensors,storages=[],set()
   for key,value in selected.items.items():
    row=validate_dense_tensor(value,S);need(row["storageKey"]not in storages,"duplicate_storage")
    storages.add(row["storageKey"]);need(id(value)in self.dependencies,"missing_dependency")
    tensors.append(dict(row,name=key))
   check_escape([selected],self.escapes,self.children,self.mutable,min(MAX_SLOTS,self.max_slots))
   need(not closure([selected],self.children,lambda x:type(x)is Opaque,min(MAX_SLOTS,self.max_slots)),"opaque_export")
   return tensors
  def parse_projection(self,raw,context):
   require_context(context)
   need(type(raw)is bytes and len(raw)==PICKLE_BYTES and sha(raw)==PICKLE_SHA,"metadata_identity")
   stream=io.BytesIO(raw)
   try:
    segment,protocol,count=S.legacy_read_segment(stream,len(raw),min(MAX_METADATA,self.limits["max_pickle_argument"]),min(MAX_SLOTS,self.limits["max_pickle_opcodes"]))
    need(segment==raw and stream.tell()==len(raw)and protocol==4,"metadata_stream")
    root=S.LegacyMachine.parse(self,raw,protocol);tensors=self.select(root)
   except S.LegacyTorchError:raise ProjectionError("metadata_stream")from None
   return tensors,count
 return Machine

class _Context:
 __slots__=("seal","deadline","pid","avGate","used","moduleSHA256","policySHA256")
 def __init__(self,deadline,module_sha=None,policy_sha=None):
  self.seal,self.deadline,self.pid,self.avGate,self.used=_SEAL,deadline,os.getpid(),None,False
  self.moduleSHA256,self.policySHA256=module_sha,policy_sha
def _runtime_checks(deadline):
 need(sys.platform=="linux"and os.geteuid()==os.getegid()==65532 and set(os.getgroups())<={65532},"runtime_guard")
 need(type(deadline)in(int,float)and 0<deadline-time.time()<=120,"deadline")
 rows=[x.split()for x in Path("/proc/self/mountinfo").read_text().splitlines()]
 for mount,flags,fs in[("/",{"ro"},None),("/tmp",{"rw","noexec","nosuid","nodev"},"tmpfs")]:
  found=[r for r in rows if len(r)>=10 and r[4]==mount and "-"in r]
  need(len(found)==1 and flags<=set(found[0][5].split(","))and(fs is None or found[0][found[0].index("-")+1]==fs),"runtime_guard")
 need({p.name for p in Path("/sys/class/net").iterdir()}=={"lo"},"runtime_guard")
 for name,header in[("route",True),("ipv6_route",False)]:
  lines=(Path("/proc/net")/name).read_text().splitlines();lines=lines[1:]if header else lines
  need(all(not x.strip()or x.split()[0 if header else-1]=="lo"for x in lines),"runtime_guard")
 status=dict(x.split(":",1)for x in Path("/proc/self/status").read_text().splitlines()if ":"in x)
 need(int(status["CapEff"].strip(),16)==0 and status["NoNewPrivs"].strip()=="1","runtime_guard")
 cg=Path("/sys/fs/cgroup");memory=(cg/"memory.max").read_text().strip()
 need(memory.isdigit()and 0<int(memory)<=(4608<<20)and(cg/"memory.swap.max").read_text().strip()=="0"and(cg/"memory.swap.current").read_text().strip()=="0","runtime_guard")
 pids=(cg/"pids.max").read_text().strip();cpu=(cg/"cpu.max").read_text().split()
 need(pids.isdigit()and 0<int(pids)<=128 and len(cpu)==2 and all(x.isdigit()for x in cpu)and 0<int(cpu[0])<=4*int(cpu[1]),"runtime_guard")
 need(not list(Path("/dev").glob("nvidia*"))and not Path("/dev/dri").exists()and not Path("/var/run/docker.sock").exists()and not Path("/engine/docker.sock").exists(),"runtime_guard")
def new_context(deadline,module_sha256):
 _runtime_checks(deadline)
 module_source_sha256(module_sha256)
 import resource
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20));resource.setrlimit(resource.RLIMIT_CPU,(30,30));resource.setrlimit(resource.RLIMIT_NOFILE,(64,64));resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_OUTPUT,MAX_OUTPUT))
 return _Context(deadline,module_sha256,policy_sha256())
def require_context(context):
 need(sys.platform=="linux"and type(context)is _Context and context.seal is _SEAL and context.pid==os.getpid()and is_sha(context.moduleSHA256)and context.policySHA256==policy_sha256(),"runtime_guard")
 need(time.time()<context.deadline,"deadline")
def held_source(fd,context):
 require_context(context)
 import fcntl
 value=os.fstat(fd)
 need(stat.S_ISREG(value.st_mode)and value.st_nlink==1 and value.st_uid==65532 and value.st_dev==os.stat("/tmp").st_dev and value.st_size==INPUT_BYTES and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,"source_fd")
 before,digest,count=stamp(value),hashlib.sha256(),0;os.lseek(fd,0,os.SEEK_SET)
 while True:
  require_context(context);block=os.read(fd,CHUNK)
  if not block:break
  count+=len(block);need(count<=INPUT_BYTES,"source_digest");digest.update(block)
 need(count==INPUT_BYTES and digest.hexdigest()==INPUT_SHA and stamp(os.fstat(fd))==before,"source_changed")
 os.lseek(fd,0,os.SEEK_SET);return before


class _AVGate:
 __slots__=("seal","receiptSHA256","runId","generation","rulesSHA256","finishedUnix")
 def __init__(self,digest,run,generation,rules,finished):
  self.seal,self.receiptSHA256,self.runId=_SEAL,digest,run
  self.generation,self.rulesSHA256,self.finishedUnix=generation,rules,finished
def validate_source_av_receipt_metadata(raw,expected,now):
 """Pure receipt validation; does not mint a runtime gate or read artifacts."""
 need(type(now)in(int,float)and math.isfinite(now),"source_av_stale")
 need(type(raw)is bytes and 0<len(raw)<=2<<20 and type(expected)is dict,"source_av_shape")
 for key in["receiptSHA256","generation","rulesSHA256","limitsSHA256"]:need(is_sha(expected.get(key)),"source_av_binding")
 need(sha(raw)==expected["receiptSHA256"]and expected["generation"]==REFERENCE_GEN,"source_av_binding");receipt=decode(raw)
 need(receipt.get("scope")=="R25_SINGLE_SASREC_DIAGNOSTIC_NOT_ADMISSION"and receipt.get("status")=="PASS"and receipt.get("existingNineUnchanged")is True and receipt.get("failure")is None and receipt.get("cleanup",{}).get("success")is True,"source_av_scope")
 run=receipt.get("runId");finished=receipt.get("finishedUnix")
 need(type(run)is str and re.fullmatch("[a-f0-9]{32}",run)is not None and run==expected.get("runId")and receipt.get("imageId")==expected.get("imageId"),"source_av_binding")
 need(type(finished)in(int,float)and 0<=now-finished<=1800,"source_av_stale")
 full=receipt.get("inner",{}).get("fullAV",{})
 need(full.get("scope")=="R25_SINGLE_SASREC_FULLAV_AND_COMPONENT_DIAGNOSTIC"and full.get("status")=="PASS"and full.get("fullAV")is True and full.get("failure")is None and full.get("sourceSHA256")==SOURCE_SHA and full.get("generation")==expected["generation"]and full.get("ownedProcessesAbsent")is True and full.get("forcedKills")==0,"source_av_binding")
 need(sha(canonical(full.get("rules")))==expected["rulesSHA256"]and full.get("bundle",{}).get("generation")==expected["generation"],"source_av_binding")
 bundle=expected.get("completeBundleEvidence")
 need(type(bundle)is dict and bundle.get("bundle")==full.get("bundle")and bundle.get("bundle",{}).get("generation")==expected["generation"]and sha(canonical(bundle.get("evidence",{}).get("limits")))==expected["limitsSHA256"]and sha(canonical(bundle.get("evidence")))==expected["generation"]and bundle.get("evidence",{}).get("source_sha256")==SOURCE_SHA and bundle.get("evidence",{}).get("rules")==full.get("rules"),"source_av_binding")
 cases=full.get("cases",[]);need(type(cases)is list and len(cases)==1,"source_av_shape");case=cases[0]
 need(case.get("id")=="SASRec"and case.get("sha256")==INPUT_SHA and case.get("bytes")==INPUT_BYTES and case.get("executionStatus")=="EXECUTED"and case.get("failure")is None and case.get("technicalPass")is True and case.get("fullWorkerResultAvailable")is True and case.get("heldFDPrePostUnchanged")is True and case.get("prePostIdentityUnchanged")is True and case.get("recoveryFullScanPassed")is True,"source_av_binding")
 observation=case.get("observation",{})
 need(observation.get("httpStatus")==200 and observation.get("protocolValid")is True and observation.get("identityMatched")is True and observation.get("generationMatched")is True and observation.get("requestError")is None,"source_av_not_clean")
 need(observation.get("complete")is False and observation.get("admission")=="deny"and observation.get("coverageCodes")==["unsupported_container_or_serialization"]and observation.get("rules")==["pickle.unknown-global"]and observation.get("severities")==["medium"],"source_av_not_clean")
 return{"status":"VALID_NATIVE_CLEAN_STATIC_UNSUPPORTED_METADATA_NOT_RUNTIME_GATE","sourceAVReceiptSHA256":expected["receiptSHA256"],"sourceAVRunId":run,"generation":expected["generation"],"rulesSHA256":expected["rulesSHA256"],"finishedUnix":finished}
def bind_source_av_receipt(raw,expected,context):
 """Only a guarded caller with an exact actual fullAV receipt can mint a gate."""
 require_context(context);facts=validate_source_av_receipt_metadata(raw,expected,time.time())
 need(context.avGate is None,"source_av_binding")
 context.avGate=_AVGate(facts["sourceAVReceiptSHA256"],facts["sourceAVRunId"],facts["generation"],facts["rulesSHA256"],facts["finishedUnix"])
 return{"status":"BOUND_NATIVE_CLEAN_STATIC_UNSUPPORTED_SOURCE_REMAINS_DENIED","sourceAVReceiptSHA256":facts["sourceAVReceiptSHA256"],"sourceAVRunId":facts["sourceAVRunId"]}

def audit_globals(S,raw,limits):
 from picklescan.scanner import _build_scan_result_from_raw_globals,SafetyLevel
 references=S.SymbolicReferences(min(MAX_SLOTS,limits["max_pickle_opcodes"]))
 reader=S.PickleOpcodeReader(io.BytesIO(raw),min(MAX_METADATA,limits["max_pickle_argument"]))
 pairs,count=set(),0
 try:
  for count,(opcode,argument,_)in enumerate(S.pickletools.genops(reader),1):
   need(count<=MAX_SLOTS,"metadata_budget")
   need(opcode.name not in{"PERSID","EXT1","EXT2","EXT4","INST","OBJ","NEWOBJ_EX"},"unsupported_opcode")
   pair=references.apply(opcode,argument)
   if pair is not None:
    pairs.add(pair);need(len(pairs)<=MAX_REFS and not S.known_dangerous_reference(pair)and pair!=S.NESTED_DESERIALIZATION_SYMBOL,"dangerous_reference")
  result=_build_scan_result_from_raw_globals(pairs,"quarantined-source",strict=False)
  need(all(value.safety!=SafetyLevel.Dangerous for value in result.globals),"dangerous_reference")
 except(S.Incomplete,ValueError,UnicodeError,EOFError,OverflowError):raise ProjectionError("global_analysis")from None
 return pairs,count
def bounded_scanner_source(path):
 need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),"source_module")
 before=path.stat()
 with path.open("rb")as stream:
  held=os.fstat(stream.fileno());raw=stream.read(206592);after=os.fstat(stream.fileno())
 need(stat.S_ISREG(held.st_mode)and held.st_nlink==1 and len(raw)==206591 and stamp(before)==stamp(held)==stamp(after)==stamp(path.stat())and sha(raw)==SOURCE_SHA,"source_module")
 return raw

class ProjectionPlan:
 __slots__=("seal","sourceStamp","sourceFD","entries","tensors","header","metadata","used","context","_snapshot","_digest")
 def __init__(self,context,fd,source_stamp,entries,tensors,header,metadata):
  self.seal,self.sourceFD,self.sourceStamp=_SEAL,fd,source_stamp
  self.entries,self.tensors,self.header=entries,tensors,header
  self.metadata,self.used,self.context=metadata,False,context
  self._snapshot=canonical(plan_document(self));self._digest=sha(self._snapshot)

def plan_document(plan):
 def clean(v):
  if type(v)is bytes:return{"bytesSHA256":sha(v),"bytesLength":len(v)}
  if type(v)in(str,int,float,bool,type(None)):return v
  if type(v)in(list,tuple):return[clean(x)for x in v]
  need(type(v)is dict and all(type(k)is str for k in v),"plan_changed")
  return{k:clean(x)for k,x in v.items()}
 gate=plan.context.avGate
 return{"profile":PROFILE,"sourceSHA256":INPUT_SHA,"sourceStamp":list(plan.sourceStamp),"sourceFD":plan.sourceFD,
        "contextPID":plan.context.pid,"contextDeadline":plan.context.deadline,
        "projectionModuleSHA256":plan.context.moduleSHA256,"projectionPolicySHA256":plan.context.policySHA256,
        "sourceAV":{"receiptSHA256":gate.receiptSHA256,"runId":gate.runId,"generation":gate.generation,
                    "rulesSHA256":gate.rulesSHA256,"finishedUnix":gate.finishedUnix},
        "entries":clean(plan.entries),"tensors":clean(plan.tensors),"headerHex":plan.header.hex(),
        "metadata":clean(plan.metadata)}
def checked_plan_snapshot(plan):
 need(type(plan)is ProjectionPlan and plan.seal is _SEAL and
      sha(plan._snapshot)==plan._digest and sha(canonical(plan_document(plan)))==plan._digest,"plan_changed")
 # Return a fresh document, so later caller mutation cannot alter a running writer.
 return decode(plan._snapshot)

def prove_projection(S,source_fd,context):
 require_context(context)
 need(type(context.avGate)is _AVGate and context.avGate.seal is _SEAL and 0<=time.time()-context.avGate.finishedUnix<=1800 and not context.used,"source_av_required")
 before=held_source(source_fd,context);source=Path(S.__file__);source_bytes=bounded_scanner_source(source)
 need(len(source_bytes)==206591 and sha(source_bytes)==SOURCE_SHA,"source_module")
 limits=S.limits_from_env();limits=dict(limits,max_pickle_opcodes=min(MAX_SLOTS,limits["max_pickle_opcodes"]),max_pickle_argument=min(MAX_METADATA,limits["max_pickle_argument"]))
 with os.fdopen(os.dup(source_fd),"rb")as data:
  try:
   entries,total=S.zip_directory(data,limits);need(total==INPUT_BYTES and len(entries)==150,"zip_layout");data.seek(0)
   with zipfile.ZipFile(data)as archive:
    infos=archive.infolist();need(len(infos)==len(entries),"zip_layout")
    for info,entry in zip(infos,entries):
     need((info.filename,info.header_offset,info.file_size,info.compress_size,info.CRC,info.flag_bits,info.compress_type)==(entry["name"],entry["offset"],entry["size"],entry["size"],entry["crc"],entry["flags"],entry["method"]),"zip_layout")
    candidates=[info for info in infos if info.filename.split("/")[-1]=="data.pkl"]
    need(len(candidates)==1 and len(candidates[0].filename.split("/"))==2,"zip_metadata")
    prefix=candidates[0].filename.split("/")[0]+"/"
    need(S.ROOT_RE.fullmatch(prefix[:-1])is not None and all(info.filename.startswith(prefix)for info in infos),"zip_metadata")
    relative={info.filename[len(prefix):]:info for info in infos}
    need({"data.pkl","version","byteorder"}<=set(relative),"zip_metadata")
    need(sum(info.file_size for name,info in relative.items()if name in S.METADATA)<=MAX_METADATA,"metadata_budget")
    raw=S.read_member(archive,relative["data.pkl"],MAX_METADATA,True)
    need(len(raw)==PICKLE_BYTES and sha(raw)==PICKLE_SHA,"metadata_identity")
    pairs,count=audit_globals(S,raw,limits);machine=machine_class(S)(limits)
    tensors,vm_count=machine.parse_projection(raw,context)
    need(machine.seen_globals==pairs and count==vm_count,"global_analysis")
    fixed={"version":b"3\n","byteorder":b"little",".format_version":b"1",".storage_alignment":b"64"}
    need((".format_version"in relative)==(".storage_alignment"in relative),"zip_metadata")
    raw_members={}
    for name,info in relative.items():
     require_context(context)
     if name=="data.pkl":continue
     if name in S.METADATA:
      value=S.read_member(archive,info,256,True)
      if name==".data/serialization_id":need(re.fullmatch(b"[0-9]{40}",value)is not None,"zip_metadata")
      else:need(name in fixed and value==fixed[name],"zip_metadata")
     else:
      need(name.startswith("data/")and S.KEY_RE.fullmatch(name[5:])is not None,"zip_metadata");raw_members[name[5:]]=info
    need(set(raw_members)==set(machine.layout.storages),"storage_closure")
    need(set(machine.original_devices)==set(machine.layout.storages),"source_location_closure")
    physical={entry["name"][len(prefix):]:entry for entry in entries};storage_entries={}
    for key,spec in machine.layout.storages.items():
     require_context(context);need(spec[:3]==("torch","FloatStorage","cpu"),"tensor_profile")
     info=raw_members[key];need(info.file_size==spec[-1],"storage_size")
     S.read_member(archive,info,spec[-1],False);storage_entries[key]=physical["data/"+key]
    need(held_source(source_fd,context)==before and bounded_scanner_source(source)==source_bytes,"source_changed")
  except(S.LayoutError,S.LegacyTorchError,zipfile.BadZipFile,EOFError,UnicodeError,ValueError,OverflowError):raise ProjectionError("zip_layout")from None
 header,public,payload={},[],0
 for tensor in tensors:
  size=tensor["bytes"];header[tensor["name"]]={"dtype":"F32","shape":tensor["shape"],"data_offsets":[payload,payload+size]}
  public.append({"nameSHA256":sha(tensor["name"].encode("utf-8")),"dtype":"F32","shape":tensor["shape"],"bytes":size});payload+=size
 header["__metadata__"]={"projection_profile":PROFILE,"source_sha256":INPUT_SHA,"original_checkpoint_admission":"deny"}
 header_raw=canonical(header);header_raw+=b" "*(-len(header_raw)%8)
 need(len(header_raw)<=MAX_METADATA and 8+len(header_raw)+payload<=MAX_OUTPUT,"output_budget")
 metadata={"schema":1,"profile":PROFILE,"projectionModuleSHA256":context.moduleSHA256,"projectionPolicySHA256":context.policySHA256,"sourceSHA256":INPUT_SHA,"sourceBytes":INPUT_BYTES,"dataPickleSHA256":PICKLE_SHA,"sourceAVReceiptSHA256":context.avGate.receiptSHA256,"sourceAVRunId":context.avGate.runId,"originalCheckpointAdmission":"deny","originalExecutionSemanticsEquivalent":False,"derivedArtifactState":"QUARANTINE_REQUIRES_INDEPENDENT_FULL_SCAN","allZIPMembersCRCVerified":True,"sourceLocationTagsValidated":True,"normalizedStorageF32LayoutClosed":True,"outputDeviceCPU":True,"sourceStorageLocations":[{"storageKeySHA256":sha(key.encode("ascii")),"location":machine.original_devices[key]}for key in sorted(machine.original_devices)],"wholeMetadataParsed":True,"opcodes":count,"globalReferences":len(pairs),"opaqueEscapeDisjoint":True,"consumedMetadataDependenciesRetained":True,"payloadBytes":payload,"outputBytes":8+len(header_raw)+payload,"tensors":public,"modelDeserialized":False}
 context.used=True
 return ProjectionPlan(context,source_fd,before,storage_entries,tensors,header_raw,metadata)


def write_projection(plan,source_fd,output_directory_fd,context):
 require_context(context)
 need(type(plan)is ProjectionPlan and plan.seal is _SEAL and plan.context is context and not plan.used and source_fd==plan.sourceFD,"proof_binding")
 snapshot=checked_plan_snapshot(plan)
 plan.used=True
 entries,tensors,header,metadata=snapshot["entries"],snapshot["tensors"],bytes.fromhex(snapshot["headerHex"]),snapshot["metadata"]
 source_stamp=tuple(snapshot["sourceStamp"])
 need(held_source(source_fd,context)==source_stamp,"source_changed")
 directory=os.fstat(output_directory_fd);path=os.readlink("/proc/self/fd/"+str(output_directory_fd))
 need(stat.S_ISDIR(directory.st_mode)and directory.st_uid==65532 and directory.st_dev==os.stat("/tmp").st_dev and stat.S_IMODE(directory.st_mode)==0o700 and re.fullmatch("/tmp/projection-[a-f0-9]{32}",path)is not None,"output_directory")
 name,fd,opened="projected.safetensors",None,None
 try:
  try:fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output_directory_fd)
  except FileExistsError:raise ProjectionError("output_exists")from None
  opened=os.fstat(fd)
  need(stat.S_ISREG(opened.st_mode)and opened.st_nlink==1 and opened.st_uid==65532 and opened.st_size==0 and opened.st_dev==directory.st_dev,"output_identity")
  digest,count=hashlib.sha256(),0
  def emit(block):
   nonlocal count
   require_context(context);need(type(block)is bytes and count+len(block)<=metadata["outputBytes"],"output_budget")
   offset=0
   while offset<len(block):
    written=os.write(fd,block[offset:]);need(written>0,"output_identity");offset+=written
   digest.update(block);count+=len(block)
  emit(len(header).to_bytes(8,"little"));emit(header)
  for tensor in tensors:
   entry=entries[tensor["storageKey"]];os.lseek(source_fd,entry["payloadOffset"],os.SEEK_SET);remaining=tensor["bytes"]
   while remaining:
    block=os.read(source_fd,min(CHUNK,remaining));need(bool(block),"source_changed");emit(block);remaining-=len(block)
  need(count==metadata["outputBytes"],"output_budget");os.fsync(fd);os.fchmod(fd,0o400);after=os.fstat(fd)
  need(after.st_size==count and(after.st_dev,after.st_ino)==(opened.st_dev,opened.st_ino)and after.st_nlink==1,"output_changed")
  os.lseek(fd,0,os.SEEK_SET);check=hashlib.sha256()
  while True:
   require_context(context);block=os.read(fd,CHUNK)
   if not block:break
   check.update(block)
  need(check.hexdigest()==digest.hexdigest()and stamp(os.fstat(fd))==stamp(after)and held_source(source_fd,context)==source_stamp,"output_changed")
  named=os.stat(name,dir_fd=output_directory_fd,follow_symlinks=False)
  need(stat.S_ISREG(named.st_mode)and stamp(named)==stamp(os.fstat(fd))and
       stat.S_IMODE(named.st_mode)==0o400 and named.st_nlink==1 and
       os.readlink("/proc/self/fd/"+str(output_directory_fd))==path,"output_changed")
  os.fsync(output_directory_fd)
  return dict(metadata,outputSHA256=digest.hexdigest(),outputFile=name,outputWritten=True,sourcePrePostSHAAndFstat=True,outputFullSHAAndFstat=True,outputPublished=False)
 finally:
  if fd is not None:os.close(fd)
  # Keep success/failure quarantined. ROOT cleans only after known child absence.
  # Never unlink a possibly active writer/verifier's file here.

if __name__=="__main__":print(json.dumps(describe(),sort_keys=True))
