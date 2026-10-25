"""Pure finite-graph/shape tests. No model/ZIP/Pickle fixture bytes are built.
Real VM metadata parsing, ZIP CRC, AV, writing and deployment remain Linux tests.
"""
import importlib.util
from pathlib import Path
import types
import unittest
path=Path(__file__).with_name("safe_weight_projection.py")
spec=importlib.util.spec_from_file_location("projection_pure_module",path)
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
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
class GraphTests(unittest.TestCase):
 def machine(self):return Machine(dict(LIMITS))
 def test_no_runtime_or_loader_claim(self):
  d=P.describe();self.assertFalse(d["defaultArtifactIO"]);self.assertFalse(d["modelDeserialized"])
  self.assertEqual(d["originalCheckpointAdmission"],"deny")
  self.assertFalse(d["originalExecutionSemanticsEquivalent"])
 def test_isolated_opaque_training_config_does_not_enter_weight_graph(self):
  m=self.machine();root,selected=root_for(m)
  unknown=m.global_token("fixture_config","Record")
  config=m.reduce(unknown,());m.stack=[config]
  state=m.mapping();state.items["literal"]="inert";m.stack.append(state);m.apply("BUILD",None)
  root.items["config"]=config
  rows=m.select(root);self.assertEqual(rows[0]["bytes"],8)
 def test_unknown_never_called_only_opaque_token_returned(self):
  m=self.machine();value=m.reduce(m.global_token("fixture_config","Record"),())
  self.assertIs(type(value),P.Opaque);self.assertEqual(value.kind,"REDUCE")
 def test_unknown_state_tuple_build_once_no_execution(self):
  m=self.machine();value=m.reduce(m.global_token("fixture_config","Record"),())
  m.stack=[value,(3,"little",None)];m.apply("BUILD",None)
  self.assertTrue(value.built);self.assertEqual(value.state,(3,"little",None))
  m.stack.append(None)
  with self.assertRaisesRegex(P.ProjectionError,"opaque_state"):m.apply("BUILD",None)
 def test_opaque_result_cannot_be_called(self):
  m=self.machine();value=m.reduce(m.global_token("fixture_config","Record"),())
  with self.assertRaisesRegex(P.ProjectionError,"dynamic_callable"):m.reduce(value,())
 def test_opaque_cannot_be_mapping_write_target(self):
  m=self.machine();value=m.reduce(m.global_token("fixture_config","Record"),())
  with self.assertRaisesRegex(P.ProjectionError,"opaque_write"):m.setitems(value,["weight",None])
 def test_dangerous_global_anywhere_is_rejected(self):
  for pair in[("os","system"),("builtins","eval"),S.NESTED_DESERIALIZATION_SYMBOL]:
   with self.subTest(pair=pair):
    with self.assertRaisesRegex(P.ProjectionError,"dangerous_reference"):self.machine().global_token(*pair)
 def test_parameter_profile_is_not_silently_unwrapped(self):
  with self.assertRaisesRegex(P.ProjectionError,"parameter_unsupported"):self.machine().global_token(*S._PARAMETER_SYMBOL)
 def test_known_invalid_reducer_does_not_fall_back(self):
  m=self.machine()
  with self.assertRaises(OriginalFailure):m.reduce(Global("collections","OrderedDict"),("invalid",))
  with self.assertRaisesRegex(P.ProjectionError,"known_constructor_opcode"):m.reduce(Global("torch","FloatStorage"),())
 def test_known_newobj_does_not_fall_back(self):
  m=self.machine();m.stack=[Global("collections","OrderedDict"),()]
  with self.assertRaisesRegex(P.ProjectionError,"known_constructor_opcode"):m.apply("NEWOBJ",None)
 def test_newobj_ex_not_supported(self):
  with self.assertRaisesRegex(P.ProjectionError,"unsupported_opcode"):self.machine().apply("NEWOBJ_EX",None)
 def test_selected_tensor_escape_is_rejected(self):
  m=self.machine();root,selected=root_for(m)
  m.reduce(m.global_token("fixture_config","Record"),(selected.items["weight"],))
  with self.assertRaisesRegex(P.ProjectionError,"escaped_export"):m.select(root)
 def test_selected_storage_escape_is_rejected(self):
  m=self.machine();root,selected=root_for(m)
  m.reduce(m.global_token("fixture_config","Record"),(selected.items["weight"].storage,))
  with self.assertRaisesRegex(P.ProjectionError,"escaped_export"):m.select(root)
 def test_late_alias_write_is_in_escape_closure(self):
  m=self.machine();selected=m.mapping(True)
  m.reduce(m.global_token("fixture_config","Record"),(selected,))
  m.setitems(selected,["weight",build_tensor(m)]);root=m.mapping();root.items["state_dict"]=selected
  with self.assertRaisesRegex(P.ProjectionError,"escaped_export"):m.select(root)
 def test_consumed_empty_metadata_identity_is_not_lost(self):
  m=self.machine();metadata=m.mapping()
  m.reduce(m.global_token("fixture_config","Record"),(metadata,))
  tensor=build_tensor(m,metadata=metadata)
  self.assertIs(tensor.metadata,False)
  self.assertIs(m.dependencies[id(tensor)][6],metadata)
  root,_=root_for(m,tensor)
  with self.assertRaisesRegex(P.ProjectionError,"escaped_export"):m.select(root)
 def test_unknown_build_state_escape_is_checked(self):
  m=self.machine();root,selected=root_for(m)
  unknown=m.reduce(m.global_token("fixture_config","Record"),())
  m.stack=[unknown,(selected,)];m.apply("BUILD",None)
  with self.assertRaisesRegex(P.ProjectionError,"escaped_export"):m.select(root)
 def test_retained_hooks_escape_is_checked(self):
  m=self.machine();root,selected=root_for(m)
  m.reduce(m.global_token("fixture_config","Record"),(selected.items["weight"].hooks,))
  with self.assertRaisesRegex(P.ProjectionError,"escaped_export"):m.select(root)
 def test_opaque_in_consumed_dependency_is_rejected(self):
  m=self.machine();metadata=m.mapping();tensor=build_tensor(m,metadata=metadata)
  metadata.items["later"]=P.Opaque((),"REDUCE")
  root,_=root_for(m,tensor)
  with self.assertRaisesRegex(P.ProjectionError,"opaque_export"):m.select(root)
 def test_missing_dependency_refuses(self):
  m=self.machine();root,selected=root_for(m);del m.dependencies[id(selected.items["weight"])]
  with self.assertRaisesRegex(P.ProjectionError,"missing_dependency"):m.select(root)
 def test_duplicate_storage_refuses_not_alias_reconstruction(self):
  m=self.machine();root,selected=root_for(m)
  selected.items["other"]=build_tensor(m,key="0")
  with self.assertRaisesRegex(P.ProjectionError,"duplicate_storage"):m.select(root)
 def test_bool_int_key_collision_refuses(self):
  m=self.machine();target=m.mapping()
  m.setitems(target,[1,"one"])
  with self.assertRaisesRegex(P.ProjectionError,"mapping_key"):m.setitems(target,[True,"bool"])
 def test_duplicate_key_refuses(self):
  m=self.machine();target=m.mapping();m.setitems(target,["x",1])
  with self.assertRaisesRegex(P.ProjectionError,"duplicate_key"):m.setitems(target,["x",2])
 def test_non_str_export_and_reserved_name_refuse(self):
  for key in[1,True,"__metadata__",""]:
   with self.subTest(key=key):
    m=self.machine();root,selected=root_for(m);selected.items={key:selected.items["weight"]}
    with self.assertRaisesRegex(P.ProjectionError,"root_state_dict"):m.select(root)
 def test_cycles_terminate_and_budget_is_enforced(self):
  m=self.machine();value=m.mapping();value.items["self"]=value
  self.assertEqual(P.closure([value],m.children,m.mutable),{id(value)})
  for i in range(4):value.items[str(i)]=m.mapping()
  with self.assertRaisesRegex(P.ProjectionError,"graph_budget"):P.closure([value],m.children,m.mutable,2)
 def test_pure_metadata_float_must_be_finite(self):
  for x in[float("nan"),float("inf")]:
   with self.assertRaisesRegex(P.ProjectionError,"metadata_stream"):self.machine().apply("BINFLOAT",x)
 def test_pid_f32_and_canonical_location_are_strict(self):
  for location,kind,code in[("meta","FloatStorage","source_location"),("cpu","IntStorage","tensor_profile")]:
   with self.assertRaisesRegex(P.ProjectionError,code):
    self.machine().persistent(("storage",Global("torch",kind),"0",location,2))
class TensorTests(unittest.TestCase):
 def tensor(self,**changes):
  t=Tensor(Storage(),0,(2,),(1,),Map(True),None)
  for key,value in changes.items():setattr(t,key,value)
  return t
 def test_f32_cpu_dense_metadata(self):
  row=P.validate_dense_tensor(self.tensor(),S);self.assertEqual(row["dtype"],"F32");self.assertEqual(row["bytes"],8)
 def test_negative_view_rejected_even_if_dense(self):
  with self.assertRaisesRegex(P.ProjectionError,"tensor_profile"):P.validate_dense_tensor(self.tensor(metadata=True),S)
 def test_empty_consumed_metadata_effect_allowed(self):
  self.assertEqual(P.validate_dense_tensor(self.tensor(metadata=False),S)["bytes"],8)
 def test_offset_partial_view_and_transpose_refused(self):
  for changes in[{"offset":1},{"shape":(1,)},{"stride":(0,)},{"shape":(1,2),"stride":(1,1)}]:
   with self.subTest(changes=changes):
    with self.assertRaisesRegex(P.ProjectionError,"tensor_profile"):P.validate_dense_tensor(self.tensor(**changes),S)
 def test_unknown_metadata_and_nonempty_hooks_refused(self):
  t=self.tensor();t.hooks.items["callback"]=None
  for value in[t,self.tensor(metadata=0),self.tensor(metadata="negative")]:
   with self.assertRaisesRegex(P.ProjectionError,"tensor_profile"):P.validate_dense_tensor(value,S)
 def test_bool_shape_or_stride_is_not_integer(self):
  for changes in[{"shape":(True,)},{"stride":(True,)}]:
   with self.assertRaisesRegex(P.ProjectionError,"tensor_profile"):P.validate_dense_tensor(self.tensor(**changes),S)
 def test_scalar_and_zero_sized_shapes_metadata_only(self):
  scalar=self.tensor(storage=Storage(numel=1),shape=(),stride=())
  empty=self.tensor(storage=Storage(numel=0),shape=(0,),stride=(1,))
  self.assertEqual(P.validate_dense_tensor(scalar,S)["bytes"],4)
  self.assertEqual(P.validate_dense_tensor(empty,S)["bytes"],0)


class DeviceLiteralTests(unittest.TestCase):
 def pid(self,key="0",tag="cpu",kind="FloatStorage",numel=2):
  return("storage",Global("torch",kind),key,tag,numel)
 def test_cpu_existing_path_preserved(self):
  m=Machine(dict(LIMITS));original=self.pid();m.persistent(original)
  self.assertEqual(m.original_devices,{"0":"cpu"})
  self.assertEqual(m.last_pid,original)
 def test_canonical_cuda_labels_normalize_only_pid_location(self):
  for tag in("cuda:0","cuda:1","cuda:9","cuda:10","cuda:255"):
   with self.subTest(tag=tag):
    m=Machine(dict(LIMITS));original=self.pid(tag=tag);m.persistent(original)
    self.assertEqual(m.original_devices,{"0":tag})
    self.assertIs(m.last_pid[1],original[1])
    self.assertEqual((m.last_pid[0],m.last_pid[2],m.last_pid[3],m.last_pid[4]),
                     (original[0],original[2],"cpu",original[4]))
 def test_other_or_noncanonical_backends_refused(self):
  for tag in("meta","mps:0","MPS","mps ","mps\n","cuda:00","cuda:+0","cuda:-1","cuda:256"," cuda:0","cuda:0 ",
             "CUDA:0","cpu:0","xpu:0","privateuseone:0","cuda:٠","cuda:０",
             "cuda:0\n","cuda:1.0","cuda:000"):
   with self.subTest(tag=tag):
    with self.assertRaisesRegex(P.ProjectionError,"source_location"):P.validated_device_tag(tag)
 def test_nonexact_string_does_not_call_comparison(self):
  class String(str):
   def __eq__(self,other):raise AssertionError("device eq executed")
  for tag in(String("cpu"),None,0,True,Global("torch","device")):
   with self.assertRaisesRegex(P.ProjectionError,"source_location"):P.validated_device_tag(tag)
 def test_same_storage_key_same_original_tag_accepted(self):
  m=Machine(dict(LIMITS));m.persistent(self.pid(tag="cuda:0"));m.persistent(self.pid(tag="cuda:0"))
  self.assertEqual(m.original_devices,{"0":"cuda:0"})
 def test_same_storage_key_different_original_tag_refused(self):
  for before,after in(("cpu","cuda:0"),("cuda:0","cpu"),("cuda:0","cuda:1")):
   with self.subTest(before=before,after=after):
    m=Machine(dict(LIMITS));m.persistent(self.pid(tag=before))
    with self.assertRaisesRegex(P.ProjectionError,"source_location_conflict"):m.persistent(self.pid(tag=after))
 def test_distinct_keys_can_retain_distinct_provenance(self):
  m=Machine(dict(LIMITS));m.persistent(self.pid(key="0",tag="cpu"));m.persistent(self.pid(key="1",tag="cuda:1"))
  self.assertEqual(m.original_devices,{"0":"cpu","1":"cuda:1"})
 def test_key_and_numel_exact_types_and_bounds(self):
  for key,numel in((True,2),("bad/key",2),("0",True),("0",-1),("0",1<<64)):
   with self.subTest(key=key,numel=numel):
    with self.assertRaisesRegex(P.ProjectionError,"tensor_profile"):
     Machine(dict(LIMITS)).persistent(self.pid(key=key,numel=numel,tag="cuda:0"))
 def test_added_exact_device_literals_keep_parent_cpu_layout(self):
  for tag in("cuda","mps"):
   with self.subTest(tag=tag):
    m=Machine(dict(LIMITS));original=self.pid(tag=tag);m.persistent(original)
    self.assertEqual(m.original_devices,{"0":tag});self.assertEqual(m.last_pid[3],"cpu")
 def test_added_literals_cannot_conflict_for_same_storage(self):
  for before,after in(("mps","cpu"),("cuda","cuda:0"),("mps","cuda"),("cuda:1","mps")):
   with self.subTest(before=before,after=after):
    m=Machine(dict(LIMITS));m.persistent(self.pid(tag=before))
    with self.assertRaisesRegex(P.ProjectionError,"source_location_conflict"):m.persistent(self.pid(tag=after))
 def test_new_profile_policy_is_distinct_without_device_execution(self):
  self.assertNotEqual(P.policy_sha256(),"bdfc4bbe79fc12fd7bc00fbb1b8b01f4c953add00130cd679b60375c010fa947")
  self.assertFalse(P.projection_policy()["deviceCodeExecuted"]);self.assertFalse(P.projection_policy()["originalExecutionSemanticsEquivalent"])
 def test_profile_and_original_denial_remain_explicit(self):
  policy=P.projection_policy()
  self.assertFalse(policy["deviceCodeExecuted"])
  self.assertEqual(policy["outputDevice"],"cpu")
  self.assertEqual(policy["originalAdmission"],"deny")
  self.assertFalse(policy["originalExecutionSemanticsEquivalent"])

class PlanBindingTests(unittest.TestCase):
 def plan(self):
  gate=types.SimpleNamespace(receiptSHA256="a"*64,runId="1"*32,generation="b"*64,rulesSHA256="c"*64,finishedUnix=100)
  context=types.SimpleNamespace(avGate=gate,pid=123,deadline=200,moduleSHA256="e"*64,policySHA256=P.policy_sha256())
  return P.ProjectionPlan(context,7,(1,2,486423,4,5),
   {"0":{"payloadOffset":128,"size":8,"nameRaw":b"metadata-name"}},
   [{"name":"weight","storageKey":"0","bytes":8,"shape":[2],"dtype":"F32"}],
   b"metadata-only",{"outputBytes":29,"sourceSHA256":P.INPUT_SHA})
 def test_exact_snapshot_accepted_metadata_only(self):
  plan=self.plan();snapshot=P.checked_plan_snapshot(plan)
  self.assertEqual(snapshot["entries"]["0"]["payloadOffset"],128)
 def test_offsets_header_and_tensor_byte_mutation_refused(self):
  changes=[
   lambda p:p.entries["0"].update(payloadOffset=129),
   lambda p:setattr(p,"header",b"changed-metadata"),
   lambda p:p.tensors[0].update(bytes=4),
   lambda p:p.tensors[0].update(name="changed"),
   lambda p:p.tensors[0]["shape"].append(2),
   lambda p:p.metadata.update(outputBytes=30),
   lambda p:setattr(p,"sourceStamp",(1,3,486423,4,5)),
   lambda p:setattr(p.context.avGate,"generation","d"*64),
   lambda p:setattr(p.context,"moduleSHA256","f"*64),
   lambda p:setattr(p.context,"policySHA256","f"*64)]
  for change in changes:
   with self.subTest(change=changes.index(change)):
    plan=self.plan();change(plan)
    with self.assertRaisesRegex(P.ProjectionError,"plan_changed"):P.checked_plan_snapshot(plan)
 def test_returned_snapshot_is_independent_copy(self):
  plan=self.plan();snapshot=P.checked_plan_snapshot(plan)
  snapshot["entries"]["0"]["payloadOffset"]=0
  self.assertEqual(P.checked_plan_snapshot(plan)["entries"]["0"]["payloadOffset"],128)
 def test_private_snapshot_digest_mismatch_refused(self):
  plan=self.plan();plan._snapshot+=b" "
  with self.assertRaisesRegex(P.ProjectionError,"plan_changed"):P.checked_plan_snapshot(plan)
 def test_windows_context_cannot_read_artifacts(self):
  if P.sys.platform!="linux":
   with self.assertRaisesRegex(P.ProjectionError,"runtime_guard"):
    P.require_context(P._Context(200))

if __name__=="__main__":unittest.main()
