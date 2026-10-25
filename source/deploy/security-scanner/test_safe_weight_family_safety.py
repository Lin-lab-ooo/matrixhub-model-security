# Copyright The MatrixHub Authors.
# Licensed under the Apache License, Version 2.0.
"""Pure functional safety tests; no archive/model/AV/runtime qualification."""
import types,unittest
from unittest.mock import patch
from family_test_support import P,S,Machine,LIMITS,OriginalFailure,Global,Map,List,Storage,Tensor,Parameter,build_tensor,root_for,approved_metadata_fixture,context,binding
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
 def setUp(self):
  fixture=approved_metadata_fixture();fixture.__enter__();self.addCleanup(fixture.__exit__,None,None,None)
 def plan(self):
  ctx=context();ctx.avGate=types.SimpleNamespace(receiptSHA256='a'*64,runId='1'*32,generation='b'*64,rulesSHA256='c'*64,finishedUnix=100,sourceBindingSHA256=ctx.sourceBindingSHA256)
  return P.ProjectionPlan(ctx,7,(1,2,1024,4,5),{'0':{'payloadOffset':128,'size':8,'nameRaw':b'metadata-name'}},[{'name':'weight','storageKey':'0','bytes':8,'shape':[2],'dtype':'F32'}],b'metadata-only',{'outputBytes':29,'sourceSHA256':binding()['inputSHA256']})
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
    P.require_context(P._Context(200,"e"*64,P.policy_sha256(),"reference",b"{}",P.sha(b"{}")))

if __name__=="__main__":unittest.main()
