# Copyright The MatrixHub Authors.
# Licensed under the Apache License, Version 2.0.
"""Binding, finite VM and native-AV receipt shape tests; no artifact execution."""
import copy,json,time,unittest
from unittest.mock import patch
from family_test_support import P,REAL_SCANNER as S,BUNDLE,A,B,text,glob,integer,ORDERED,tensor,metadata,approved_metadata_fixture,binding,context,parse,av_fixture,check_av
class BindingTests(unittest.TestCase):
 def test_legacy_pending_slots_refuse_before_runtime_checks(self):
  pending=P.canonical({'schema':1,'profiles':[{'slot':'reference','status':'PENDING'},{'slot':'independent','status':'PENDING'}]})
  with patch.multiple(P,TRUSTED_PROFILES_RAW=pending,TRUSTED_PROFILES_SHA256=P.sha(pending)):
   for slot in P.PROFILE_SLOTS:
    with self.subTest(slot=slot),patch.object(P,'_runtime_checks',side_effect=AssertionError('must not reach runtime')):
     with self.assertRaisesRegex(P.ProjectionError,'profile_pending'):
      P.new_context(1,'f'*64,slot,b'{}',P.sha(b'{}'))
 def test_exact_profile_and_canonical_identity(self):
  with approved_metadata_fixture():
   for slot in P.PROFILE_SLOTS:
    value=binding(slot);raw=P.canonical(value)
    self.assertEqual(P.validate_source_binding_metadata(raw,P.sha(raw),slot),value)
 def test_wrong_expected_digest_and_cross_slot_refuse(self):
  with approved_metadata_fixture():
   raw=P.canonical(binding())
   for sha,slot in [('0'*64,'reference'),(P.sha(raw),'independent')]:
    with self.assertRaises(P.ProjectionError):P.validate_source_binding_metadata(raw,sha,slot)
 def test_source_policy_metadata_types_and_budget_cannot_change(self):
  with approved_metadata_fixture():
   for key,value in [('inputSHA256','0'*64),('inputBytes',True),('dataPickleSHA256','0'*64),('dataPickleBytes',True),
                     ('profileSHA256','0'*64),('projectionPolicySHA256','0'*64),('schema',True),('upstreamRevision','main'),
                     ('upstreamNamespace',''),('upstreamRepository','x\n'),('upstreamVersionEvidenceSHA256',None)]:
    v=binding();v[key]=value;raw=P.canonical(v)
    with self.subTest(key=key),self.assertRaises(P.ProjectionError):P.validate_source_binding_metadata(raw,P.sha(raw),'reference')
 def test_extra_duplicate_noncanonical_and_nan_refuse(self):
  with approved_metadata_fixture():
   raw=P.canonical(binding())
   for changed in [raw+b' ',b'{"schema":1,"schema":1}',b'{"x":NaN}',P.canonical(dict(binding(),maxSourceBytes=1<<40))]:
    with self.assertRaises(P.ProjectionError):P.validate_source_binding_metadata(changed,P.sha(changed),'reference')
 def test_ready_profile_cannot_raise_static_caps(self):
  with approved_metadata_fixture():
   reg=json.loads(P.TRUSTED_PROFILES_RAW)
   for key,value in [('inputBytes',P.MAX_SOURCE_BYTES+1),('dataPickleBytes',P.MAX_METADATA+1),('inputBytes',True)]:
    row=copy.deepcopy(reg);row['profiles'][0][key]=value;raw=P.canonical(row)
    with patch.multiple(P,TRUSTED_PROFILES_RAW=raw,TRUSTED_PROFILES_SHA256=P.sha(raw)),self.assertRaises(P.ProjectionError):P.trusted_profile('reference')
 def test_registry_order_count_and_hash_are_fixed(self):
  raw=P.TRUSTED_PROFILES_RAW
  for bad in [raw+b' ',P.canonical({'schema':1,'profiles':[]}),P.canonical({'schema':1,'profiles':[{'slot':'independent'},{'slot':'reference'}]})]:
   with patch.object(P,'TRUSTED_PROFILES_RAW',bad),self.assertRaises(P.ProjectionError):P.trusted_profile('reference')
 def test_source_budget_and_member_bound(self):
  source={'inputBytes':1024}
  for count in [3,6,149,150]:P.validate_member_count(1024,count,source)
  for size,count in [(1025,3),(1024,151),(1024,2),(True,3),(1024,True),(P.MAX_SOURCE_BYTES+1,3)]:
   with self.assertRaises(P.ProjectionError):P.validate_member_count(size,count,source)
 def test_returned_binding_is_detached_and_context_tamper_refuses(self):
  with approved_metadata_fixture():
   ctx=context();v=P.bound_source(ctx);v['inputSHA256']='0'*64
   self.assertNotEqual(P.bound_source(ctx)['inputSHA256'],v['inputSHA256'])
   ctx.sourceBindingRaw+=b' '
   with self.assertRaises(P.ProjectionError):P.bound_source(ctx)
 def test_version_changes_cannot_reuse_outer_binding_digest(self):
  with approved_metadata_fixture():
   source=binding();old=P.canonical(source)
   for key,val in [('upstreamNamespace','another-owner'),('upstreamRepository','another/repo'),('upstreamRevision','f'*40),
                   ('upstreamBlobPath','another.pth'),('upstreamVersionEvidenceSHA256','f'*64)]:
    altered=dict(source);altered[key]=val
    with self.subTest(key=key),self.assertRaises(P.ProjectionError):
     P.validate_source_binding_metadata(P.canonical(altered),P.sha(old),'reference')
 def test_each_upstream_value_must_equal_ready_profile_even_with_new_binding_sha(self):
  with approved_metadata_fixture():
   for key,val in [('upstreamNamespace','different'),('upstreamRepository','test/different'),('upstreamRevision','f'*40),
                   ('upstreamBlobPath','different.pth'),('upstreamVersionEvidenceSHA256','f'*64),
                   ('versionAuthority','MATRIXHUB_PLANNED_REVISION')]:
    value=binding();value[key]=val;raw=P.canonical(value)
    with self.subTest(key=key),self.assertRaisesRegex(P.ProjectionError,'source_version'):
     P.validate_source_binding_metadata(raw,P.sha(raw),'reference')
 def test_no_planned_matrix_fields_or_generic_version_aliases(self):
  with approved_metadata_fixture():
   for key in ['tenantId','repositoryId','revision','blobPath','immutableVersionEvidenceSHA256',
               'plannedTenant','plannedCommit','matrixHubRevision','targetFixture']:
    value=binding();value[key]='planned';raw=P.canonical(value)
    with self.subTest(key=key),self.assertRaisesRegex(P.ProjectionError,'source_binding_shape'):
     P.validate_source_binding_metadata(raw,P.sha(raw),'reference')
 def test_ready_namespace_repository_and_real_evidence_pin_are_mandatory(self):
  with approved_metadata_fixture():
   registry=json.loads(P.TRUSTED_PROFILES_RAW)
   for key,val in [('originNamespace','other'),('originRepository','test/repo/extra'),
                   ('originVersionEvidenceSHA256',None),('originVersionEvidenceSHA256','PENDING')]:
    value=copy.deepcopy(registry);value['profiles'][0][key]=val;raw=P.canonical(value)
    with patch.multiple(P,TRUSTED_PROFILES_RAW=raw,TRUSTED_PROFILES_SHA256=P.sha(raw)),self.assertRaises(P.ProjectionError):
     P.trusted_profile('reference')
 def test_two_contexts_do_not_share_source_identity(self):
  with approved_metadata_fixture():
   first,second=context(),context('independent')
   before=P.bound_source(first)
   self.assertNotEqual(before['inputSHA256'],P.bound_source(second)['inputSHA256'])
   self.assertEqual(P.bound_source(first),before)
   self.assertNotEqual(first.sourceBindingSHA256,second.sourceBindingSHA256)
 def test_wrong_av_binding_refuses_before_any_source_fd_access(self):
  with approved_metadata_fixture():
   ctx=context();other=context('independent')
   ctx.avGate=P._AVGate('a'*64,'b'*32,P.REFERENCE_GEN,'c'*64,time.time(),other.sourceBindingSHA256)
   with patch.object(P.sys,'platform','linux'),patch.object(P,'held_source',side_effect=AssertionError('no fd access')):
    with self.assertRaisesRegex(P.ProjectionError,'source_av_required'):P.prove_projection(S,-1,ctx)

class RealFiniteVMTests(unittest.TestCase):
 def test_two_distinct_full_metadata_streams_use_real_unchanged_b2_vm(self):
  self.assertNotEqual(A,B)
  with approved_metadata_fixture():
   aa,ca=parse(A);bb,cb=parse(B,'independent')
   self.assertEqual(aa,[{'dtype':'F32','shape':[2],'bytes':8,'storageKey':'0','name':'weight'}])
   self.assertEqual(bb,[{'dtype':'F32','shape':[3],'bytes':12,'storageKey':'0','name':'different_weight'}])
   self.assertGreater(ca,20);self.assertGreater(cb,20)
 def test_source_metadata_swap_refused(self):
  with approved_metadata_fixture():
   with self.assertRaisesRegex(P.ProjectionError,'metadata_identity'):parse(B)
 def rejected(self,raw):
  with approved_metadata_fixture(raw_a=raw),self.assertRaises((P.ProjectionError,S.LegacyTorchError)):parse(raw)
 def test_complete_stream_and_protocol_required(self):
  self.rejected(A+b'X');self.rejected(b'\x80\x05'+A[2:]);self.rejected(A[:-1])
 def test_dangerous_and_nested_reference_anywhere(self):
  for pair in [('os','system'),('builtins','eval'),('torch.storage','_load_from_bytes')]:
   self.rejected(metadata(extra=glob(*pair)+b')R'))
 def test_known_invalid_constructor_no_opaque_fallback(self):
  self.rejected(metadata(extra=glob('collections','OrderedDict')+integer(7)+b'\x85R'))
 def test_opaque_argument_alias_to_selected_map_refuses(self):
  self.rejected(metadata(extra=glob('trusted_inert_fixture','AliasConsumer')+b'h\x00\x85R'))
 def test_dtype_offset_stride_and_device_expansions_refuse(self):
  for kw in [dict(kind='DoubleStorage'),dict(offset=1),dict(stride=2),dict(device='cuda:01'),dict(device='xpu')]:
   self.rejected(metadata(**kw))
 def test_duplicate_mapping_key_refuses(self):
  self.rejected(A[:-1]+text('state_dict')+b'}s.')
 def test_duplicate_storage_refuses(self):
  raw=b'\x80\x04}'+text('state_dict')+ORDERED+text('a')+tensor()+b's'+text('b')+tensor()+b'ss.'
  self.rejected(raw)
 def test_parameter_refuses(self):
  self.rejected(metadata(extra=glob('torch._utils','_rebuild_parameter')+b')R'))

class AVBindingTests(unittest.TestCase):
 def test_complete_native_clean_static_unsupported_shape_only(self):
  with approved_metadata_fixture():
   for slot in P.PROFILE_SLOTS:
    r,e,b=av_fixture(slot);self.assertIn('NOT_RUNTIME_GATE',check_av(r,e,b,slot=slot)['status'])
 def test_each_version_dimension_cannot_be_swapped_in_receipt(self):
  with approved_metadata_fixture():
   for key,val in [('upstreamNamespace','other'),('upstreamRepository','other/repo'),('upstreamRevision','f'*40),('upstreamBlobPath','other.pth'),
                   ('inputSHA256','f'*64),('dataPickleSHA256','f'*64),('upstreamVersionEvidenceSHA256','f'*64)]:
    r,e,b=av_fixture();r['sourceBinding'][key]=val
    with self.subTest(key=key),self.assertRaises(P.ProjectionError):check_av(r,e,b)
 def test_swapped_gate_hash_old_schema_and_wrong_gen_refuse(self):
  with approved_metadata_fixture():
   for change in [lambda r:r.update(sourceBindingSHA256='f'*64),lambda r:r.pop('sourceBinding'),
                  lambda r:r['inner']['fullAV'].update(generation='f'*64),lambda r:r.update(scope='OLD_SASREC_SCOPE')]:
    r,e,b=av_fixture();change(r)
    with self.assertRaises(P.ProjectionError):check_av(r,e,b)
 def test_stale_future_or_signature_original_allow_and_cleanup_fail_refuse(self):
  with approved_metadata_fixture():
   r,e,b=av_fixture()
   for now in [999,2800.001,True,float('nan')]:
    with self.assertRaises(P.ProjectionError):check_av(r,e,b,now)
   for change in [lambda r:r['cleanup'].update(success=False),
                  lambda r:r['inner']['fullAV']['cases'][0]['observation'].update(admission='allow',complete=True),
                  lambda r:r['inner']['fullAV']['cases'][0]['observation'].update(rules=['clamav.signature']),
                  lambda r:r['inner']['fullAV']['cases'][0].update(heldFDPrePostUnchanged=False)]:
    r,e,b=av_fixture();change(r)
    with self.assertRaises(P.ProjectionError):check_av(r,e,b)

class StaticBoundaryTests(unittest.TestCase):
 def test_no_prohibited_loader_added_and_source_caps_fixed(self):
  self.assertEqual((P.MAX_SOURCE_BYTES,P.MAX_ZIP_MEMBERS,P.MAX_METADATA,P.MAX_SLOTS,P.MAX_REFS,P.MAX_TENSORS,P.MAX_OUTPUT),
                   (2<<20,150,32768,65536,128,256,2<<20))
  src=(P.Path(P.__file__)).read_text(encoding='utf-8')
  for bad in ['pickle.loads','pickle.load(','torch.load','eval(','exec(','import torch']:
   self.assertNotIn(bad,src)

if __name__=="__main__":unittest.main()
