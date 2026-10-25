# Copyright The MatrixHub Authors.
# Licensed under the Apache License, Version 2.0.
"""Exact public HF identities and negative capsules, not runtime receipts."""
import copy,json,unittest
from family_test_support import P,FIXTURES
EVIDENCE={'reference':'62ce8ddd15cf7c7551d6d89fa7ed382b02ba86126091046bd649794f9cca750b','independent':'e725473d538bb047f26495b2d76acba008f7abd29f55fb5224bc9f69e1ae5487'}
CAPSULES={'reference':'ea190682812068ed9a1cc54cfab93e6072eb13a65257c70c5cce87c7101333e6','independent':'32352eb457380b55036fa49c660a6a4a0b261b2a8f0e3588de1207b69110f4c0'}
class ReadyIdentityTests(unittest.TestCase):
 def test_two_ready_profiles_match_actual_immutable_HF_metadata(self):
  for slot in P.PROFILE_SLOTS:
   profile=P.trusted_profile(slot);raw=(FIXTURES/slot/'version-metadata.json').read_bytes();self.assertEqual(P.sha(raw),EVIDENCE[slot]);v=json.loads(raw);entry=next(x for x in v['siblings']if x['rfilename']==profile['originBlobPath'])
   self.assertEqual((profile['status'],profile['originNamespace'],profile['originRepository'],profile['originRevision']),('READY','viberec',v['id'],v['sha']));self.assertEqual(profile['originVersionEvidenceSHA256'],EVIDENCE[slot]);self.assertEqual((profile['inputSHA256'],profile['inputBytes']),(entry['lfs']['sha256'],entry['lfs']['size']))
   self.assertEqual(profile['sourceAVScope'],'R25_PUBLIC_HF_FAMILY_BOUND_AV_NOT_ADMISSION');self.assertEqual(profile['sourceAVFullScope'],'R25_PUBLIC_HF_FAMILY_BOUND_AV_COMPLETE_NATIVE_SCAN');self.assertEqual(profile['sourceAVCaseId'],'FamilyReference'if slot=='reference'else'FamilyIndependent')
 def test_canonical_capsules_have_only_actual_upstream_fields(self):
  for slot in P.PROFILE_SLOTS:
   raw=(FIXTURES/slot/'source-binding.json').read_bytes();self.assertEqual(P.sha(raw),CAPSULES[slot]);binding=P.validate_source_binding_metadata(raw,CAPSULES[slot],slot);self.assertEqual(raw,P.canonical(binding));self.assertEqual(set(binding),P._BINDING_KEYS);self.assertEqual(binding['versionAuthority'],'PUBLIC_HF_IMMUTABLE_REVISION')
   self.assertFalse(any('planned'in key.lower()or'matrix'in key.lower()or'tenant'in key.lower()for key in binding))
 def test_swapped_capsule_or_recomputed_cross_identity_refuses(self):
  ref=json.loads((FIXTURES/'reference/source-binding.json').read_bytes());ind=json.loads((FIXTURES/'independent/source-binding.json').read_bytes())
  for slot,other in [('reference','independent'),('independent','reference')]:
   raw=(FIXTURES/other/'source-binding.json').read_bytes()
   with self.subTest(slot=slot),self.assertRaises(P.ProjectionError):P.validate_source_binding_metadata(raw,P.sha(raw),slot)
  for key in ['inputSHA256','inputBytes','dataPickleSHA256','dataPickleBytes','upstreamRepository','upstreamRevision','upstreamBlobPath','upstreamVersionEvidenceSHA256','profileSHA256','projectionPolicySHA256']:
   bad=copy.deepcopy(ref);bad[key]=ind[key]if key!='projectionPolicySHA256'else'0'*64;raw=P.canonical(bad)
   with self.subTest(key=key),self.assertRaises(P.ProjectionError):P.validate_source_binding_metadata(raw,P.sha(raw),'reference')
 def test_planned_matrix_fields_and_branch_alias_refuse(self):
  binding=json.loads((FIXTURES/'reference/source-binding.json').read_bytes())
  for key,value in [('plannedMatrixTenant','demo'),('targetMatrixCommit','a'*40),('upstreamRevision','main')]:
   bad=copy.deepcopy(binding);bad[key]=value;raw=P.canonical(bad)
   with self.subTest(key=key),self.assertRaises(P.ProjectionError):P.validate_source_binding_metadata(raw,P.sha(raw),'reference')
 def test_ready_is_identity_only_not_native_av_or_projection(self):
  self.assertEqual(P.describe()['status'],'READY_IDENTITIES_PENDING_NATIVE_BOUND_AV');policy=P.projection_policy();self.assertEqual(policy['originalAdmission'],'deny');self.assertEqual(policy['derivedState'],'QUARANTINE_REQUIRES_INDEPENDENT_FULL_SCAN');self.assertFalse(policy['targetMatrixHubVersionClaimed']);self.assertFalse(policy['originalExecutionSemanticsEquivalent'])

if __name__=="__main__":unittest.main()
