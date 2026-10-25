"""Actual sanitized AV-receipt metadata tests only; no model, ZIP or Pickle IO.
Replay-time tests validate receipt semantics at finishedUnix+1. A separate live
clock result is printed and must be fresh before ROOT can bind a runtime gate.
"""
import argparse,copy,hashlib,importlib.util,json,sys,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("projection_av_metadata",HERE/"safe_weight_projection.py")
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
RAW=RECORD=EXPECTED=REPLAY_NOW=None
def read_metadata(path,pin,maximum):
 path=Path(path);before=path.stat()
 with path.open("rb")as stream:raw=stream.read(maximum+1)
 if len(raw)>maximum or len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=pin:raise ValueError("metadata-input-pin")
 return raw
class ActualAVMetadata(unittest.TestCase):
 def validate(self,record=None,expected=None,now=None):
  raw=RAW if record is None else P.canonical(record)
  wanted=copy.deepcopy(EXPECTED)if expected is None else expected
  if record is not None:wanted["receiptSHA256"]=P.sha(raw)
  return P.validate_source_av_receipt_metadata(raw,wanted,REPLAY_NOW if now is None else now)
 def altered(self,change):
  record=copy.deepcopy(RECORD);change(record)
  with self.assertRaises(P.ProjectionError):self.validate(record)
 def test_real_source_av_schema_at_record_time(self):
  result=self.validate()
  self.assertEqual(result["status"],"VALID_NATIVE_CLEAN_STATIC_UNSUPPORTED_METADATA_NOT_RUNTIME_GATE")
  self.assertEqual(result["sourceAVReceiptSHA256"],EXPECTED["receiptSHA256"])
 def test_wrong_receipt_sha(self):
  expected=copy.deepcopy(EXPECTED);expected["receiptSHA256"]="0"*64
  with self.assertRaisesRegex(P.ProjectionError,"source_av_binding"):self.validate(expected=expected)
 def test_stale_source_av_is_rejected(self):
  with self.assertRaisesRegex(P.ProjectionError,"source_av_stale"):self.validate(now=RECORD["finishedUnix"]+1801)
 def test_future_source_av_is_rejected(self):
  with self.assertRaisesRegex(P.ProjectionError,"source_av_stale"):self.validate(now=RECORD["finishedUnix"]-1)
 def test_http422_rejected(self):
  self.altered(lambda r:r["inner"]["fullAV"]["cases"][0]["observation"].update(httpStatus=422))
 def test_signature_rejected(self):
  self.altered(lambda r:r["inner"]["fullAV"]["cases"][0]["observation"].update(rules=["malware.signature-match"],severities=["critical"]))
 def test_high_severity_rejected(self):
  self.altered(lambda r:r["inner"]["fullAV"]["cases"][0]["observation"].update(severities=["high"]))
 def test_native_coverage_failure_rejected(self):
  self.altered(lambda r:r["inner"]["fullAV"]["cases"][0]["observation"].update(coverageCodes=["clamav_coverage_incomplete"]))
 def test_wrong_identity_or_generation_rejected(self):
  for key in("identityMatched","generationMatched","protocolValid"):
   with self.subTest(key=key):self.altered(lambda r:r["inner"]["fullAV"]["cases"][0]["observation"].update({key:False}))
 def test_request_error_rejected(self):
  self.altered(lambda r:r["inner"]["fullAV"]["cases"][0]["observation"].update(requestError="worker-failed"))
 def test_wrong_source_digest_rejected(self):
  self.altered(lambda r:r["inner"]["fullAV"]["cases"][0].update(sha256="0"*64))
 def test_wrong_source_size_rejected(self):
  self.altered(lambda r:r["inner"]["fullAV"]["cases"][0].update(bytes=P.INPUT_BYTES-1))
 def test_unfinished_cleanup_rejected(self):
  self.altered(lambda r:r["cleanup"].update(success=False))
 def test_static_only_receipt_rejected(self):
  self.altered(lambda r:r.update(scope="R25_SINGLE_SASREC_STATIC_ONLY_NOT_ADMISSION"))
 def test_fullav_failed_or_not_absent_rejected(self):
  for key,value in[("status","FAIL"),("ownedProcessesAbsent",False),("forcedKills",1),("fullAV",False)]:
   with self.subTest(key=key):self.altered(lambda r:r["inner"]["fullAV"].update({key:value}))
 def test_changed_reference_generation_rejected(self):
  expected=copy.deepcopy(EXPECTED);expected["generation"]="0"*64
  with self.assertRaisesRegex(P.ProjectionError,"source_av_binding"):self.validate(expected=expected)
 def test_changed_limits_bundle_rejected(self):
  expected=copy.deepcopy(EXPECTED);expected["completeBundleEvidence"]["evidence"]["limits"]["native_threads"]=1
  expected["limitsSHA256"]=P.sha(P.canonical(expected["completeBundleEvidence"]["evidence"]["limits"]))
  with self.assertRaisesRegex(P.ProjectionError,"source_av_binding"):self.validate(expected=expected)
 def test_bare_boolean_not_source_av_receipt(self):
  with self.assertRaisesRegex(P.ProjectionError,"source_av_shape"):P.validate_source_av_receipt_metadata(True,EXPECTED,REPLAY_NOW)
 def test_not_a_sanitizer_or_original_allow(self):
  result=self.validate()
  self.assertIn("STATIC_UNSUPPORTED",result["status"])
  self.assertEqual(RECORD["inner"]["fullAV"]["cases"][0]["observation"]["admission"],"deny")

def main():
 global RAW,RECORD,EXPECTED,REPLAY_NOW
 parser=argparse.ArgumentParser()
 parser.add_argument("--receipt",required=True);parser.add_argument("--receipt-sha256",required=True)
 parser.add_argument("--bundle",required=True);parser.add_argument("--bundle-sha256",required=True)
 args=parser.parse_args()
 RAW=read_metadata(args.receipt,args.receipt_sha256,2<<20);RECORD=json.loads(RAW)
 bundle=json.loads(read_metadata(args.bundle,args.bundle_sha256,32768))
 full=RECORD["inner"]["fullAV"]
 EXPECTED={"receiptSHA256":P.sha(RAW),"runId":RECORD["runId"],"imageId":RECORD["imageId"],
  "generation":full["generation"],"rulesSHA256":P.sha(P.canonical(full["rules"])),
  "limitsSHA256":P.sha(P.canonical(bundle["evidence"]["limits"])),"completeBundleEvidence":bundle}
 REPLAY_NOW=RECORD["finishedUnix"]+1
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(ActualAVMetadata)
 result=unittest.TextTestRunner(verbosity=1).run(suite)
 try:
  P.validate_source_av_receipt_metadata(RAW,EXPECTED,time.time());live="FRESH_METADATA_VALID"
 except P.ProjectionError as error:live=error.code
 print(json.dumps({"scope":"ACTUAL_SANITIZED_AV_METADATA_ONLY_NOT_RUNTIME_GATE",
  "testsRun":result.testsRun,"passed":result.wasSuccessful(),"liveClockStatus":live,
  "receiptSHA256":P.sha(RAW),"sourceOriginalAdmission":"deny","newSFTQualified":False,
  "artifactIO":False,"metadataReplayClock":REPLAY_NOW,"moduleSHA256":P.sha((HERE/"safe_weight_projection.py").read_bytes()),
  "policySHA256":P.policy_sha256()}))
 return 0 if result.wasSuccessful()else 1
if __name__=="__main__":raise SystemExit(main())
