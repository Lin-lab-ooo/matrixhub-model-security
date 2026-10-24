"""Portable32 finite-token tests. Default DESCRIBE reads no source and runs no tests."""
import argparse,hashlib,importlib.util,json,re,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASELINE_SHA='3619a7f3e1f966cefa0a96dfa7d1e3c08895bbb690cf7bfd51bdf1a96bd5f2fe'
LOADER_SHA='8df4f3931517204dae2555bb72bb0f8f1c550fe2bfc5d5f00c4051843707f042'
def need(ok,code):
 if not ok:raise ValueError(code)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class SourcePathBinding:
 """Preserve old HERE/'scanner.py' assertions while selecting the real caller file."""
 def __init__(self,source):self.source=source
 def __truediv__(self,leaf):
  need(leaf=='scanner.py','unexpected-test-path');return self.source
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--baseline',type=Path);p.add_argument('--baseline-sha',default=BASELINE_SHA);p.add_argument('--source',type=Path);p.add_argument('--source-sha');a=p.parse_args(argv)
 if not a.execute:print(json.dumps({'mode':'DESCRIBE','testsRun':0,'sourceRead':False,'serializedFixturesGenerated':0,'DockerOrNetworkUsed':False}));return 0
 need(a.baseline_sha==BASELINE_SHA,'frozen-baseline-required');need(a.source is not None and type(a.source_sha)is str and re.fullmatch('[a-f0-9]{64}',a.source_sha),'explicit-current-source-and-sha-required')
 baseline=(a.baseline or HERE/'fixtures/scanner-baseline-3619.py').resolve();source=a.source.resolve();need(baseline.is_file()and source.is_file()and source!=baseline and not source.is_relative_to(HERE),'current-must-be-external-real-source-file')
 need(digest(baseline)==BASELINE_SHA and digest(source)==a.source_sha,'baseline-current-full-sha');need(digest(HERE/'token_loader.py')==LOADER_SHA,'original-token-loader-sha')
 loader=module(HERE/'token_loader.py','portable32_original_loader');prior=sys.modules.get('token_loader');sys.modules['token_loader']=loader
 try:tests=module(HERE/'test_token_contract.py','portable32_original_tests')
 finally:
  if prior is None:sys.modules.pop('token_loader',None)
  else:sys.modules['token_loader']=prior
 tests.HERE=SourcePathBinding(source);tests.CONFIG={'baselineSourcePath':str(baseline),'baselineSourceSHA256':BASELINE_SHA,'candidateSourceSHA256':a.source_sha};tests.B=loader.load_tokens(baseline,BASELINE_SHA,'portable32_baseline_tokens');tests.C=loader.load_tokens(source,a.source_sha,'portable32_current_tokens')
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(tests.Contract);need(suite.countTestCases()==32,'original32-inventory');result=unittest.TextTestRunner(verbosity=2).run(suite);need(digest(baseline)==BASELINE_SHA and digest(source)==a.source_sha,'sources-unchanged-after-tests');need('torch'not in sys.modules and 'pickle'not in sys.modules,'no-framework-or-pickle-import')
 ok=result.wasSuccessful()and result.testsRun==32 and not result.skipped
 print(json.dumps({'status':'PASS'if ok else'FAIL','testsRun':result.testsRun,'skipped':len(result.skipped),'baselinePath':str(baseline),'baselineSHA256':BASELINE_SHA,'sourcePath':str(source),'sourceSHA256':a.source_sha,'sourceIsCallerProvidedExternalFile':True,'currentScannerCopiedIntoTestPackage':False,'serializedFixturesGenerated':0,'frameworkOrPickleImported':False,'DockerOrNetworkUsed':False},ensure_ascii=False));return 0 if ok else 2
if __name__=='__main__':raise SystemExit(main())
