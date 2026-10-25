"""ROOT Linux-only inert TAR routing dev matrix; Describe is zero-input.

No model loader, unpickler, command reducer or external process is invoked.
Every serialized fixture is created only after the complete frozen H guard.
"""
import argparse,contextlib,gzip,hashlib,importlib.util,io,json,logging,os,stat,sys,tarfile,time,zipfile
from pathlib import Path
HERE=Path(__file__).parent
BASELINE_SHA='6062a3f95ab822be816d6e84aa3cc32934490b60d85242f19162e2160b6f7bb3'
CANDIDATE_SHA='b2e80d9544f0c5dd313d3758107ea6069b0c0a742cd7f78030901aabea7ffda6'
HELPER_SHA='7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b'
MAX_FIXTURES=1<<20
MAX_OUTPUT=128<<10
# IDs and expectations are preregistered before Linux execution. ALLOW0 is a
# projection with no inspected Pickle; it never means universal model safety.
CASES=(
 ('v7-literal-direct-tar','v7-literal','artifact.tar','ALLOW_PICKLE','ALLOW_PICKLE',None),
 ('v7-danger-direct-tar','v7-danger','artifact.tar','DANGEROUS_REF','DANGEROUS_REF',None),
 ('v7-literal-tgz','gz-v7-literal','artifact.tgz','ALLOW0','ALLOW_PICKLE',None),
 ('v7-danger-tgz','gz-v7-danger','artifact.tgz','ALLOW0','DANGEROUS_REF',None),
 ('v7-literal-gz','gz-v7-literal','artifact.gz','ALLOW0','ALLOW_PICKLE',None),
 ('v7-danger-gz','gz-v7-danger','artifact.gz','ALLOW0','DANGEROUS_REF',None),
 ('v7-literal-renamed-bin-gzip','gz-v7-literal','artifact.bin','ALLOW0','ALLOW_PICKLE',None),
 ('v7-danger-renamed-bin-gzip','gz-v7-danger','artifact.bin','ALLOW0','DANGEROUS_REF',None),
 ('v7-literal-unknown-suffix','v7-literal','artifact.txt','ALLOW0','ALLOW_PICKLE',None),
 ('v7-danger-unknown-suffix','v7-danger','artifact.txt','ALLOW0','DANGEROUS_REF',None),
 ('old-pickle-suffix-precedence','v7-literal','artifact.bin','DENY_CODE:invalid_serialization','DENY_CODE:invalid_serialization',None),
 ('ustar-literal-old-route','ustar-literal','artifact.tar','ALLOW_PICKLE','ALLOW_PICKLE',None),
 ('ustar-danger-old-route','ustar-danger','artifact.tar','DANGEROUS_REF','DANGEROUS_REF',None),
 ('ustar-literal-gzip-old-route','gz-ustar-literal','artifact.tgz','ALLOW_PICKLE','ALLOW_PICKLE',None),
 ('ustar-danger-gzip-old-route','gz-ustar-danger','artifact.tgz','DANGEROUS_REF','DANGEROUS_REF',None),
 ('pax-literal-old-route','pax-literal','artifact.tar','ALLOW_PICKLE','ALLOW_PICKLE',None),
 ('pax-danger-old-route','pax-danger','artifact.tar','DANGEROUS_REF','DANGEROUS_REF',None),
 ('pax-literal-gzip-old-route','gz-pax-literal','artifact.tgz','ALLOW_PICKLE','ALLOW_PICKLE',None),
 ('pax-danger-gzip-old-route','gz-pax-danger','artifact.tgz','DANGEROUS_REF','DANGEROUS_REF',None),
 ('ordinary-nontar-old-success','ordinary','artifact.txt','ALLOW0','ALLOW0',None),
 ('allzero-old-success','zero','artifact.txt','ALLOW0','ALLOW0',None),
 ('bad-checksum-not-candidate','bad-checksum','artifact.txt','ALLOW0','ALLOW0',None),
 ('short-header-not-candidate','short-header','artifact.txt','ALLOW0','ALLOW0',None),
 ('bad-checksum-old-tar-deny','bad-checksum','artifact.tar','DENY_CODE:invalid_serialization','DENY_CODE:invalid_serialization',None),
 ('valid-header-short-body','gz-short-body','artifact.tgz','ALLOW0','DENY_CODE:archive_member_size',None),
 ('valid-first-bad-second-header','gz-bad-second','artifact.tgz','ALLOW0','DENY_CODE:invalid_serialization',None),
 ('missing-double-zero-tail','gz-single-zero-tail','artifact.tgz','ALLOW0','DENY_CODE:invalid_serialization',None),
 ('nonzero-tail','gz-nonzero-tail','artifact.tgz','ALLOW0','DENY_CODE:invalid_serialization',None),
 ('symbolic-link-rejected','gz-symlink','artifact.tgz','ALLOW0','DENY_CODE:archive_link_or_special_file',None),
 ('special-file-rejected','gz-special','artifact.tgz','ALLOW0','DENY_CODE:archive_link_or_special_file',None),
 ('directory-payload-rejected','gz-directory-payload','artifact.tgz','ALLOW0','DENY_CODE:archive_member_size',None),
 ('new-tar-global-member-budget','gz-two-members','artifact.tgz','ALLOW0','DENY_CODE:archive_member_limit','members2'),
 ('new-tar-global-depth-budget','gz-v7-literal','artifact.tgz','ALLOW0','DENY_CODE:archive_depth_limit','depth1'),
 ('new-tar-global-expanded-budget','gz-v7-literal','artifact.tgz','ALLOW0','DENY_CODE:expanded_bytes_limit','expanded-after-outer3'),
 ('pickle-literal-preserved','pickle-literal','artifact.pkl','ALLOW_PICKLE','ALLOW_PICKLE',None),
 ('pickle-danger-preserved','pickle-danger','artifact.pkl','DANGEROUS_REF','DANGEROUS_REF',None),
 ('safetensors-preserved','safetensors','artifact.safetensors','ALLOW0','ALLOW0',None),
 ('numeric-npy-preserved','npy','artifact.npy','ALLOW0','ALLOW0',None),
 ('zip-pickle-literal-preserved','zip-literal','artifact.zip','ALLOW_PICKLE','ALLOW_PICKLE',None),
 ('zip-pickle-danger-preserved','zip-danger','artifact.zip','DANGEROUS_REF','DANGEROUS_REF',None),
)
def need(ok,code):
    if not ok:raise ValueError(code)
def pin(path,wanted):
    p=Path(path);need(p.is_file()and not p.is_symlink()and all(not v.is_symlink()for v in p.parents),'CODE-path')
    a=p.stat()
    with p.open('rb')as f:x=os.fstat(f.fileno());raw=f.read(512001);y=os.fstat(f.fileno())
    ident=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(stat.S_ISREG(x.st_mode)and x.st_nlink==1 and ident(a)==ident(x)==ident(y)==ident(p.stat())and 0<len(raw)<=512000 and hashlib.sha256(raw).hexdigest()==wanted,'CODE-fullSHA-fstat')
    return raw
def load_pinned(path,name,wanted):
    raw=pin(path,wanted);spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
class Fixtures:
    def __init__(self,H,cap):
        need(sys.platform=='linux'and cap is H._CAP and cap is not None,'Linux-fixture-capability');self.H=H;self.B=H.Builder(cap);self.cache={}
    def payload(self,danger):
        if danger:
            # GLOBAL reference only, no REDUCE/constructor/call. Never unpickle.
            raw=bytes([128,2])+self.B.global_ref('os','system')+b'.';need(b'R'not in raw,'no-REDUCE');return raw
        return self.B.dumps(None,protocol=2)
    def header(self,name,size,kind=tarfile.REGTYPE,v7=True):
        info=tarfile.TarInfo(name);info.size=size;info.mode=0o600;info.uid=info.gid=0;info.mtime=0;info.type=kind
        if kind==tarfile.SYMTYPE:info.linkname='inert-target'
        raw=bytearray(info.tobuf(format=tarfile.USTAR_FORMAT))
        if v7:
            raw[257:512]=bytes(255);raw[148:156]=b' '*8;checksum=sum(raw);raw[148:156]=('%06o'%checksum).encode('ascii')+b'\0 '
        return bytes(raw)
    def tar(self,danger=False,v7=True,kind=tarfile.REGTYPE,declared=None,members=1,zeros=2):
        body=self.payload(danger)if kind==tarfile.REGTYPE else b'x'if kind==tarfile.DIRTYPE else b''
        out=bytearray()
        for i in range(members):
            name='z_payload%d.pkl'%i;size=len(body)if declared is None else declared
            out+=self.header(name,size,kind,v7)+body+bytes((-len(body))%512)
        out+=bytes(zeros*512);return bytes(out)
    def pax(self,danger):
        body=self.payload(danger);out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w',format=tarfile.PAX_FORMAT)as archive:
            info=tarfile.TarInfo('z_payload.pkl');info.size=len(body);info.mode=0o600;info.mtime=0;info.pax_headers={'comment':'bounded inert metadata'};archive.addfile(info,io.BytesIO(body))
        return out.getvalue()
    def build(self,key):
        if key in self.cache:return self.cache[key]
        if key.startswith('gz-'):raw=gzip.compress(self.build(key[3:]),mtime=0)
        elif key=='v7-literal':raw=self.tar()
        elif key=='v7-danger':raw=self.tar(True)
        elif key=='ustar-literal':raw=self.tar(v7=False)
        elif key=='ustar-danger':raw=self.tar(True,v7=False)
        elif key=='pax-literal':raw=self.pax(False)
        elif key=='pax-danger':raw=self.pax(True)
        elif key=='ordinary':raw=b'z ordinary nonarchive text\n'
        elif key=='zero':raw=bytes(1024)
        elif key=='bad-checksum':
            raw=bytearray(self.tar());raw[0]^=1;raw=bytes(raw)
        elif key=='short-header':raw=b'z'*511
        elif key=='short-body':raw=self.tar(declared=4096)
        elif key=='bad-second':
            first=self.tar(zeros=0);bad=bytearray(self.header('z_second.pkl',0));bad[0]^=1;raw=first+bytes(bad)+bytes(1024)
        elif key=='single-zero-tail':raw=self.tar(zeros=1)
        elif key=='nonzero-tail':raw=self.tar()+b'z'+bytes(511)
        elif key=='symlink':raw=self.tar(kind=tarfile.SYMTYPE)
        elif key=='special':raw=self.tar(kind=tarfile.CHRTYPE)
        elif key=='directory-payload':raw=self.tar(kind=tarfile.DIRTYPE)
        elif key=='two-members':raw=self.tar(members=2)
        elif key=='pickle-literal':raw=self.payload(False)
        elif key=='pickle-danger':raw=self.payload(True)
        elif key=='safetensors':
            header=json.dumps({'x':{'dtype':'U8','shape':[1],'data_offsets':[0,1]}},sort_keys=True,separators=(',',':')).encode('ascii');header+=b' '*((-len(header))%8);raw=len(header).to_bytes(8,'little')+header+b'x'
        elif key=='npy':
            head=b"{'descr': '|u1', 'fortran_order': False, 'shape': (1,)}";head+=b' '*((-(10+len(head)+1))%64)+b'\n';raw=b'\x93NUMPY'+bytes([1,0])+len(head).to_bytes(2,'little')+head+b'x'
        elif key in{'zip-literal','zip-danger'}:
            out=io.BytesIO()
            with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED)as z:
                i=zipfile.ZipInfo('z_payload.pkl',(1980,1,1,0,0,0));i.external_attr=0o100600<<16;z.writestr(i,self.payload(key=='zip-danger'))
            raw=out.getvalue()
        else:raise ValueError('unknown-fixed-recipe')
        need(type(raw)is bytes and 0<len(raw)<=MAX_FIXTURES,'fixture-bound');self.cache[key]=raw;return raw
def observation(S,raw,name,limits):
    inspector=S.StaticInspector(limits);complete=True;code=None
    try:inspector.inspect(io.BytesIO(raw),name)
    except S.Incomplete as error:complete=False;code=error.args[0]if error.args and error.args[0]in S.ERROR_CODES else'OTHER'
    except S.FORMAT_EXCEPTIONS:complete=False;code='invalid_serialization'
    rules=sorted({x['rule']for x in inspector.findings});high=any(x['severity']in{'high','critical'}for x in inspector.findings)
    return{'complete':complete,'code':code,'rules':rules,'pickleFiles':inspector.pickle_files,'members':inspector.members,'expandedBytes':inspector.expanded,'projectedAdmission':'deny'if not complete or high else'allow'}
def matches(observed,expected):
    if expected.startswith('DENY_CODE:'):return observed['complete']is False and observed['code']==expected.split(':',1)[1]
    if expected=='DANGEROUS_REF':return observed['complete']is True and'pickle.dangerous-global'in observed['rules']and observed['projectedAdmission']=='deny'and observed['pickleFiles']>=1
    return observed['complete']is True and observed['projectedAdmission']=='allow'and(observed['pickleFiles']==0 if expected=='ALLOW0'else observed['pickleFiles']>=1)
def execute(args):
    need(sys.platform=='linux'and os.geteuid()==os.getegid()==65532 and set(os.getgroups())<={65532},'Linux-low-UID')
    need(args.root_idle_confirmed and type(args.deadline)is int and 0<args.deadline-time.time()<=120,'fresh-root-deadline')
    H=load_pinned(HERE/'fixture_helpers.py','v7_frozen_guard',HELPER_SHA);cap=H.environment(args.deadline,args.root_idle_confirmed);logging.disable(logging.CRITICAL)
    baseline=Path(args.baseline);candidate=Path(args.candidate)
    A=load_pinned(baseline,'v7_old_6062_source',BASELINE_SHA);B=load_pinned(candidate,'v7_candidate_source',CANDIDATE_SHA)
    fixtures=Fixtures(H,cap);records=[];total=0
    for case,key,name,expected_old,expected_new,override in CASES:
        need(time.time()<args.deadline,'matrix-deadline');raw=fixtures.build(key);total+=len(raw);need(total<=MAX_FIXTURES,'aggregate-fixture-bound')
        limits=dict(H.LIMITS)
        if override=='members2':limits['max_members']=2
        elif override=='depth1':limits['max_depth']=1
        elif override=='expanded-after-outer3':limits['max_expanded_bytes']=len(fixtures.build('v7-literal'))+3
        old=observation(A,raw,name,limits);new=observation(B,raw,name,limits)
        passed=matches(old,expected_old)and matches(new,expected_new)
        records.append({'id':case,'recipe':key,'nameClass':name.rsplit('.',1)[-1],'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'expectedOld':expected_old,'expectedNew':expected_new,'old':old,'new':new,'passed':passed,'notMalwareAccuracyOrAPP':True})
    pin(baseline,BASELINE_SHA);pin(candidate,CANDIDATE_SHA);need(time.time()<args.deadline,'matrix-deadline')
    result={'schema':1,'status':'PASS'if all(x['passed']for x in records)else'FAIL','scope':'AUTHOR_DEV_INERT_STATIC_TAR_ROUTING_MATRIX_NOT_FULLAV_OR_ADOPTION','tests':len(CASES),'passed':sum(x['passed']for x in records),'baselineSHA256':BASELINE_SHA,'candidateSHA256':CANDIDATE_SHA,'fixtureBytesGenerated':total,'fixtureFilesWritten':0,'records':records,'modelLoaded':False,'modelDeserialized':False,'AVRun':False,'GPUUsed':False,'candidateAdopted':False}
    encoded=json.dumps(result,sort_keys=True);need(len(encoded.encode('utf-8'))<=MAX_OUTPUT,'matrix-output-bound');print(encoded);return 0 if result['status']=='PASS'else 2
def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--baseline');p.add_argument('--candidate');p.add_argument('--deadline',type=int);p.add_argument('--root-idle-confirmed',action='store_true');args=p.parse_args(argv)
    if not args.execute:print(json.dumps({'mode':'DESCRIBE','sourceInputsRead':0,'fixtureBytesGenerated':0,'scannerImported':False,'tests':len(CASES),'baselineSHA256':BASELINE_SHA,'candidateSHA256':CANDIDATE_SHA}));return 0
    return execute(args)
if __name__=='__main__':
    try:raise SystemExit(main())
    except SystemExit:raise
    except Exception:print(json.dumps({'status':'REFUSED','code':'MATRIX_GUARD_OR_OPERATION','componentPASS':False,'AVRun':False}));raise SystemExit(2)
