"""Independent ASCII STRING tracker holdouts; Linux guard before any fixture.
Default Describe has zero artifact/source reads. No loader/deserializer/AV call.
"""
import argparse,hashlib,importlib.util,io,json,os,pickletools,sys,tempfile
from pathlib import Path
BASE='19aee967a7d5c8e3857b4d962423af3a036f5f72af721a98372f419804b6c5ad'
CANDIDATE='7cd1be1e44b007f57a643bfbb195f4495fd97ec92df872a7cbf91dbb2e4d6e01'
HELPER='7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b'
LIMITS={'max_file_bytes':1<<20,'max_scan_bytes':1<<20,'max_expanded_bytes':1<<20,'max_members':64,'max_depth':3,'max_ratio':100,'max_pickle_opcodes':10000,'max_pickle_argument':8192}
def need(v,c):
    if not v:raise ValueError(c)
def load(path,wanted,name,H=None):
    if H is None:
        need(not path.is_symlink() and path.is_file() and path.stat().st_size<=64<<10,'fixed-helper');raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==wanted,'helper-pin')
    else:raw=H.bounded_sha(path,wanted)
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def run(a,H):
    # The exact fixed bundle uses Python3.13.16; STRING decoding facts refer to
    # its pickletools Latin-1 reader, not an older Python implementation.
    need(sys.version.split()[0]=='3.13.16','fixed-python-reader-version')
    B=load(a.baseline,BASE,'ascii_parent19aee',H);C=load(a.candidate,CANDIDATE,'ascii_candidatev3',H)
    rows=[];total=0
    def record(name,passed,**v):rows.append({'id':name,'passed':bool(passed),**v})
    def observe(m,path,limits=LIMITS):
        inspector=m.StaticInspector(dict(limits));code=None;operation=None
        try:
            with path.open('rb') as f:inspector.inspect(f,path.name)
            complete=True
        except m.Incomplete as e:complete=False;code=e.args[0] if len(e.args)==1 and e.args[0] in m.ERROR_CODES else 'UNCLASSIFIED'
        except m.FORMAT_EXCEPTIONS as e:
            complete=False;code='invalid_serialization';operation=type(e).__name__ if type(e).__name__ in {'ValueError','UnicodeDecodeError','UnicodeEncodeError','EOFError','BadZipFile','BadGzipFile','error'} else 'KNOWN_FORMAT_OTHER'
        except Exception:complete=False;code='UNEXPECTED_OPERATION';operation='OTHER'
        return {'complete':complete,'code':code,'operation':operation,'dangerous':any(f.get('rule')=='pickle.dangerous-global' for f in inspector.findings),'unknown':any(f.get('rule')=='pickle.unknown-global' for f in inspector.findings),'high':sum(f.get('severity') in {'high','critical'} for f in inspector.findings)}
    with tempfile.TemporaryDirectory(prefix='ascii-holdout-',dir='/tmp') as temp:
        d=Path(temp)
        def case(name,raw,expect,limits=LIMITS):
            nonlocal total
            total+=len(raw);need(total<=64<<10,'aggregate-fixture-bound');path=d/(name+'.pkl');path.write_bytes(raw)
            old=observe(B,path,limits);new=observe(C,path,limits)
            okay=new['code'] not in {'UNCLASSIFIED','UNEXPECTED_OPERATION'}
            if expect=='same':okay=okay and old==new
            elif expect=='clean':okay=okay and new['complete'] and new['high']==0
            elif expect=='reject':okay=okay and not new['complete']
            elif expect=='danger':okay=okay and new['complete'] and new['dangerous'] and new['high']>0
            record(name,okay,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),baseline=old,candidate=new);return old,new
        # These are separate controlled holdouts, not copies of the 26B author
        # original. No reducer or reference is ever loaded/invoked.
        ordered=b"S'collections'\nS'OrderedDict'\n\x93)R"
        case('ascii-global-offset-zero-benign',ordered+b'.','clean')
        old,new=case('ascii-global-p4-benign-map-write',b'\x80\x04'+ordered+b"S'key'\nK\x01s.",'clean')
        record('new-benign-allow-is-explicitly-observed',not old['complete'] and new['complete'] and new['high']==0)
        case('ascii-hex-escape-benign',b"S'collect\\x69ons'\nS'OrderedDict'\n\x93)R.",'clean')
        case('ascii-octal-escape-benign',b"S'collect\\151ons'\nS'OrderedDict'\n\x93)R.",'clean')
        case('memo-get-map-alias',ordered+b"q\x02h\x02S'x'\nK\x01s0.",'clean')
        case('memo-module-overwrite',b"S'os'\nq\x000S'collections'\nq\x00S'OrderedDict'\nq\x01\x93)R.",'clean')
        dup_stream=b"S'collections'\n2q\x000S'OrderedDict'\n\x93)R."
        old,new=case('dup-string-global-vendor-disagreement-kept',dup_stream,'reject')
        record('dup-pop-fullentry-keeps-vendor-agreement',new['code']=='pickle_symbol_analysis_disagreement')
        # Abstract literal/DUP correctness does not imply vendor agreement or
        # fullentry admission; keep those two claims separate.
        for cls in ['ContainerWriteTypes','SymbolicReferences']:
            tracker=getattr(C,cls)(64);matched=None
            for op,arg,pos in pickletools.genops(dup_stream):
                matched=tracker.apply(op,arg)
                if op.name=='STACK_GLOBAL':break
            okay=matched==('collections','OrderedDict') if cls=='SymbolicReferences' else type(tracker.stack[-1])is C._WriteGlobal and tracker.stack[-1].name==('collections','OrderedDict')
            record(cls+'-direct-dup-pop-literal-proof',okay)
        case('undefined-get',b"h\x08S'OrderedDict'\n\x93)R.",'same')
        case('nonascii-standalone-original-behavior',b"S'\\xe9'\n.",'same')
        case('nonascii-global-stays-unknown',b"S'\\xe9'\nS'system'\n\x93.",'same')
        case('malformed-string-quote',b"S'unclosed\n.",'same')
        case('unknown-escape-standalone',b"S'\\q'\n.",'same')
        case('cross-stream-undefined-new-memo',b"S'collections'\nq\x00.h\x00S'OrderedDict'\n\x93)R.",'same')
        case('opaque-reducer-not-map',b"cbuiltins\nlist\n)RS'x'\nK\x01s.",'same')
        case('nonempty-ordereddict-args-stays-unknown',b"S'collections'\nS'OrderedDict'\n\x93K\x01\x85RS'x'\nK\x01s.",'reject')
        case('fake-ordereddict-module',b"S'not_collections'\nS'OrderedDict'\n\x93)RS'x'\nK\x01s.",'reject')
        case('late-build-does-not-upgrade-unknown',b"cbuiltins\nlist\n)R}bS'x'\nK\x01s.",'same')
        case('primitive-is-not-map',b"S'plain'\nS'x'\nK\x01s.",'same')
        case('dangerous-ascii-offset-zero',b"S'os'\nS'system'\n\x93.",'danger')
        old,new=case('danger-prefix-truncated-tail',b"S'os'\nS'system'\n\x93X",'reject')
        record('danger-prefix-risk-retained-on-truncation',new['dangerous'] and new['high']>0)
        budget=dict(LIMITS,max_pickle_opcodes=2);case('existing-opcode-budget-kept',ordered+b'.','reject',budget)
        op=next(op for op in pickletools.opcodes if op.name=='STRING')
        for cls in ['ContainerWriteTypes','SymbolicReferences']:
            for label,arg in [('ascii','literal'),('nonascii','é'),('nonstring',b'literal')]:
                old=getattr(B,cls)(64);new=getattr(C,cls)(64);old.apply(op,arg);new.apply(op,arg)
                record(cls+'-guard-'+label,(new.stack[-1] is arg and type(new.stack[-1])is str) if label=='ascii' else (type(new.stack[-1])is object and type(old.stack[-1])is object))
            small=getattr(C,cls)(1);small.apply(op,'literal')
            put=next(x for x in pickletools.opcodes if x.name=='BINPUT')
            try:small.apply(put,0);okay=False
            except C.Incomplete as e:okay=e.args==('pickle_symbol_budget',)
            record(cls+'-original-slot-budget',okay)
    H.bounded_sha(a.baseline,BASE);H.bounded_sha(a.candidate,CANDIDATE)
    out={'schema':1,'scope':'ASCII_STRING_STATIC_COMPONENT_HOLDOUT_NOT_AV_ADOPTION_OR_CUSTOM_LOADER_SUPPORT','status':'PASS' if all(r['passed'] for r in rows) else 'FAIL','tests':len(rows),'passed':sum(r['passed'] for r in rows),'fixtureBytesGenerated':total,'baselineSHA256':BASE,'candidateSHA256':CANDIDATE,'original26ByteFullAV':'NOT_RUN_SEPARATE_ROOT_COHORT','original200and6and84':'NOT_RUN_SEPARATE_QUALIFICATION','modelLoaded':False,'AVRun':False,'records':rows}
    raw=json.dumps(out,sort_keys=True,ensure_ascii=False);need(len(raw.encode())<=128<<10,'bounded-output');print(raw);return 0 if out['status']=='PASS' else 2
def main():
    p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--baseline',type=Path);p.add_argument('--candidate',type=Path);p.add_argument('--deadline',type=int);p.add_argument('--root-idle-confirmed',action='store_true');a=p.parse_args()
    if not a.execute:print(json.dumps({'mode':'DESCRIBE','sourceOrArtifactInputsRead':False,'fixturesGenerated':0,'testsExecuted':0}));return 0
    need(a.baseline is not None and a.candidate is not None,'explicit-pinned-source-paths')
    H=load(Path(__file__).with_name('fixture_helpers.py'),HELPER,'ascii_fixed_guard');H.environment(a.deadline,a.root_idle_confirmed);return run(a,H)
if __name__=='__main__':
    try:raise SystemExit(main())
    except SystemExit:raise
    except Exception as e:print(json.dumps({'status':'REFUSED','exceptionType':type(e).__name__ if type(e).__name__ in {'ValueError','MemoryError','OSError'} else 'OTHER','accepted':False}));raise SystemExit(2)
