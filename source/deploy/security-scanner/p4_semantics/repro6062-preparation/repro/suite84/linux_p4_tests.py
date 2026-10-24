"""ROOT-only Linux/private noexec RAM candidate tests. Default has no artifact I/O.
No Torch import, pickle load, author scanner, network, Docker or AV invocation.
"""
import argparse,hashlib,importlib.util,io,json,os,pickletools,struct,sys,tempfile,time,zipfile
from pathlib import Path
BASELINE_SHA='5fa1c563389f6b70ce16d9a7c3e60fc7c5a452ede2871a231b7e386147500c57'
HELPER_SHA='7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b'
ROOT_GAP_BUILDER_SHA='ecd23cf040ab294747df7b3d3df1c4802dbe8f4dfc76aacd5438f156eefec84e'
MAX_TOTAL=1<<20
LIMITS={'max_file_bytes':1<<20,'max_scan_bytes':1<<20,'max_expanded_bytes':1<<20,'max_members':64,'max_depth':3,'max_ratio':100,'max_pickle_opcodes':10000,'max_pickle_argument':8192}
def need(v,code):
    if not v:raise ValueError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path,wanted,name,H):
    raw=H.bounded_sha(path,wanted);spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
def outcome(m,path,limits):
    inspector=m.StaticInspector(dict(limits));code=None;operation=None
    try:
        with path.open('rb') as f:inspector.inspect(f,path.name)
        complete=True
    except m.Incomplete as e:
        complete=False;code=e.args[0] if len(e.args)==1 and e.args[0] in m.ERROR_CODES else 'UNCLASSIFIED_INCOMPLETE'
    except m.FORMAT_EXCEPTIONS as e:
        # Exact production-worker format tuple; not an arbitrary failure=deny.
        names={'ValueError','UnicodeError','UnicodeDecodeError','UnicodeEncodeError','EOFError','BadZipFile','TarError','ReadError','CompressionError','BadGzipFile','error'}
        operation=type(e).__name__ if type(e).__name__ in names else 'KNOWN_FORMAT_SUBCLASS_OTHER'
        complete=False;code='invalid_serialization'
    except Exception as e:
        complete=False;code='UNEXPECTED_OPERATION';operation='OTHER'
    high=sum(x.get('severity') in {'high','critical'} for x in inspector.findings)
    return {'complete':complete,'code':code,'operation':operation,'highCriticalFindings':high,'dangerousGlobalFound':any(x.get('rule')=='pickle.dangerous-global' for x in inspector.findings),'typedZIP':hasattr(inspector,'verified_framework_zip')}
def zip_bytes(raw,storage='default',extra=(),corrupt=False,key='0',metadata_name='data.pkl',mode=0o100400):
    if storage=='default':storage=bytes(4)
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_STORED) as z:
        parts=[('archive/'+metadata_name,raw),('archive/version',b'3\n')]
        if storage is not None:parts.append(('archive/data/'+key,storage))
        parts.extend(extra)
        for name,value in parts:
            entry=zipfile.ZipInfo(name,(1980,1,1,0,0,0));entry.external_attr=(0o040700 if name.endswith('/') else mode)<<16;z.writestr(entry,value)
    rawzip=output.getvalue()
    if corrupt:
        with zipfile.ZipFile(io.BytesIO(rawzip)) as z:e=z.getinfo('archive/data/'+key)
        at=e.header_offset+30+len(e.filename.encode())+len(e.extra);changed=bytearray(rawzip);changed[at]^=1;rawzip=bytes(changed)
    return rawzip
def run(a,H,cap):
    # Builders first emit explicit P2 memo keys. Python expression evaluation
    # order is not wire order, so no MEMOIZE index is assigned by a builder.
    class P4Builder(H.Builder):pass
    def modern_wire(body):
        raw=b'\x80\x02'+body;stream=io.BytesIO(raw)
        ops=list(pickletools.genops(stream))
        need(len(ops)<=10000 and stream.tell()==len(raw) and ops[-1][0].name=='STOP','wire-single-stop-eof')
        refs=B.SymbolicReferences(10000);mapping={};out=[]
        for i,(op,arg,pos) in enumerate(ops):
            end=ops[i+1][2] if i+1<len(ops) else len(raw)
            need(op.proto<=2,'wire-source-protocol2')
            if op.name=='PROTO':
                need(i==0 and arg==2,'wire-source-header');continue
            if op.name in refs.PUT_OPS:
                refs.require(1)
                need(type(arg)is int and arg>=0 and arg not in mapping,'fixture-memo-key')
                mapping[arg]=len(mapping);piece=b'\x94'
            elif op.name in refs.GET_OPS:
                need(type(arg)is int and arg in mapping,'fixture-memo-get-before-put')
                index=mapping[arg];piece=(b'h'+bytes([index])) if index<256 else b'j'+struct.pack('<I',index)
            elif op.name=='GLOBAL':
                module,symbol=arg.split(' ',1)
                def literal(value):
                    encoded=value.encode('ascii');need(0<len(encoded)<256,'wire-global-literal');return b'\x8c'+bytes([len(encoded)])+encoded
                piece=literal(module)+literal(symbol)+b'\x93'
            else:piece=raw[pos:end]
            # This bounded stack/memo observer rejects undefined references and
            # invalid marks. It is not an alias/effect or model-safety proof.
            refs.apply(op,arg);out.append(piece)
        need(not refs.stack and not refs.marks and set(refs.memo)==set(mapping),'wire-final-stack-memo')
        result=b''.join(out)
        # Check the transformed stack/memo in wire order, using the explicit
        # key bijection. OPAQUE values cannot prove semantic alias safety.
        modern=B.SymbolicReferences(10000)
        for op,arg,pos in pickletools.genops(b'\x80\x04'+result):modern.apply(op,arg)
        need(not modern.stack and not modern.marks and modern.globals==refs.globals and set(modern.memo)==set(mapping.values()),'wire-reference-shape')
        return result,mapping
    B=load(a.baseline,BASELINE_SHA,'p4_frozen_baseline',H);C=load(a.candidate,a.candidate_sha256,'p4_isolated_candidate',H)
    records=[];generated=0;wire_maps=[]
    def record(name,ok,**metadata):records.append({'id':name,'passed':bool(ok),**metadata})
    def p4(case='none',root='parameter-map',frame=True,modern=True):
        b=P4Builder(cap) if modern else H.Builder(cap)
        if root=='parameter-map':body=b.root(case,True)
        elif root=='tensor':body=b.tensor(case,True)+b'.'
        elif root in {'tensor-map','mixed-generic'}:
            body=b.ordered()+b'('+b.text('weight')+b.tensor(case,True)
            if root=='mixed-generic':body+=b.text('epoch')+b.integer(1)
            body+=b'u.'
        else:raise ValueError('fixture-root')
        if modern:
            body,mapping=modern_wire(body)
            if root=='parameter-map' and case=='post-empty':wire_maps.append(mapping)
        return b'\x80\x04'+(b'\x95'+struct.pack('<Q',len(body)) if frame else b'')+body
    def write(d,name,raw):
        nonlocal generated
        generated+=len(raw);need(generated<=MAX_TOTAL,'aggregate-fixture-budget');path=d/(name+'.pt');path.write_bytes(raw);return path
    with tempfile.TemporaryDirectory(prefix='p4-finite-',dir='/tmp') as temp:
        d=Path(temp)
        def compare(name,raw,limits=LIMITS,expect=None,code=None,typed=None):
            path=write(d,name,raw);old=outcome(B,path,limits);new=outcome(C,path,limits);ok=new['code'] not in {'UNCLASSIFIED_INCOMPLETE','UNEXPECTED_OPERATION'}
            if expect=='same':ok=ok and (old['complete'],old['code'],old['highCriticalFindings'])==(new['complete'],new['code'],new['highCriticalFindings'])
            elif expect=='clean':ok=ok and new['complete'] and not new['highCriticalFindings']
            elif expect=='deny':ok=ok and not new['complete'] and new['code'] in code
            if typed is not None:ok=ok and new['typedZIP'] is typed
            record(name,ok,fixtureBytes=len(raw),fixtureSHA256=sha(raw),baseline=old,candidate=new);return path,new
        G=load(Path(__file__).with_name('root_gap_builder.py'),ROOT_GAP_BUILDER_SHA,'p4_root_gap_builder',H)
        raw2=G.metadata('N01');need(raw2[:2]==b'\x80\x02','root-gap-prefix');raw4=b'\x80\x04'+raw2[2:]
        root_cases=[('match',4,'e18ed185148c95a647f12d808df8877717a44bbf9fdfca069ebf285eb7c0742a'),('short',3,'61cefe313cfe7a9eef22f4693f128f11edbfaa73cd9969c0c00d46608a8ca864'),('long',5,'3cb5bfe51190f475ac3203336da9c73426ce552231eeca0c58c5c569f26fdbe0')]
        for label,size,digest in root_cases:
            blob=zip_bytes(raw4,bytes(size),mode=0o100600);need(sha(blob)==digest,'root-gap-same-byte-sha')
            compare('root-observed-same-byte-'+label,blob,expect='same' if label=='match' else 'deny',code={'archive_member_size'},typed=False)
        record('classifier-pinned-actual-fact',C.p4_parameter_bridge_available())
        for label,raw in [('none',b'\x80\x04N.'),('list',b'\x80\x04](K\x01K\x02e.'),('dictionary',b'\x80\x04}\x8c\x01xK\x01s.'),('concat',b'\x80\x04N.\x80\x04N.'),('nonstrict-frame',b'\x80\x04\x95'+struct.pack('<Q',100)+b'N.')]:
            compare('unselected-'+label,zip_bytes(raw,None),expect='same',typed=False)
        compare('unselected-tensor-plus-primitive',zip_bytes(p4(root='mixed-generic')),expect='same',typed=False)
        # New deny-only cohort: CRCs are freshly valid in every small ZIP.
        # Normal and mismatch cases share identical metadata, only record size
        # changes. The independent width/key holdout is not the ROOT N01 trio.
        raw=p4(root='tensor-map')
        compare('deny-guard-float-match4',zip_bytes(raw,bytes(4)),expect='same',typed=False)
        compare('deny-guard-float-short3',zip_bytes(raw,bytes(3)),expect='deny',code={'archive_member_size'},typed=False)
        compare('deny-guard-float-long5',zip_bytes(raw,bytes(5)),expect='deny',code={'archive_member_size'},typed=False)
        compare('deny-guard-match-keeps-original-storage-crc-error',zip_bytes(raw,bytes(4),corrupt=True),expect='same',typed=False)
        compare('deny-guard-missing-record-unproven',zip_bytes(raw,None),expect='deny',code={'invalid_serialization'},typed=False)
        class HoldoutBuilder(P4Builder):
            def text(self,s):return super().text('7' if s=='0' else s)
            def global_ref(self,module,symbol):return super().global_ref(module,'DoubleStorage' if module=='torch' and symbol=='FloatStorage' else symbol)
        b=HoldoutBuilder(cap);body=b.ordered()+b'('+b.text('weight')+b.tensor('none',True)+b'u.';body,_=modern_wire(body);raw=b'\x80\x04\x95'+struct.pack('<Q',len(body))+body
        for label,size in [('match',8),('short',7),('long',9)]:
            compare('deny-guard-holdout-double-key7-'+label,zip_bytes(raw,bytes(size),key='7'),expect='same' if label=='match' else 'deny',code={'archive_member_size'},typed=False)
        class FreshBuilder(P4Builder):
            def __init__(self,token):super().__init__(token);self.next_memo=0;self.storage_key='0';self.storage_kind='FloatStorage'
            def put(self,n):
                # This helper creates two independent tensors and uses no GET.
                # Allocate unique explicit source keys; wire conversion alone
                # assigns MEMOIZE indices. Duplicate-key checks remain strict.
                key=100+self.next_memo;self.next_memo+=1;return super().put(key)
            def text(self,s):return super().text(self.storage_key if s=='0' else s)
            def global_ref(self,module,symbol):return super().global_ref(module,self.storage_kind if module=='torch' and symbol=='FloatStorage' else symbol)
        def two_tensors(distinct=False,conflict=False):
            b=FreshBuilder(cap);body=b.ordered()+b'('+b.text('one')+b.tensor('none',True)
            if distinct:b.storage_key='7'
            if distinct or conflict:b.storage_kind='DoubleStorage'
            body+=b.text('two')+b.tensor('none',True)+b'u.';body,_=modern_wire(body);return b'\x80\x04\x95'+struct.pack('<Q',len(body))+body
        compare('deny-guard-shared-key-valid',zip_bytes(two_tensors()),expect='same',typed=False)
        raw=two_tensors(True);compare('deny-guard-two-keys-valid',zip_bytes(raw,extra=[('archive/data/7',bytes(8))]),expect='same',typed=False)
        compare('deny-guard-second-key-mismatch',zip_bytes(raw,extra=[('archive/data/7',bytes(7))]),expect='deny',code={'archive_member_size'},typed=False)
        raw=two_tensors(conflict=True);path,_=compare('deny-guard-conflicting-pid-unproven',zip_bytes(raw),expect='same',typed=False)
        with path.open('rb') as f:record('conflicting-pid-has-no-deny-witness',C.observe_protocol4_storage_mismatch(f,LIMITS) is None)
        compare('deny-guard-cuda-unproven',zip_bytes(p4('noncpu',root='tensor-map')),expect='same',typed=False)
        b=P4Builder(cap);raw=b'\x80\x04'+modern_wire(b.global_ref('argparse','Namespace')+b'.')[0];compare('deny-guard-unknown-config-global',zip_bytes(raw,None),expect='same',typed=False)
        compare('deny-guard-fake-metadata-name',zip_bytes(p4(root='tensor-map'),metadata_name='not-data.pkl'),expect='same',typed=False)
        b=H.Builder(cap);body=b.ordered()+b'('+b.text('weight')+b.tensor('none',True)+b'u.';raw=b'\x80\x02'+body
        for label,size in [('match',4),('short',3),('long',5)]:compare('deny-guard-p2-unchanged-'+label,zip_bytes(raw,bytes(size)),expect='same')
        for root in ['parameter-map','tensor','tensor-map']:
            raw=p4(root=root);limits=dict(LIMITS)
            if root!='parameter-map':limits['max_expanded_bytes']=len(raw)+3
            compare('selected-'+root,zip_bytes(raw),limits,expect='clean',typed=True)
        for modern in [False,True]:
            raw=p4(modern=modern);compare('p4-opcode-family-'+str(modern),zip_bytes(raw),expect='clean',typed=True)
        for case in ['empty','neg','post-empty']:
            compare('metadata-valid-'+case,zip_bytes(p4(case)),expect='clean',typed=True)
        record('wire-post-empty-root-hooks-metadata-memo-order',wire_maps==[{0:0,11:1,10:2}],expectedRootMemo=0,expectedHooksMemo=1,expectedMetadataMemo=2)
        for case in ['false','int','string','extra','conj','ordered-neg','state','pre-alias','second-use','hooks-late','hooks-state','shared-hook-metadata','noncpu','nonfloat','int-key']:
            compare('metadata-or-alias-invalid-'+case,zip_bytes(p4(case)),expect='deny',code={'unsupported_container_or_serialization','invalid_serialization'})
        compare('geometry-oob',zip_bytes(p4('geometry')),expect='deny',code={'archive_member_size'})
        raw=p4('geometry',root='tensor');limit=dict(LIMITS,max_expanded_bytes=len(raw)+3)
        compare('bridge-b-ordinary-tensor-geometry-oob',zip_bytes(raw),limit,expect='deny',code={'archive_member_size'})
        compare('storage-missing',zip_bytes(p4(),None),expect='deny',code={'invalid_serialization'})
        compare('storage-extra',zip_bytes(p4(),extra=[('archive/data/1',bytes(4))]),expect='deny',code={'invalid_serialization'})
        compare('storage-short',zip_bytes(p4(),bytes(3)),expect='deny',code={'archive_member_size'})
        compare('storage-crc',zip_bytes(p4(),corrupt=True),expect='deny',code={'invalid_serialization'})
        raw=p4();body=raw[11:]
        # Exhaustion exactly before STOP is legal in CPython's _Unframer:
        # the next complete opcode can be read outside the completed frame.
        compare('selected-frame-stop-outside-valid',zip_bytes(b'\x80\x04\x95'+struct.pack('<Q',len(body)-1)+body),expect='clean',typed=True)
        parsed=list(pickletools.genops(b'\x80\x04'+body))
        split=None
        for i,(op,arg,pos) in enumerate(parsed[:-1]):
            after=parsed[i+1][2]
            if op.name=='SHORT_BINUNICODE' and type(arg)is str and len(arg.encode('ascii'))>=2:
                split=pos+3-2;need(pos+2<split+2<after,'frame-cut-splits-string-content');break
        need(split is not None,'frame-cut-target-exists')
        for name,broken in [('split-opcode',b'\x80\x04\x95'+struct.pack('<Q',split)+body),('long-frame',b'\x80\x04\x95'+struct.pack('<Q',len(body)+1)+body),('extra-stream',raw+b'\x80\x04N.'),('trailing',raw+b'X')]:
            _,observed=compare('selected-frame-'+name,zip_bytes(broken),expect='deny',code={'invalid_serialization','unsupported_container_or_serialization'})
            if name=='trailing':record('trailing-has-fixed-known-format-operation',observed['operation'] not in {None,'OTHER'} and observed['code']=='invalid_serialization',candidate=observed)
        # Known dangerous import only: no invocation or dangerous argument.
        b=P4Builder(cap);danger=b'\x80\x04'+modern_wire(b.global_ref('os','system')+b'.')[0];path=write(d,'dangerous-reference',zip_bytes(danger,None));result=outcome(C,path,LIMITS);record('dangerous-reference-rule',result['dangerousGlobalFound'] and result['highCriticalFindings']>0,candidate=result)
        b=P4Builder(cap);body=b'\x8c\x02os\x8c\x06system\x93'+b'0'+p4(root='tensor-map')[11:];raw=b'\x80\x04\x95'+struct.pack('<Q',len(body))+body
        path,result=compare('deny-guard-unknown-danger-keeps-old-risk',zip_bytes(raw,bytes(3)),expect='same',typed=False)
        record('deny-guard-dangerous-reference-retained',result['dangerousGlobalFound'])
        b=H.Builder(cap);p2=b'\x80\x02'+b.root('none',True);compare('frozen-p2-parameter',zip_bytes(p2),expect='same',typed=True)
        oldcap=C._P4_SELECTOR_BYTES
        try:
            C._P4_SELECTOR_BYTES=32;path=write(d,'optional-budget-fallback',zip_bytes(p4()))
            with path.open('rb') as f:selection=C.selects_protocol4_bridge(f,LIMITS,LIMITS['max_expanded_bytes'])
            record('optional-selector-cap-not-selected',selection==C._P4_NOT_SELECTED)
            compare('optional-cap-keeps-old-generic',path.read_bytes(),expect='same',typed=False)
            compare('optional-deny-cap-keeps-old-generic',zip_bytes(p4(root='tensor-map'),bytes(3)),expect='same',typed=False)
        finally:C._P4_SELECTOR_BYTES=oldcap
        path=write(d,'denial-observer-interruption-control',zip_bytes(p4(root='tensor-map')))
        original_parse=C._P4ZipMachine.parse
        try:
            for name,kind in [('memory',MemoryError),('io',OSError),('interrupt',KeyboardInterrupt),('exit',SystemExit),('deadline',TimeoutError)]:
                def interrupt(self,raw,exception=kind):raise exception()
                C._P4ZipMachine.parse=interrupt
                try:
                    with path.open('rb') as f:C.observe_protocol4_storage_mismatch(f,LIMITS)
                    ok=False
                except kind:ok=True
                record('deny-guard-does-not-swallow-'+name,ok)
        finally:C._P4ZipMachine.parse=original_parse
        raw=p4();context=C._ZipP4Context(raw,2,'archive/data.pkl',LIMITS,C._ZIP_PARAMETER_SEAL);stream=io.BytesIO(raw);context.stream=stream
        for name,args in [('clone',(io.BytesIO(raw),context.chain,LIMITS)),('chain',(stream,((0,'wrong'),),LIMITS)),('limits',(stream,context.chain,dict(LIMITS,max_members=63)))]:
            try:context.prove(*args);ok=False
            except C.LegacyTorchError:ok=True
            record('context-'+name,ok)
        context.prove(stream,context.chain,LIMITS);machine=context.machine
        try:context.prove(stream,context.chain,LIMITS);ok=False
        except C.LegacyTorchError:ok=context.machine is machine
        record('context-once-no-second-vm',ok)
        context=C._ZipP4Context(raw,2,'archive/data.pkl',LIMITS,C._ZIP_PARAMETER_SEAL);stream=io.BytesIO(raw);context.stream=stream;stream.seek(len(raw)-1);stream.write(b'N')
        try:context.prove(stream,context.chain,LIMITS);ok=False
        except C.LegacyTorchError:ok=True
        record('context-mutated-buffer',ok)
        # A Parameter bridge is already established; an extra primitive root
        # value is outside this selected finite contract, never a new allowlist.
        b=P4Builder(cap);body=p4()[11:-1]+b.text('epoch')+b.integer(1)+b's.';mixed=b'\x80\x04\x95'+struct.pack('<Q',len(body))+body
        compare('selected-parameter-map-extra-primitive',zip_bytes(mixed),expect='deny',code={'unsupported_container_or_serialization'})
        # B lower bound excludes directory bodies that old generic never reads.
        raw=b'\x80\x04N.';path=write(d,'directory-not-charged',zip_bytes(raw,None,[('archive/unused/',bytes(1024))]));limit=dict(LIMITS,max_expanded_bytes=128)
        with path.open('rb') as f:selection=C.selects_protocol4_bridge(f,limit,128)
        record('selector-directory-not-charged',selection==C._P4_NOT_SELECTED)
    H.bounded_sha(a.baseline,BASELINE_SHA);H.bounded_sha(a.candidate,a.candidate_sha256)
    result={'schema':1,'scope':'STATIC_COMPONENT_CANDIDATE_TESTS_ONLY_NOT_AV_PRODUCT_OR_ADOPTION','status':'PASS' if all(r['passed'] for r in records) else 'FAIL','tests':len(records),'passed':sum(r['passed'] for r in records),'fixtureBytesGenerated':generated,'candidateSHA256':a.candidate_sha256,'baselineSHA256':BASELINE_SHA,'modelDeserialized':False,'AVRun':False,'records':records}
    encoded=json.dumps(result,ensure_ascii=False,sort_keys=True);need(len(encoded.encode())<=128<<10,'bounded-output');print(encoded);return 0 if result['status']=='PASS' else 2
def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--baseline',type=Path);p.add_argument('--candidate',type=Path);p.add_argument('--candidate-sha256');p.add_argument('--deadline',type=int);p.add_argument('--root-idle-confirmed',action='store_true');a=p.parse_args(argv)
    if not a.execute:print(json.dumps({'mode':'DESCRIBE','artifactInputsRead':False,'fixturesGenerated':0,'testsExecuted':0}));return 0
    need(a.baseline is not None and a.candidate is not None and a.candidate_sha256 is not None,'explicit-source-inputs')
    # Import only the fixed own guard/builder helper. No fixture exists until
    # its complete Linux/noexec/network/cgroup/source checks succeed.
    path=Path(__file__).with_name('fixture_helpers.py');need(not path.is_symlink() and path.is_file() and path.stat().st_size<=64<<10,'fixed-own-helper')
    with path.open('rb') as f:helper=f.read((64<<10)+1)
    need(sha(helper)==HELPER_SHA,'fixed-helper-sha');spec=importlib.util.spec_from_file_location('p4_fixture_guard',path);H=importlib.util.module_from_spec(spec);exec(compile(helper,str(path),'exec'),H.__dict__)
    cap=H.environment(a.deadline,a.root_idle_confirmed);H.bounded_sha(a.baseline,BASELINE_SHA);H.bounded_sha(a.candidate,a.candidate_sha256);return run(a,H,cap)
if __name__=='__main__':
    try:raise SystemExit(main())
    except SystemExit:raise
    except Exception as e:print(json.dumps({'status':'REFUSED','errorType':type(e).__name__,'fixturesExecutedSuccessfully':False}));raise SystemExit(2)
