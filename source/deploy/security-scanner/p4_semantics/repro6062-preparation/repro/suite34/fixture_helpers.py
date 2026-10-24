"""ROOT future Linux private-RAM static-format probe. Default DESCRIBE is zero-I/O.
No Docker/network command, Torch import, unpickler, external process or AV call.
Fixtures are built only after the full Linux/environment/source guard succeeds.
"""
import argparse,hashlib,importlib.util,io,json,os,re,shutil,stat,struct,sys,tempfile,time,zipfile
from pathlib import Path
MAX_FIXTURES=1<<20;MAX_OUTPUT=128<<10
LIMITS={'max_file_bytes':1<<20,'max_scan_bytes':1<<20,'max_expanded_bytes':1<<20,'max_members':64,'max_depth':3,'max_ratio':100,'max_pickle_opcodes':10000,'max_pickle_argument':8192}
SCOPE='Static component real-format comparison only; no AV, product admission, adoption or accuracy claim.'
CASES=('none','empty','neg','false','int','string','extra','conj','ordered-neg','state','pre-alias','post-neg','post-empty','second-use','hooks-late','hooks-state','shared-hook-metadata','noncpu','nonfloat','geometry','truncated','missing-storage','dangerous-ref','ext','int-key','zip-crc')
GAINS={'neg','post-empty'}
_CAP=None
def need(ok,code):
    if not ok:raise ValueError(code)
def bounded_sha(path,wanted):
    p=Path(path);need(p.is_file() and not p.is_symlink() and all(not q.is_symlink() for q in p.parents),'source-path')
    a=p.stat()
    with p.open('rb') as f:
        x=os.fstat(f.fileno());raw=f.read(512001);y=os.fstat(f.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(stat.S_ISREG(x.st_mode) and x.st_nlink==1 and 0<len(raw)<=512000 and stamp(a)==stamp(x)==stamp(y)==stamp(p.stat()) and hashlib.sha256(raw).hexdigest()==wanted,'source-sha-fstat');return raw
def environment(deadline,root_idle):
    global _CAP
    need(sys.platform=='linux' and os.geteuid()==os.getegid()==65532 and set(os.getgroups())<={65532},'linux-low-uid-required')
    need(root_idle is True and type(deadline)is int and 0<deadline-time.time()<=120,'fresh-root-idle-deadline')
    rows=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    def mount(name,required,filesystem=None):
        found=[x for x in rows if x[4]==name];need(len(found)==1 and required<=set(found[0][5].split(',')),'mount-controls')
        if filesystem:need(found[0][found[0].index('-')+1]==filesystem,'mount-filesystem')
    mount('/',{'ro'});mount('/tmp',{'rw','noexec','nosuid','nodev'},'tmpfs')
    for name in ('/probe','/baseline','/candidate'):mount(name,{'ro'})
    need(Path('/tmp').is_dir() and not Path('/tmp').is_symlink() and 2<<20<=os.statvfs('/tmp').f_blocks*os.statvfs('/tmp').f_frsize<=32<<20,'private-tmpfs-size')
    need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'network-none')
    for filename,index in (('/proc/net/route',1),('/proc/net/ipv6_route',0)):
        lines=Path(filename).read_text().splitlines();data=lines[1:] if filename.endswith('/route') else lines
        need(all(not x.split() or (x.split()[0] if filename.endswith('/route') else x.split()[-1])=='lo' for x in data),'no-nonloopback-routes')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(int(status['CapEff'].strip(),16)==0 and status['NoNewPrivs'].strip()=='1','capabilities-and-no-new-privileges')
    need(not any(Path('/dev').glob('nvidia*')) and not Path('/dev/dri').exists(),'no-gpu-devices')
    cg=Path('/sys/fs/cgroup');mem=(cg/'memory.max').read_text().strip();pids=(cg/'pids.max').read_text().strip();cpu=(cg/'cpu.max').read_text().split()
    need(mem.isdigit() and 64<<20<=int(mem)<=512<<20 and (cg/'memory.swap.max').read_text().strip()=='0' and (cg/'memory.swap.current').read_text().strip()=='0','memory-noswap')
    need(pids.isdigit() and 1<=int(pids)<=64 and cpu[0].isdigit() and 0<int(cpu[0])<=int(cpu[1]),'cpu-pids')
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_FIXTURES,MAX_FIXTURES));resource.setrlimit(resource.RLIMIT_CPU,(30,30));resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    _CAP=object();return _CAP
class Builder:
    def __init__(self,cap):
        need(cap is not None and cap is _CAP and sys.platform=='linux','fixture-capability-required')
        import pickle
        self.dumps=pickle.dumps
    def text(self,s):
        raw=s.encode('ascii');return b'X'+struct.pack('<I',len(raw))+raw
    def integer(self,n):return self.dumps(n,protocol=2)[2:-1]
    def global_ref(self,module,symbol):return b'c'+module.encode('ascii')+b'\n'+symbol.encode('ascii')+b'\n'
    def ordered(self):return self.global_ref('collections','OrderedDict')+b')R'
    def get(self,n):return b'h'+bytes([n])
    def put(self,n):return b'q'+bytes([n])
    def metadata(self,case):
        if case=='none':return b'N'
        raw=self.ordered() if case in ('ordered-neg','shared-hook-metadata') else b'}'
        if case in ('neg','post-neg','false','int','string','extra','conj','ordered-neg','noncpu','nonfloat'):
            key='conj' if case=='conj' else 'neg';value=b'\x89' if case=='false' else self.integer(1) if case=='int' else self.text('True') if case=='string' else b'\x88'
            raw+=self.text(key)+value+b's'
        if case=='int-key':raw+=self.integer(1)+b'\x88s'
        if case=='extra':raw+=self.text('other')+b'\x89s'
        if case=='state':raw+=b'}b'
        return raw+self.put(10)
    def tensor(self,case,zipformat=False,repeat=False):
        kind='IntStorage' if case=='nonfloat' else 'FloatStorage';location='cuda:0' if case=='noncpu' else 'cpu'
        pid=b'('+self.text('storage')+self.global_ref('torch',kind)+self.text('0')+self.text(location)+self.integer(1)+(b'tQ' if zipformat else b'NtQ')
        if case=='shared-hook-metadata':
            hooks=self.ordered()+self.put(10)+self.put(11)
        else:
            hooks=self.ordered()+(b'' if repeat else self.put(11))
        if repeat:meta=self.get(10)+self.text('wrong_second_consumption')+b'\x88s'
        elif case=='shared-hook-metadata':meta=self.get(10)
        else:
            meta=self.metadata(case)
            if case=='pre-alias':meta+=self.text('wrong_before_consumption')+b'\x88s'
        return self.global_ref('torch._utils','_rebuild_tensor_v2')+b'('+pid+self.integer(0)+self.integer(2 if case=='geometry' else 1)+b'\x85'+self.integer(1)+b'\x85\x89'+hooks+meta+b'tR'
    def root(self,case,zipformat=False):
        # No POP is used in any positive profile. Metadata is arg7 at REDUCE.
        initial=self.global_ref('os','system')+b'0' if case=='dangerous-ref' else b'\x82\x010' if case=='ext' else b''
        def parameter(value):return self.global_ref('torch._utils','_rebuild_parameter')+b'('+value+b'\x89'+self.ordered()+b'tR'
        data=self.tensor(case,zipformat);value=parameter(data) if zipformat else data
        pairs=self.text('weight')+value
        if case=='second-use':pairs+=self.text('second')+(parameter(self.tensor(case,True,True)) if zipformat else self.tensor(case,False,True))
        root=initial+self.ordered()+self.put(0)+b'('+pairs+b'u'
        if case in ('post-neg','post-empty','hooks-late','hooks-state','shared-hook-metadata'):
            # Reuse aliases through the existing root BUILD _metadata/version
            # closure, without discarding stack objects or adding VM opcodes.
            if case in ('post-neg','post-empty'):
                alias=self.get(10)+self.text('version')+self.integer(1)+b's'
                state=b'}'+self.text('_metadata')+b'}'+self.text('')+alias+b'ss'
            else:
                alias=self.get(11)
                if case=='hooks-state':alias+=b'}'+self.text('_metadata')+b'}sb'
                version=b'}'+self.text('version')+self.integer(1)+b's'
                state=b'}'+self.text('_metadata')+alias+self.text('')+version+b'ss'
            root+=state+b'b'
        return root+b'.'
    def build(self,family,case):
        need(sys.platform=='linux' and _CAP is not None,'linux-generation-required')
        if family=='zip-parameter-p2':
            data=b'\x80\x02'+self.root(case,True);stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as z:
                parts=[('archive/data.pkl',data),('archive/version',b'3\n')]
                if case!='missing-storage':parts.append(('archive/data/0',bytes(4)))
                for name,content in parts:
                    entry=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));entry.external_attr=0o100400<<16;z.writestr(entry,content)
            raw=stream.getvalue()
            if case=='zip-crc':
                with zipfile.ZipFile(io.BytesIO(raw)) as check:entry=check.getinfo('archive/data/0')
                offset=entry.header_offset+30+len(entry.filename.encode('utf-8'))+len(entry.extra);changed=bytearray(raw);changed[offset]^=1;raw=bytes(changed)
        else:
            protocol=2 if family=='legacy-p2' else 4;system={'protocol_version':1001,'little_endian':True,'type_sizes':{'short':2,'int':4,'long':8}}
            raw=self.dumps(0x1950A86A20F9469CFC6C,protocol=protocol)+self.dumps(1001,protocol=protocol)+self.dumps(system,protocol=protocol)+bytes([128,protocol])+self.root(case)+self.dumps(['0'],protocol=protocol)
            if case!='missing-storage':raw+=struct.pack('<q',1)+bytes(4)
        return raw[:-3] if case=='truncated' else raw
