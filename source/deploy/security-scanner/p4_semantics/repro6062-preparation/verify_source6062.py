"""Metadata-only preparation/source identity verifier. No source execution."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).parent
SOURCE_SHA='6062a3f95ab822be816d6e84aa3cc32934490b60d85242f19162e2160b6f7bb3'
SOURCE_BYTES=205944
def need(ok,code):
    if not ok:raise ValueError(code)
def stamp(v):return[v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns]
def held(path):
    p=Path(path)
    need(p.is_absolute()and p.name=='scanner.py','absolute-plain-scanner-path')
    for part in(p,*p.parents):
        v=part.lstat();need(not stat.S_ISLNK(v.st_mode)and not getattr(v,'st_file_attributes',0)&0x400,'reparse-refused')
    before=p.stat()
    with p.open('rb')as f:
        first=os.fstat(f.fileno());raw=f.read(512001);last=os.fstat(f.fileno())
    final=p.stat()
    need(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and stamp(before)==stamp(final)and stamp(first)==stamp(last)
         and stamp(before)[:4]==stamp(first)[:4]and(sys.platform=='win32'or before.st_ctime_ns==first.st_ctime_ns),'source-held-fstat')
    need(len(raw)==SOURCE_BYTES and hashlib.sha256(raw).hexdigest()==SOURCE_SHA,'source-full-sha')
    return{'path':str(p.resolve()),'bytes':len(raw),'sha256':SOURCE_SHA,'identity':stamp(before),'heldFstat':stamp(first),
           'pathAndHeldCTimeCompared':sys.platform!='win32','WindowsFstatCTimeMayBeUnavailable':sys.platform=='win32'}
def verify_source(source,snapshot=None,previous=None):
    p=Path(source)
    need(not p.resolve(strict=True).is_relative_to(HERE.resolve()),'package-copy-is-not-installed-source')
    original=held(p);copy=None
    if snapshot is not None:
        q=Path(snapshot);copy=held(q)
        need(q.resolve()!=p.resolve()and not q.resolve().is_relative_to(HERE.resolve()),'snapshot-must-be-external-and-distinct')
        need({x.name for x in q.parent.iterdir()}=={'scanner.py'},'snapshot-directory-not-single-code-file')
    need(held(p)==original,'source-changed-during-binding')
    if previous is not None:
        path=Path(previous);raw=path.read_bytes();need(len(raw)<=16384,'previous-binding-budget');old=json.loads(raw)
        need(type(old)is dict and old.get('scope')=='INSTALLED_SOURCE_VERIFIED_SNAPSHOT_METADATA_ONLY'and old.get('status')=='VERIFIED','previous-binding-shape')
        need(old.get('source')==original and(old.get('snapshot')is None or old.get('snapshot')==copy),'source-or-snapshot-changed-since-binding')
    return{'schema':1,'status':'VERIFIED','scope':'INSTALLED_SOURCE_VERIFIED_SNAPSHOT_METADATA_ONLY','source':original,'snapshot':copy,
           'installationConfirmedByROOT':True,'adoptionEstablishedByVerifier':False,'sourceExecuted':False,'DockerExecuted':False,'modelBytesRead':0}
def verify_package():
    raw=(HERE/'allowlist.json').read_bytes();need(len(raw)<=65536,'allowlist-budget');m=json.loads(raw)
    need(m.get('schema')==1 and type(m.get('files'))is list,'allowlist-shape')
    names=[]
    for row in m['files']:
        name=row['path'];need(type(name)is str and name not in names and not Path(name).is_absolute()and '..'not in Path(name).parts,'allowlist-path');names.append(name)
        p=HERE/name;need(p.is_file()and not p.is_symlink(),'allowlist-file');data=p.read_bytes()
        need(len(data)==row['bytes']and hashlib.sha256(data).hexdigest()==row['sha256'],'allowlist-file-sha')
    entries=list(HERE.rglob('*'));need(all(not p.is_symlink()and not getattr(p.lstat(),'st_file_attributes',0)&0x400 for p in entries),'allowlist-reparse-refused')
    actual={p.relative_to(HERE).as_posix()for p in entries if p.is_file()}
    need(actual==set(names)|{'allowlist.json'},'allowlist-exact-tree')
    return{'schema':1,'status':'VERIFIED','scope':'SOURCE_ONLY_ALLOWLIST_NOT_TEST_EXECUTION','files':len(names),'sourceSHA256':SOURCE_SHA,'sourceExecuted':False,'DockerExecuted':False}
def main(argv=None):
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group();g.add_argument('--verify-package',action='store_true');g.add_argument('--verify-source',action='store_true')
    p.add_argument('--source');p.add_argument('--snapshot');p.add_argument('--previous-binding');p.add_argument('--installed-source-confirmed',action='store_true');a=p.parse_args(argv)
    if not(a.verify_package or a.verify_source):
        print(json.dumps({'mode':'DESCRIBE','sourceSHA256':SOURCE_SHA,'sourceBytes':SOURCE_BYTES,'sourceFilesRead':0,'sourceExecuted':False,'DockerExecuted':False}));return 0
    if a.verify_package:out=verify_package()
    else:
        need(a.installed_source_confirmed and type(a.source)is str,'explicit-installed-source-confirmation-required')
        out=verify_source(a.source,a.snapshot,a.previous_binding)
    print(json.dumps(out,sort_keys=True));return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except ValueError as e:print(json.dumps({'status':'REFUSED','code':e.args[0],'sourceExecuted':False,'DockerExecuted':False}));raise SystemExit(2)
