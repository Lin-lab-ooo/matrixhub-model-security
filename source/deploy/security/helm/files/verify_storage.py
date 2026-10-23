
import hashlib,json,os,signal,stat,sys,uuid
signal.alarm(15)
name=".matrixhub-posix-probe-"+uuid.uuid4().hex
if not name.startswith(".matrixhub-posix-probe-") or len(name)!=55: raise RuntimeError("invalid-probe-name")
payload=b"MatrixHub POSIX permission and stable descriptor probe.\n"
for root in ("/data","/input"):
 directory=os.stat(root,follow_symlinks=False)
 if not stat.S_ISDIR(directory.st_mode) or (directory.st_uid,directory.st_gid,stat.S_IMODE(directory.st_mode))!=(65532,65532,0o750): raise RuntimeError("directory-posix-contract")
 path=root+"/"+name; descriptor=None
 try:
  descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  if os.write(descriptor,payload)!=len(payload): raise RuntimeError("short-write")
  os.fsync(descriptor); os.fchmod(descriptor,0o440); os.fsync(descriptor)
  before=os.fstat(descriptor)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=(65532,65532,0o440): raise RuntimeError("file-posix-contract")
  os.lseek(descriptor,0,os.SEEK_SET)
  if hashlib.sha256(os.read(descriptor,1024)).digest()!=hashlib.sha256(payload).digest(): raise RuntimeError("probe-hash")
  after=os.fstat(descriptor)
  identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
  if identity(before)!=identity(after): raise RuntimeError("unstable-descriptor")
  os.close(descriptor); descriptor=None
  descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  if identity(os.fstat(descriptor))!=identity(before) or os.read(descriptor,1024)!=payload: raise RuntimeError("unstable-reopen")
 finally:
  if descriptor is not None: os.close(descriptor)
  if os.path.lexists(path): os.unlink(path)
print(json.dumps({"status":"posix-verified","directories":2}))
