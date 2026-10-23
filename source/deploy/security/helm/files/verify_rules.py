
import hashlib,json,os,subprocess,time,signal
signal.alarm(300)
from pathlib import Path
root=Path("/rules")
def call(args):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=240)
 if p.returncode: raise RuntimeError("verification-tool-failed")
 return p.stdout
version=call(["/usr/local/bin/sigtool","--version"]).decode().strip()
if not version.startswith("ClamAV 1.4.6/") and version!="ClamAV 1.4.6": raise RuntimeError("wrong-engine-version")
metadata=json.loads(Path("/provenance/rules.json").read_text())
expected={entry["name"]:entry for entry in metadata["files"]}
if set(expected)!={"main.cvd","daily.cvd","bytecode.cvd"} or len(metadata["files"])!=3: raise RuntimeError("incomplete-manifest")
if set(p.name for p in root.iterdir())!=set(expected): raise RuntimeError("unexpected-rule-inventory")
for name,item in expected.items():
 file=root/name
 if file.is_symlink() or not file.is_file(): raise RuntimeError("unsafe-rule-file")
 with file.open("rb") as stream: actual=hashlib.file_digest(stream,"sha256").hexdigest()
 if file.stat().st_size!=item["size"] or actual!=item["sha256"]: raise RuntimeError("rules-digest-mismatch")
records=[]
for name in ("main.cvd","daily.cvd","bytecode.cvd"):
 output=call(["/usr/local/bin/sigtool","--info",str(root/name)])
 if b"Verification OK." not in output: raise RuntimeError("signature-verification-missing")
 with (root/name).open("rb") as f: fields=f.read(512).decode("ascii").rstrip(" \x00\r\n").split(":")
 if len(fields)<9 or fields[0]!="ClamAV-VDB": raise RuntimeError("invalid-cvd-header")
 records.append({"name":name,"version":int(fields[2]),"buildEpoch":int(fields[8]),"signatureVerified":True,"verificationOutputSha256":hashlib.sha256(output).hexdigest()})
probe=Path("/tmp/engine-probe.txt"); probe.write_bytes(b"MatrixHub rule initialization probe.\n")
call(["/usr/local/bin/clamscan","--database=/rules","--no-summary",str(probe)])
now=int(time.time())
for entry in records:
 item=expected[entry["name"]]
 if entry["version"]!=item["version"] or entry["buildEpoch"]!=item["buildEpoch"] or not 0<entry["buildEpoch"]<=now: raise RuntimeError("rules-metadata-mismatch")
max_age=metadata["maxAgeSeconds"]
if not 0<max_age<=604800 or metadata["expiresAt"]!=expected["daily.cvd"]["buildEpoch"]+max_age or now>=metadata["expiresAt"]: raise RuntimeError("rules-expired")
print(json.dumps({"engine":version,"engineLoadVerified":True,"files":records}))
