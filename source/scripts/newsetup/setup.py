#!/usr/bin/env python3
"""Preflight and start one isolated MatrixHub security deployment; never downloads images."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

from rules_snapshot import SetupError, atomic_json, atomic_text, digest, image_id, ordinary, require, run, verify_active, prepare, bounded, temporary_container
from admin_setup import initialize_account, verify_account

SOURCE = Path(__file__).resolve().parents[2]
COMPOSE = SOURCE / "deploy" / "security" / "compose.yaml"
PROBE_SCRIPT = r'''
import http.client,json,os,socket,stat,signal
signal.alarm(20)
p="/run/matrix-security/scanner.sock"
s=os.stat(p)
if not stat.S_ISSOCK(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o660 or s.st_uid!=65532 or s.st_gid!=65532: raise RuntimeError("unsafe-scanner-socket")
c=http.client.HTTPConnection("localhost",timeout=10)
c.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.sock.settimeout(10); c.sock.connect(p)
c.request("GET","/v1/bundle"); r=c.getresponse(); data=json.loads(r.read(1048576)); c.close()
if r.status!=200 or not data.get("generation"): raise RuntimeError("scanner-unhealthy")
print(json.dumps({"generation":data["generation"],"maxFileBytes":data["maxFileBytes"],"maxBatchFiles":data["maxBatchFiles"],"maxBatchBytes":data["maxBatchBytes"]}))
'''


def command(args, timeout=180):
    return run(args, timeout)


def positive_resource_limit(value, *, memory=False):
    """Compose JSON may preserve Docker's binary-unit strings, such as '4g'."""
    if type(value) is int:
        result = value
    elif type(value) is str:
        match = re.fullmatch(r"([1-9][0-9]{0,18})([kKmMgGtT]?)", value)
        require(match is not None, "runtime-resource-limit-invalid")
        suffix = match[2].lower()
        require(memory or not suffix, "runtime-resource-limit-invalid")
        result = int(match[1]) << {"": 0, "k": 10, "m": 20, "g": 30, "t": 40}[suffix]
    else:
        raise SetupError("runtime-resource-limit-invalid")
    require(0 < result <= (1 << 63) - 1, "runtime-resource-limit-invalid")
    return result


def validate_plan(plan, owned_bindings=None):
    """Check effective Compose values, including overrides and interpolation."""
    services = plan["services"]
    require(set(services) == {"init-volumes", "scanner", "matrixhub"}, "unexpected-services")
    for name in ("scanner", "matrixhub"):
        service = services[name]
        require(str(service.get("user")) == "65532:65532", "runtime-user-must-be-65532")
        require(service.get("read_only") is True, "runtime-rootfs-must-be-readonly")
        require(set(service.get("cap_drop", [])) == {"ALL"} and not service.get("cap_add"), "runtime-capabilities")
        require(not service.get("privileged"), "privileged-not-permitted")
        require("no-new-privileges:true" in service.get("security_opt", []), "no-new-privileges-required")
        positive_resource_limit(service.get("pids_limit", 0))
        positive_resource_limit(service.get("mem_limit", 0), memory=True)
    scanner = services["scanner"]
    require(scanner.get("network_mode") == "none" and not scanner.get("ports"), "scanner-network-must-be-none")
    require(int(scanner["environment"].get("SCAN_RULES_EXPIRES_AT", 0)) > int(time.time()), "scanner-rules-expiry-required")
    mounts = {name: {x["target"]: x for x in services[name].get("volumes", [])} for name in services}
    require(mounts["scanner"]["/rules"].get("read_only") is True, "rules-must-be-readonly")
    require(mounts["scanner"]["/input"].get("read_only") is True, "scanner-staging-must-be-readonly")
    require(not mounts["matrixhub"]["/input"].get("read_only", False), "api-staging-must-be-writable")
    require(mounts["matrixhub"]["/run/matrix-security"].get("read_only") is True, "api-socket-directory-must-be-readonly")
    for port in services["matrixhub"].get("ports", []):
        require(port.get("host_ip") == "127.0.0.1", "ports-must-bind-loopback")
    init = services["init-volumes"]
    require(str(init.get("user")) == "0:0" and init.get("network_mode") == "none" and init.get("read_only"), "unsafe-init")
    require(set(init.get("cap_drop", [])) == {"ALL"} and set(init.get("cap_add", [])) == {"CHOWN", "FOWNER"}, "init-capabilities")
    require(not init.get("privileged"), "privileged-init-not-permitted")
    for mount in init.get("volumes", []):
        if mount["type"] == "bind":
            require(owned_bindings is not None and owned_bindings.get(mount["target"]) == mount["source"], "init-must-touch-only-owned-volumes")
        else:
            require(mount["type"] == "volume", "init-must-touch-only-owned-volumes")
    require(len(plan.get("volumes", {})) == 3, "one-staging-owner-required")
    return True


def ownership(project, owner):
    container_ids = command(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"]).decode().split()
    volume_ids = command(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"]).decode().split()
    for kind, identifiers in (("container", container_ids), ("volume", volume_ids)):
        for identifier in identifiers:
            template = "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"
            labels = json.loads(command(["docker", kind, "inspect", "--format", template, identifier]))
            require(labels.get("matrixhub.security.owner") == owner, "project-owned-by-another-deployment")


def memory_budget():
    value = json.loads(command(["docker", "info", "--format", '{"NCPU":{{.NCPU}},"MemTotal":{{.MemTotal}},"OSType":{{json .OSType}}}']))
    require(value.get("OSType") == "linux", "linux-container-engine-required")
    require(value.get("NCPU", 0) >= 2, "docker-cpu-budget-too-small")
    require(value.get("MemTotal", 0) >= 8 * 1024**3, "docker-memory-budget-below-8GiB")
    return {"dockerCpus": value["NCPU"], "dockerMemoryBytes": value["MemTotal"]}


def state_for(args):
    require(re.fullmatch(r"mh-sec-[a-z0-9][a-z0-9-]{0,40}", args.project) is not None, "project-must-start-with-mh-sec")
    state = args.state.absolute()
    if state.exists():
        ordinary(state, directory=True)
    else:
        state.mkdir(parents=True)
    marker = state / "deployment.json"
    if marker.exists():
        ordinary(marker)
        value = json.loads(marker.read_text(encoding="utf-8"))
        require(value.get("schema") == "matrixhub.security-deployment/v1" and value.get("project") == args.project and re.fullmatch(r"[0-9a-f]{32}", value.get("owner", "")), "deployment-identity-mismatch")
    else:
        require(not any(state.iterdir()), "new-state-directory-must-be-empty")
        value = {"schema": "matrixhub.security-deployment/v1", "project": args.project, "owner": uuid.uuid4().hex}
        ownership(args.project, value["owner"])
        atomic_json(marker, value)
    ownership(args.project, value["owner"])
    return state, value


POSIX_PROBE_SCRIPT = r'''
import hashlib,json,os,signal,stat,sys
signal.alarm(15)
name=sys.argv[1]
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
'''


def verify_posix_bindings(bindings, image):
    mounts = ["--mount", f"type=bind,src={bindings['/data']},dst=/data",
              "--mount", f"type=bind,src={bindings['/input']},dst=/input"]
    try:
        temporary_container(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                             "--user=0:0", "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=FOWNER",
                             "--security-opt=no-new-privileges:true", *mounts, "--entrypoint=/bin/sh", image,
                             "-ec", "chown 65532:65532 /data /input && chmod 0750 /data /input"], timeout=30)
        name = ".matrixhub-posix-probe-" + uuid.uuid4().hex
        output = temporary_container(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                                      "--user=65532:65532", "--cap-drop=ALL", "--pids-limit=16", "--memory=128m",
                                      "--security-opt=no-new-privileges:true", *mounts, "--entrypoint=python", image,
                                      "-I", "-c", POSIX_PROBE_SCRIPT, name], timeout=30)
        require(json.loads(output) == {"status": "posix-verified", "directories": 2}, "posix-probe-result-invalid")
    except (SetupError, ValueError) as error:
        raise SetupError("posix-permissions-or-stable-fd-unavailable-use-linux-ext4") from error


def owned_directory(path, owner):
    require(path is not None and path.is_absolute(), "absolute-owned-bind-directory-required")
    path.mkdir(parents=True, exist_ok=True)
    path = ordinary(path, directory=True)
    marker = path / ".matrixhub-security-owner.json"
    if marker.exists():
        require(json.loads(ordinary(marker).read_text())["owner"] == owner, "bind-directory-owned-by-another-deployment")
    else:
        require(not any(path.iterdir()), "new-bind-directory-must-be-empty")
        atomic_json(marker, {"owner": owner})
    return str(path)


def apply_security_profile(config, values):
    header, security = config.split("security:\n", 1)
    for key, value in values.items():
        replacement = f"  {key}: {value}"
        if re.search(r"^  " + re.escape(key) + r":.*$", security, re.MULTILINE):
            security = re.sub(r"^  " + re.escape(key) + r":.*$", replacement, security, flags=re.MULTILINE)
        else:
            security += replacement + "\n"
    return header + "security:\n" + security


def render(args, state, marker, rules, manifest, app_image, scanner_image):
    config = (SOURCE / "deploy" / "security" / "config.yaml").read_text(encoding="utf-8")
    # Default remains one API and one staging owner. Internal scanner parallelism
    # is bounded independently; it is not a claim that replicas can share staging.
    config = config.replace("concurrency: 1", f"concurrency: {args.concurrency}")
    profile = None
    bindings = None
    if args.profile == "large-repository":
        profile = json.loads((SOURCE / "deploy/security/profiles/large-repository.json").read_text())
        config = apply_security_profile(config, profile["apiSecurity"])
        data = owned_directory(args.data_dir, marker["owner"])
        staging = owned_directory(args.staging_dir, marker["owner"])
        require(Path(data) != Path(staging) and Path(data) not in Path(staging).parents and Path(staging) not in Path(data).parents, "data-staging-overlap")
        require(state not in Path(data).parents and state not in Path(staging).parents and Path(data) not in state.parents and Path(staging) not in state.parents and state not in (Path(data), Path(staging)), "deployment-state-bind-overlap")
        # Conservative: require the complete two-copy+reserve budget on each
        # storage filesystem. Shared-filesystem space is never counted twice.
        for directory in (data, staging):
            require(shutil.disk_usage(directory).free >= profile["minimumFreeDiskBytes"], "large-profile-needs-220GiB-copies-plus-70GiB-reserve")
        bindings = {"/data": data, "/input": staging}
    config = config.replace("http://127.0.0.1:3002", f"http://127.0.0.1:{args.http_port}")
    config_path = state / "config.yaml"
    atomic_text(config_path, config)
    override = {"services": {}, "volumes": {}}
    labels = {"matrixhub.security.owner": marker["owner"]}
    for name in ("init-volumes", "scanner", "matrixhub"):
        override["services"][name] = {"labels": labels}
    override["services"]["scanner"]["image"] = scanner_image
    override["services"]["scanner"]["cpus"] = args.native_threads
    if profile:
        override["services"]["scanner"].update(mem_limit=profile["scannerMemoryBytes"], memswap_limit=profile["scannerMemoryBytes"])
    override["services"]["scanner"]["environment"] = {
        "SCAN_RULES_EXPIRES_AT": str(manifest["expiresAt"]),
        "SCAN_NATIVE_THREADS": str(args.native_threads),
        "SCAN_CLAMAV_BACKEND": "clamd",
    }
    if profile:
        override["services"]["scanner"]["environment"].update(profile["scannerEnvironment"])
    override["services"]["matrixhub"]["labels"] = dict(labels, **{"matrixhub.security.config-sha": digest(config_path)})
    override["services"]["matrixhub"]["image"] = app_image
    override["services"]["init-volumes"]["image"] = app_image
    override["services"]["matrixhub"]["volumes"] = [{"type": "bind", "source": str(config_path), "target": "/etc/matrixhub/config.yaml", "read_only": True}]
    if bindings:
        data_mount = {"type": "bind", "source": bindings["/data"], "target": "/data"}
        input_mount = {"type": "bind", "source": bindings["/input"], "target": "/input"}
        override["services"]["init-volumes"]["volumes"] = [data_mount, input_mount]
        override["services"]["matrixhub"]["volumes"].extend([data_mount, input_mount])
        override["services"]["scanner"]["volumes"] = [dict(input_mount, read_only=True)]
    for name in ("data", "artifacts", "socket"):
        override["volumes"][name] = {"labels": labels}
    path = state / "compose.override.json"
    atomic_json(path, override)
    # Values are supplied through a fresh child environment, not a shared .env.
    env = dict(os.environ, SCAN_RULES_DIR=str(rules), MATRIX_SECURITY_HTTP_PORT=str(args.http_port), MATRIX_SECURITY_SSH_PORT=str(args.ssh_port))
    compose = ["docker", "compose", "--project-name", args.project, "-f", str(COMPOSE), "-f", str(path)]
    return compose, env, bindings


def compose_run(compose, env, extra, timeout=180):
    # The environment only contains public deployment settings. Temporarily
    # passing it through Popen avoids printing or writing a shared .env file.
    code, output = bounded(compose + extra, timeout, limit=4 * 1024 * 1024, env=env)
    require(code == 0, "compose-failed")
    return output


def health(compose, env, manifest):
    # Confirm the running scanner has exactly the bytes and absolute deadline
    # verified before startup. This also detects a stale mount after a switch.
    script = "import os,json,hashlib,signal; signal.alarm(45); from pathlib import Path; print(json.dumps({'expiresAt':int(os.getenv('SCAN_RULES_EXPIRES_AT','0')),'files':{n:hashlib.file_digest((Path('/rules')/n).open('rb'),'sha256').hexdigest() for n in ('main.cvd','daily.cvd','bytecode.cvd')}}))"
    actual = json.loads(compose_run(compose, env, ["exec", "-T", "scanner", "python", "-I", "-c", script], timeout=60))
    require(actual["expiresAt"] == manifest["expiresAt"] and actual["files"] == {x["name"]: x["sha256"] for x in manifest["files"]}, "running-scanner-rules-mismatch")
    output = compose_run(compose, env, ["exec", "-T", "matrixhub", "python", "-I", "-c", PROBE_SCRIPT], timeout=30)
    bundle = json.loads(output)
    compose_run(compose, env, ["exec", "-T", "matrixhub", "python", "-I", "-c",
                "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:3002/healthz',timeout=5).read()==b'OK'"], timeout=30)
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "initialize", "start", "status"))
    parser.add_argument("--state", type=Path, required=True, help="New directory for this deployment only")
    parser.add_argument("--rules-store", type=Path, required=True)
    parser.add_argument("--project", required=True, help="Unique mh-sec-* Compose project; never reuse an existing project")
    parser.add_argument("--rules-source", type=Path, help="Optional official main/daily/bytecode CVD directory; verified and imported before preflight")
    parser.add_argument("--http-port", type=int, default=3002)
    parser.add_argument("--ssh-port", type=int, default=2223)
    parser.add_argument("--app-image", default="matrixhub-security:local")
    parser.add_argument("--scanner-image", default="matrixhub-security-scanner:1.4.6")
    parser.add_argument("--concurrency", type=int, choices=range(1, 9), default=1)
    parser.add_argument("--native-threads", type=int, choices=(1, 2, 4))
    parser.add_argument("--profile", choices=("standard", "large-repository"), default="standard")
    parser.add_argument("--data-dir", type=Path, help="Large profile: new dedicated source-LFS directory on the capacity filesystem")
    parser.add_argument("--staging-dir", type=Path, help="Large profile: new dedicated sealed-staging directory on the capacity filesystem")
    parser.add_argument("--initialize-admin", action="store_true", help="Start only: privately initialize a proved-new owned database before publishing the API")
    parser.add_argument("--password-stdin", action="store_true", help="First initialization only: accept one new password from anonymous stdin instead of getpass")
    args = parser.parse_args()
    try:
        require(not args.initialize_admin or args.action == "start", "initialize-admin-is-start-only")
        require(not args.password_stdin or args.action == "initialize" or args.initialize_admin, "password-stdin-is-first-initialization-only")
        args.native_threads = args.native_threads or (2 if args.profile == "large-repository" else 1)
        if args.profile == "large-repository":
            require(args.concurrency == 1 and args.native_threads in (1, 2), "large-profile-requires-one-claim-and-at-most-two-native-threads")
        require(1024 <= args.http_port <= 65535 and 1024 <= args.ssh_port <= 65535 and args.http_port != args.ssh_port, "invalid-loopback-ports")
        require(args.concurrency * args.native_threads <= 4, "concurrency-times-native-threads-exceeds-4")
        state, marker = state_for(args)
        require(shutil.disk_usage(state).free >= 10 * 1024**3, "host-free-disk-below-10GiB")
        budget = memory_budget()
        require(budget["dockerCpus"] >= 2 + args.native_threads, "docker-cpu-budget-below-request")
        app = image_id(args.app_image)
        scanner = image_id(args.scanner_image)
        if args.rules_source:
            require(args.action != "status", "status-does-not-import-rules")
            prepare(args.rules_source, args.rules_store, scanner)
        rules, manifest = verify_active(args.rules_store, scanner)
        if args.profile == "large-repository":
            require(budget["dockerMemoryBytes"] >= 13 * 1024**3, "large-profile-docker-memory-below-13GiB")
        compose, env, bindings = render(args, state, marker, rules, manifest, app, scanner)
        plan = json.loads(compose_run(compose, env, ["config", "--format", "json"]))
        validate_plan(plan, bindings)
        if bindings and args.action != "status":
            verify_posix_bindings(bindings, app)
        result = {"status": "preflight-passed", "project": args.project, "rulesSnapshot": manifest["snapshot"],
                  "expiresAt": manifest["expiresAt"], "appImage": app, "scannerImage": scanner, "resources": budget, "profile": args.profile, "filesystemContract": "native-posix-verified" if bindings and args.action != "status" else "named-volumes-or-existing-runtime"}
        if args.action == "initialize" or args.initialize_admin:
            result["administrator"] = initialize_account(compose, env, plan, state, marker, app, compose_run, args.password_stdin)
            result["status"] = "administrator-initialized-services-stopped"
        if args.action == "start":
            # No seeded/default credential may be published by this wrapper.
            # The DB transaction is the authority if host checkpointing was
            # interrupted after a successful first password change.
            try:
                result["administrator"] = verify_account(plan, marker, app)
            except (SetupError, ValueError, KeyError, OSError):
                raise SetupError("administrator-proof-required-run-initialize-once") from None
            atomic_json(state / "administrator-initialized.json", result["administrator"])
            # --pull never makes all image/network changes explicit. Existing
            # volumes are accepted only with this deployment's ownership marker.
            try:
                compose_run(compose, env, ["up", "-d", "--pull", "never", "--wait", "--wait-timeout", "180"], timeout=240)
            except SetupError:
                ownership(args.project, marker["owner"])
                compose_run(compose, env, ["stop", "--timeout", "10"], timeout=60)
                raise
        if args.action in ("start", "status"):
            try:
                result["bundle"] = health(compose, env, manifest)
                result["status"] = "healthy"
            except SetupError:
                if args.action == "start":
                    ownership(args.project, marker["owner"])
                    compose_run(compose, env, ["stop", "--timeout", "10"], timeout=60)
                raise
        atomic_json(state / "last-check.json", result)
        print(json.dumps(result))
    except (SetupError, ValueError, KeyError, OSError) as error:
        print(json.dumps({"status": "failed", "code": str(error) if isinstance(error, SetupError) else type(error).__name__}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
