"""Host-side ownership and stdin boundary for first-admin initialization."""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import posixpath
import re
import sys
import warnings

from rules_snapshot import SetupError, atomic_json, ordinary, require, run, temporary_container
from fresh_admin import password_bytes, BootstrapRefused

HELPER = Path(__file__).resolve().with_name("fresh_admin.py")


def read_new_password(from_stdin):
    try:
        if from_stdin:
            value = sys.stdin.buffer.read(1025)
            require(len(value) <= 1024, "password-input-too-long")
            if value.endswith(b"\n"):
                value = value[:-1]
                if value.endswith(b"\r"):
                    value = value[:-1]
        else:
            # getpass fails closed instead of silently echoing through a pipe.
            require(sys.stdin.isatty(), "interactive-terminal-or-password-stdin-required")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass("New administrator password (14–72 UTF-8 bytes): ").encode("utf-8")
                repeated = getpass.getpass("Confirm new administrator password: ").encode("utf-8")
            require(value == repeated, "password-confirmation-mismatch")
            repeated = None
        return password_bytes(value)
    except (BootstrapRefused, UnicodeError, EOFError, getpass.GetPassWarning):
        raise SetupError("invalid-new-administrator-password") from None


def inspect_labels(kind, identifier):
    require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", identifier or "") is not None,
            "invalid-owned-resource-name")
    template = "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"
    return json.loads(run(["docker", kind, "inspect", "--format", template, identifier]))


def data_mount(plan, marker):
    mounts = {item["target"]: item for item in plan["services"]["matrixhub"]["volumes"]}
    item = mounts["/data"]
    source = item["source"]
    require(all(c not in source for c in ",\r\n"), "unsupported-mount-source")
    if item["type"] == "volume":
        spec = plan["volumes"].get(source)
        if spec is None:
            matching = [value for value in plan["volumes"].values() if value.get("name") == source]
            require(len(matching) == 1, "unknown-data-volume")
            spec = matching[0]
        name = spec.get("name", source)
        labels = inspect_labels("volume", name)
        require(labels.get("matrixhub.security.owner") == marker["owner"]
                and labels.get("com.docker.compose.project") == marker["project"], "data-volume-owner-mismatch")
        return "type=volume,src=" + name + ",dst=/data,volume-nocopy", name
    require(item["type"] == "bind", "unsupported-data-mount")
    path = ordinary(Path(source), directory=True)
    proof = json.loads(ordinary(path / ".matrixhub-security-owner.json").read_text(encoding="utf-8"))
    require(proof == {"owner": marker["owner"]}, "bind-directory-owner-mismatch")
    return "type=bind,src=" + str(path) + ",dst=/data", None


def require_stopped_attachments(project, owner, volume):
    identifiers = set(run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project]).decode().split())
    if volume:
        identifiers.update(run(["docker", "ps", "-aq", "--filter", "volume=" + volume]).decode().split())
    for identifier in identifiers:
        labels = inspect_labels("container", identifier)
        require(labels.get("matrixhub.security.owner") == owner
                and labels.get("com.docker.compose.project") == project, "unknown-volume-attachment")
        require(run(["docker", "container", "inspect", "--format", "{{.State.Running}}", identifier]).strip() == b"false",
                "initialization-requires-stopped-owned-services")


def require_no_bind_writers(paths):
    """Read only public mount/running metadata, never full container inspect."""
    if not paths:
        return
    require(os.name == "posix" and all(path.startswith("/") for path in paths),
            "bind-first-initialization-requires-linux-host-and-ext4")
    normalized = [posixpath.normpath(path) for path in paths]
    identifiers = run(["docker", "ps", "-aq"]).decode().split()
    require(len(identifiers) <= 256, "bind-attachment-inventory-budget")
    for identifier in identifiers:
        # Env, command arguments and account contents are intentionally absent.
        template = '{"mounts":{{json .Mounts}},"running":{{json .State.Running}}}'
        value = json.loads(run(["docker", "container", "inspect", "--format", template, identifier]))
        if not value["running"]:
            continue
        for mount in value["mounts"]:
            if mount.get("Type") != "bind" or not mount.get("RW"):
                continue
            source = posixpath.normpath(mount["Source"])
            for path in normalized:
                common = posixpath.commonpath((source, path))
                require(common not in (source, path), "running-overlapping-bind-writer")


def base_container(image, marker):
    return ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--user=65532:65532",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=64",
            "--memory=512m", "--memory-swap=512m", "--cpus=1", "--ulimit=core=0", "--log-driver=none",
            "--label", "matrixhub.security.owner=" + marker["owner"],
            "--label", "com.docker.compose.project=" + marker["project"],
            "--tmpfs=/tmp:rw,size=32m,mode=1777,noexec,nosuid,nodev",
            "--mount", "type=bind,src=" + str(ordinary(HELPER)) + ",dst=/bootstrap/fresh_admin.py,readonly",
            "--entrypoint=python", image]


def verify_account(plan, marker, image):
    mount, _ = data_mount(plan, marker)
    argv = base_container(image, marker)
    index = argv.index("--entrypoint=python")
    argv[index:index] = ["--mount", mount + ",readonly"]
    result = json.loads(temporary_container(argv + ["-I", "/bootstrap/fresh_admin.py", "verify", "--owner", marker["owner"]], timeout=45))
    require(result.get("owner") == marker["owner"] and result.get("status") == "administrator-initialized",
            "administrator-not-initialized")
    return result


def initialize_account(compose, env, plan, state, marker, image, compose_run, from_stdin=False):
    lock = state / "administrator-operation.lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise SetupError("administrator-operation-locked") from None
    try:
        require(not (state / "administrator-initialized.json").exists(), "administrator-already-initialized")
        # Creates only this project's stopped init container and new labeled
        # volumes. It never starts the API or publishes a service port.
        compose_run(compose, env, ["create", "--pull", "never", "init-volumes"], timeout=60)
        mount, volume = data_mount(plan, marker)
        require_stopped_attachments(marker["project"], marker["owner"], volume)
        # The same narrow init contract used by Compose, scoped to its labeled
        # volumes. The owned temporary executor always removes its exact ID.
        init_mounts = []
        bind_paths = []
        for item in plan["services"]["init-volumes"]["volumes"]:
            if item["type"] == "volume":
                spec = plan["volumes"].get(item["source"])
                require(spec is not None, "unknown-init-volume")
                name = spec.get("name", item["source"])
                labels = inspect_labels("volume", name)
                require(labels.get("matrixhub.security.owner") == marker["owner"]
                        and labels.get("com.docker.compose.project") == marker["project"], "init-volume-owner-mismatch")
                require_stopped_attachments(marker["project"], marker["owner"], name)
                source = "type=volume,src=" + name + ",volume-nocopy"
            else:
                require(item["type"] == "bind", "unsupported-init-mount")
                bind_paths.append(item["source"])
                source = "type=bind,src=" + item["source"]
            init_mounts += ["--mount", source + ",dst=" + item["target"]]
        require_no_bind_writers(bind_paths)
        temporary_container(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--user=0:0",
                             "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=FOWNER", "--security-opt=no-new-privileges:true",
                             "--pids-limit=8", "--memory=64m", "--log-driver=none", *init_mounts,
                             "--entrypoint=/bin/sh", image, "-ec", "chown 65532:65532 /data /input /run/matrix-security && chmod 0750 /data /input && chmod 0770 /run/matrix-security"], timeout=30)
        probe = json.loads(temporary_container(base_container(image, marker) + ["-I", "/bootstrap/fresh_admin.py", "probe"], timeout=30))
        require(probe == {"status": "public-bcrypt-probe-passed"}, "target-image-bcrypt-probe-failed")
        password = read_new_password(from_stdin)
        try:
            argv = base_container(image, marker)
            index = argv.index("--entrypoint=python")
            # The private API migration uses the same proved-owned staging and
            # socket mounts as its runtime. An old cached base need not contain
            # /input; creating that path on a read-only root would fail startup.
            private_mounts = []
            for offset in range(0, len(init_mounts), 2):
                value = init_mounts[offset + 1]
                private_mounts += ["--mount", value + (",readonly" if value.endswith("dst=/run/matrix-security") else "")]
            argv[index:index] = ["-i", *private_mounts, "--mount",
                               "type=bind,src=" + str(ordinary(state / "config.yaml")) + ",dst=/etc/matrixhub/config.yaml,readonly"]
            result = json.loads(temporary_container(argv + ["-I", "/bootstrap/fresh_admin.py", "initialize", "--owner", marker["owner"]],
                                                    timeout=110, input_data=password))
        finally:
            password = None
        require(result.get("status") == "administrator-initialized" and result.get("owner") == marker["owner"],
                "administrator-initialization-failed")
        # DB marker + password are in the same transaction; a failed host write
        # is recoverable by verify/start without resetting the account.
        atomic_json(state / "administrator-initialized.json", result)
        return result
    finally:
        lock.rmdir()
