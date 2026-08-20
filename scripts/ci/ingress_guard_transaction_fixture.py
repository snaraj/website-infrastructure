#!/usr/bin/env python3
"""Hermetic Linux transaction fixture for the host ingress guard.

The outer process creates one disposable user/mount/PID namespace per hostile
scenario. The inner process overlays only synthetic /etc, /run, /usr/local,
/var/lib, and command directories; ledgered systemctl, nft, and kubectl stubs
exercise the real custodied shell entrypoints without touching the host or a
cluster. Every scenario either closes successfully or proves verified rollback
and absence of transaction residue.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pty
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


SOURCE_REVISION = "a" * 40
PHASE_VERBS = {
    "prepared": "install",
    "artifacts-installed": "systemctl:daemon-reload",
    "guard-start-intent": "systemctl:start-no-block",
    "guard-active": "install",
    "dropin-installed": "mv",
    "kubelet-restart-intent": "systemctl:restart-kubelet",
    "awaiting-reboot-intent": "mv",
    "awaiting-reboot": "mv",
}
SIGNALS = {"term": signal.SIGTERM, "kill": signal.SIGKILL}


def synthetic_uuid(fill):
    """Return a grammar-valid, obviously synthetic UUID without inventory literals."""
    return fill * 8 + "-" + fill * 4 + "-4" + fill * 3 + "-8" + fill * 3 + "-" + fill * 12


def fail(message):
    raise RuntimeError(message)


def run_checked(command, **kwargs):
    completed = subprocess.run(command, check=False, **kwargs)
    if completed.returncode != 0:
        fail("command failed: " + " ".join(map(str, command)))
    return completed


def copy_executable(source, destination):
    resolved = Path(shutil.which(source) or source).resolve()
    if not resolved.is_file():
        fail(f"required executable missing: {source}")
    shutil.copy2(resolved, destination)
    destination.chmod(0o755)


COMMON_STUB = r'''
import json
import os
import time
from pathlib import Path

ROOT = Path("/run/ingress-guard-harness")
LEDGER = ROOT / "ledger.jsonl"
CONTROL = ROOT / "control.json"
PAUSED = ROOT / "paused.json"
JOURNAL = Path("/var/lib/website-infrastructure/ingress-guard/transaction/journal.v2")
LOAD_JOURNAL = Path("/var/lib/website-infrastructure/ingress-guard/transaction/load-journal.v2")


def journal_phase(kind="main"):
    path = LOAD_JOURNAL if kind == "load" else JOURNAL
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("phase="):
                return line.split("=", 1)[1]
    except OSError:
        pass
    return "none"


def record(verb, phase=None, **details):
    row = {"verb": verb, "phase": phase or journal_phase(), **details}
    with LEDGER.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def control(verb, stage="after"):
    try:
        selected = json.loads(CONTROL.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        record(verb)
        return False
    phase = journal_phase(selected.get("journal", "main"))
    record(verb, phase=phase)
    mode = selected.get("mode", "")
    selected_stage = "before" if mode.endswith("-before") else "after"
    if (
        selected.get("consumed")
        or selected.get("phase") != phase
        or selected.get("verb") != verb
        or selected_stage != stage
    ):
        return False
    selected["consumed"] = True
    CONTROL.write_text(json.dumps(selected, sort_keys=True), encoding="utf-8")
    if mode.startswith("pause"):
        PAUSED.write_text(json.dumps({"phase": phase, "verb": verb}), encoding="utf-8")
        while not (ROOT / "release").exists():
            time.sleep(0.01)
        return False
    return mode.startswith("fail")
'''


WRAPPER_STUB = COMMON_STUB + r'''
import subprocess
import sys

name = Path(sys.argv[0]).name
real = "/usr/bin/" + name + ".real"
if control(name, "before"):
    raise SystemExit(1)
completed = subprocess.run([real, *sys.argv[1:]], check=False)
if completed.returncode != 0:
    raise SystemExit(completed.returncode)
raise SystemExit(1 if control(name) else 0)
'''


SYSTEMCTL_STUB = COMMON_STUB + r'''
import subprocess
import sys

STATE = ROOT / "systemctl.json"
state = json.loads(STATE.read_text(encoding="utf-8"))
args = sys.argv[1:]


def save():
    STATE.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")


def finish(verb, status=0):
    save()
    if control("systemctl:" + verb):
        return 1
    return status


if args[:1] == ["show"]:
    prop = args[args.index("-p") + 1]
    unit = args[-1]
    if prop == "ActiveState":
        if unit == "kubelet.service":
            value = "active" if state["kubelet_active"] else "inactive"
        else:
            value = "active" if state["guard_active"] else "inactive"
    elif prop == "LoadState":
        value = "loaded" if Path("/etc/systemd/system/website-infrastructure-ingress-guard.service").is_file() else "not-found"
    elif prop == "FragmentPath":
        value = "/etc/systemd/system/website-infrastructure-ingress-guard.service"
    elif prop in {"After", "Requires"}:
        dropin = Path("/etc/systemd/system/kubelet.service.d/50-website-infrastructure-ingress-guard.conf")
        value = "website-infrastructure-ingress-guard.service" if dropin.is_file() else ""
    else:
        raise SystemExit(1)
    print(value)
    record("systemctl:show", property=prop)
    raise SystemExit(0)

if args[:2] == ["is-enabled", "--quiet"]:
    record("systemctl:is-enabled")
    raise SystemExit(0 if state["guard_enabled"] else 1)
if args[:1] == ["daemon-reload"]:
    raise SystemExit(finish("daemon-reload"))
if args[:1] == ["enable"]:
    state["guard_enabled"] = True
    raise SystemExit(finish("enable"))
if args[:1] == ["disable"]:
    state["guard_enabled"] = False
    raise SystemExit(finish("disable"))
if args[:1] == ["stop"]:
    state["guard_active"] = False
    raise SystemExit(finish("stop-guard"))
if args[:1] == ["restart"] and args[-1] == "kubelet.service":
    state["kubelet_active"] = True
    raise SystemExit(finish("restart-kubelet"))
if args[:1] == ["start"] and args[-1] == "kubelet.service":
    state["kubelet_active"] = True
    raise SystemExit(finish("start-kubelet"))
if args[:2] == ["start", "--no-block"]:
    raise SystemExit(finish("start-no-block"))
if args[:1] == ["start"] and args[-1] == "website-infrastructure-ingress-guard.service":
    runtime = Path("/run/website-infrastructure-ingress-guard")
    runtime.mkdir(mode=0o700, exist_ok=True)
    runtime.chmod(0o700)
    completed = subprocess.run(
        ["/usr/local/sbin/website-infrastructure-ingress-guard-load"],
        env={**os.environ, "RUNTIME_DIRECTORY": str(runtime)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode == 0:
        state["guard_active"] = True
    raise SystemExit(finish("start-guard", completed.returncode))
record("systemctl:unknown")
raise SystemExit(1)
'''


NFT_STUB = COMMON_STUB + r'''
import sys

STATE = ROOT / "nft-state"
args = sys.argv[1:]
if args == ["-j", "list", "ruleset"]:
    verb = "nft:capture"
    should_fail = control(verb)
    if should_fail:
        raise SystemExit(1)
    source = ROOT / ("healthy-ruleset.json" if STATE.exists() else "absent-ruleset.json")
    sys.stdout.write(source.read_text(encoding="utf-8"))
    raise SystemExit(0)
if len(args) == 3 and args[:2] == ["-c", "-f"]:
    record("nft:check")
    raise SystemExit(0 if Path(args[2]).is_file() else 1)
if len(args) == 2 and args[0] == "-f":
    STATE.write_text("present\n", encoding="ascii")
    raise SystemExit(1 if control("nft:apply") else 0)
if args == ["delete", "table", "inet", "website_infrastructure_ingress_guard"]:
    STATE.unlink(missing_ok=True)
    raise SystemExit(1 if control("nft:delete") else 0)
record("nft:unknown")
raise SystemExit(1)
'''


KUBECTL_STUB = COMMON_STUB + r'''
import sys

CONFIG = ROOT / "health.json"
configuration = json.loads(CONFIG.read_text(encoding="utf-8"))
args = sys.argv[1:]
record("kubectl:call")
if not configuration.get("healthy", True):
    raise SystemExit(1)

namespace = "cluster"
filtered = []
index = 0
while index < len(args):
    if args[index].startswith("--kubeconfig=") or args[index].startswith("--request-timeout="):
        index += 1
        continue
    if args[index].startswith("--namespace="):
        namespace = args[index].split("=", 1)[1]
        index += 1
        continue
    if args[index] in {"--kubeconfig", "--request-timeout", "--namespace"}:
        if args[index] == "--namespace":
            namespace = args[index + 1]
        index += 2
    else:
        filtered.append(args[index])
        index += 1
args = filtered
if args[:2] == ["get", "--raw=/readyz"]:
    record("kubectl:api-ready")
    print("ok")
    raise SystemExit(0)
if args[:2] == ["get", "nodes"]:
    record("kubectl:nodes-listed")
    print("node/fixture")
    raise SystemExit(0)
if args[:1] == ["wait"]:
    record("kubectl:nodes-ready")
    raise SystemExit(0)
if args[:1] == ["rollout"]:
    if "daemonset/calico-node" in args:
        record("kubectl:calico-rollout")
    elif any(name in args for name in (
        "deployment/source-controller",
        "deployment/kustomize-controller",
        "deployment/helm-controller",
    )):
        record("kubectl:flux-rollout")
    elif any(name in args for name in (
        "deployment/naranjo-online-tunnel",
        "deployment/lidersea-com-tunnel",
    )):
        record("kubectl:tunnel-rollout")
    elif any(name in args for name in (
        "deployment/naranjo-online",
        "deployment/lidersea-com",
    )):
        record("kubectl:site-rollout")
    else:
        raise SystemExit(1)
    raise SystemExit(0)
if args[:1] == ["get"]:
    resource = args[1]
    present = {
        ("cluster", "namespace/flux-system"): configuration.get("flux", False),
        ("kube-system", "daemonset/calico-node"): True,
        ("flux-system", "deployment/source-controller"): configuration.get("flux", False),
        ("flux-system", "deployment/kustomize-controller"): configuration.get("flux", False),
        ("flux-system", "deployment/helm-controller"): configuration.get("flux", False),
        ("flux-system", "deployment/notification-controller"): configuration.get("flux", False),
        ("cloudflare-public", "deployment/naranjo-online-tunnel"): configuration.get("tunnel", False),
        ("cloudflare-public", "deployment/lidersea-com-tunnel"): configuration.get("tunnel", False),
        ("naranjo-online", "deployment/naranjo-online"): configuration.get("naranjo", False),
        ("lidersea-com", "deployment/lidersea-com"): configuration.get("lidersea", False),
    }.get((namespace, resource), False)
    if present:
        if resource == "namespace/flux-system":
            record("kubectl:flux-namespace")
        elif resource == "daemonset/calico-node":
            record("kubectl:calico-present")
        elif namespace == "flux-system":
            record("kubectl:flux-present")
        elif namespace == "cloudflare-public":
            record("kubectl:tunnel-present")
        else:
            record("kubectl:site-present")
        if resource.startswith("namespace/"):
            print(resource)
        elif resource.startswith("daemonset/"):
            print("daemonset.apps/" + resource.split("/", 1)[1])
        else:
            print("deployment.apps/" + resource.split("/", 1)[1])
    raise SystemExit(0)
raise SystemExit(1)
'''


def write_executable(path, text):
    path.write_text("#!/usr/bin/python3\n" + text, encoding="utf-8")
    path.chmod(0o755)


def healthy_ruleset(repo_root):
    script = repo_root / "scripts" / "validate_ingress_guard.py"
    spec = importlib.util.spec_from_file_location("ingress_fixture_model", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    interface = "adminvpn0"
    chain = {
        "family": "inet",
        "table": module.OWNED_TABLE,
        "name": module.OWNED_CHAIN,
        "handle": 1,
        "type": "filter",
        "hook": "input",
        "prio": -10,
        "policy": "accept",
    }
    items = [
        {"metainfo": {"version": "fixture", "release_name": "fixture", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": module.OWNED_TABLE, "handle": 20}},
        {"chain": chain},
    ]
    for iface, port, verdict in module.expected_sequence((interface,)):
        items.append({
            "rule": {
                "family": "inet",
                "table": module.OWNED_TABLE,
                "chain": module.OWNED_CHAIN,
                "handle": 7,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": iface}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {verdict: None},
                ],
            }
        })
    return {"nftables": items}


class NamespaceFixture:
    def __init__(self, repo_root, scratch):
        self.repo_root = repo_root.resolve()
        self.scratch = scratch.resolve()
        self.fake = self.scratch / "fake"
        self.harness = self.fake / "run" / "ingress-guard-harness"
        self.launcher = Path("/usr/local/sbin/website-infrastructure-ingress-guard-custody")
        self.manifest_hash = hashlib.sha256(
            (self.repo_root / "bootstrap/pi/ingress-guard/source-manifest.v1").read_bytes()
        ).hexdigest()
        self.launcher_hash = hashlib.sha256(
            (self.repo_root / "bootstrap/pi/ingress-guard/custody-ingress-guard.sh").read_bytes()
        ).hexdigest()

    def setup(self):
        for relative in (
            "etc/systemd/system/kubelet.service.d",
            "etc/kubernetes/pki",
            "usr-local/sbin",
            "usr-local/bin",
            "usr-local/lib",
            "var-lib",
            "run/ingress-guard-harness",
            "tmp",
            "usr-bin",
            "usr-sbin",
            "kernel",
        ):
            (self.fake / relative).mkdir(parents=True, exist_ok=True)
        for path in (
            self.fake / "etc/systemd/system",
            self.fake / "etc/systemd/system/kubelet.service.d",
            self.fake / "usr-local/sbin",
            self.fake / "usr-local/bin",
            self.fake / "usr-local/lib",
        ):
            path.chmod(0o755)
        (self.fake / "etc/kubernetes").chmod(0o755)
        (self.fake / "etc/kubernetes/pki").chmod(0o755)
        for name in ("passwd", "group", "nsswitch.conf"):
            source = Path("/etc") / name
            if source.exists():
                shutil.copy2(source, self.fake / "etc" / name)

        required = (
            "awk", "bash", "chmod", "chown", "cmp", "dirname", "env",
            "flock", "grep", "install", "mktemp", "mount", "mv", "python3",
            "readlink", "rm", "rmdir", "sha256sum", "stat", "sync", "timeout",
        )
        for name in required:
            destination = self.fake / "usr-bin" / name
            copy_executable(name, destination)
        shutil.copy2(self.fake / "usr-bin/install", self.fake / "usr-bin/install.real")
        shutil.copy2(self.fake / "usr-bin/mv", self.fake / "usr-bin/mv.real")
        write_executable(self.fake / "usr-bin/install", WRAPPER_STUB)
        write_executable(self.fake / "usr-bin/mv", WRAPPER_STUB)
        write_executable(self.fake / "usr-bin/systemctl", SYSTEMCTL_STUB)
        write_executable(self.fake / "usr-local/bin/kubectl", KUBECTL_STUB)
        write_executable(self.fake / "usr-sbin/nft", NFT_STUB)
        (self.fake / "usr-bin/sh").symlink_to("bash")

        state = {"kubelet_active": True, "guard_enabled": False, "guard_active": False}
        (self.harness / "systemctl.json").write_text(json.dumps(state), encoding="utf-8")
        health = {"healthy": True, "flux": True, "tunnel": True, "naranjo": True, "lidersea": True}
        (self.harness / "health.json").write_text(json.dumps(health), encoding="utf-8")
        (self.harness / "absent-ruleset.json").write_text(
            json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}]}),
            encoding="utf-8",
        )
        (self.harness / "healthy-ruleset.json").write_text(
            json.dumps(healthy_ruleset(self.repo_root), separators=(",", ":")),
            encoding="utf-8",
        )
        self.set_boot(synthetic_uuid("1"))
        (self.fake / "kernel/uuid").write_text(
            synthetic_uuid("3") + "\n", encoding="ascii"
        )
        (self.fake / "kernel/uuid").chmod(0o444)
        (self.fake / "etc/kubernetes/pki/ca.crt").write_text("fixture-ca\n", encoding="ascii")
        (self.fake / "etc/kubernetes/pki/ca.crt").chmod(0o644)
        (self.fake / "etc/kubernetes/admin.conf").write_text("fixture-kubeconfig\n", encoding="ascii")
        (self.fake / "etc/kubernetes/admin.conf").chmod(0o600)

        mount = shutil.which("mount") or "/usr/bin/mount"
        for source, target in (
            (self.fake / "var-lib", Path("/var/lib")),
            (self.fake / "run", Path("/run")),
            (self.fake / "tmp", Path("/tmp")),
            (self.fake / "usr-local", Path("/usr/local")),
            (self.fake / "usr-sbin", Path("/usr/sbin")),
            (self.fake / "usr-bin", Path("/usr/bin")),
            (self.fake / "etc", Path("/etc")),
        ):
            run_checked([mount, "--bind", str(source), str(target)])
        run_checked(["/usr/bin/mount", "--bind", str(self.fake / "kernel/boot_id"), "/proc/sys/kernel/random/boot_id"])
        run_checked(["/usr/bin/mount", "--bind", str(self.fake / "kernel/uuid"), "/proc/sys/kernel/random/uuid"])

        shutil.copy2(
            self.repo_root / "bootstrap/pi/ingress-guard/custody-ingress-guard.sh",
            self.launcher,
        )
        self.launcher.chmod(0o700)

    def set_boot(self, value):
        path = self.fake / "kernel/boot_id"
        if path.exists():
            path.chmod(0o600)
        path.write_text(value + "\n", encoding="ascii")
        path.chmod(0o444)

    def environment(self, action):
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "LANG": "C",
            "LC_ALL": "C",
            "TERM": "dumb",
            "INGRESS_GUARD_SOURCE_REVISION": SOURCE_REVISION,
            "INGRESS_GUARD_MANIFEST_SHA256": self.manifest_hash,
            "INGRESS_GUARD_CUSTODY_SHA256": self.launcher_hash,
        }
        if action == "--stage":
            environment.update({
                "INGRESS_GUARD_SOURCE_ROOT": str(self.repo_root),
                "CONFIRM_INGRESS_GUARD_CUSTODY": (
                    "custody-reviewed-ingress-guard-" + SOURCE_REVISION + "-" + self.manifest_hash
                ),
            })
        elif action == "--install":
            environment["CONFIRM_INGRESS_GUARD_INSTALL"] = (
                "install-reviewed-ssh-only-ingress-guard-" + SOURCE_REVISION + "-" + self.manifest_hash
            )
        elif action == "--retrofit-activate":
            environment["CONFIRM_INGRESS_GUARD_RETROFIT"] = (
                "retrofit-reviewed-running-cluster-" + SOURCE_REVISION + "-" + self.manifest_hash
            )
        elif action == "--retrofit-close":
            environment["CONFIRM_INGRESS_GUARD_RETROFIT_CLOSE"] = (
                "close-reviewed-ingress-guard-retrofit-" + SOURCE_REVISION + "-" + self.manifest_hash
            )
        elif action == "--recover":
            environment["CONFIRM_INGRESS_GUARD_RECOVERY"] = "recover-reviewed-ingress-guard"
        return environment

    def pty_run(self, action, environment=None, signal_to_send=None, timeout=75):
        child, master = pty.fork()
        if child == 0:
            os.execve(str(self.launcher), [str(self.launcher), action], environment or self.environment(action))
        output = bytearray()
        deadline = time.monotonic() + timeout
        sent = signal_to_send is None
        status = None
        while time.monotonic() < deadline:
            if not sent and (self.harness / "paused.json").exists():
                os.killpg(child, signal_to_send)
                # Bash defers a trapped TERM while it waits for a foreground
                # command, and that child may inherit TERM ignored. Release the
                # synthetic pause only after the signal is pending so Bash can
                # reap the child and run its rollback trap deterministically.
                (self.harness / "release").write_text(
                    "release\n", encoding="ascii"
                )
                sent = True
            readable, _, _ = select.select([master], [], [], 0.02)
            if readable:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                output.extend(chunk[: max(0, 65536 - len(output))])
            waited, observed = os.waitpid(child, os.WNOHANG)
            if waited:
                status = os.waitstatus_to_exitcode(observed)
                break
        if status is None:
            try:
                os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waited, observed = os.waitpid(child, 0)
            status = os.waitstatus_to_exitcode(observed)
            fail("transaction timeout")
        os.close(master)
        return status, bytes(output)

    def stage(self, source_root=None):
        environment = self.environment("--stage")
        if source_root is not None:
            environment["INGRESS_GUARD_SOURCE_ROOT"] = str(source_root)
        return self.pty_run("--stage", environment)

    def prepare_private_inputs(self):
        input_root = Path("/var/lib/website-infrastructure/ingress-guard/input")
        input_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        input_root.chmod(0o700)
        contract = input_root / "admin-ingress.env"
        contract.write_text(
            "ADMIN_INGRESS_REVIEWED=yes\nADMIN_INGRESS_INTERFACE=adminvpn0\n",
            encoding="ascii",
        )
        contract.chmod(0o600)
        boot_hash = hashlib.sha256((self.fake / "kernel/boot_id").read_bytes()).hexdigest()
        ca_hash = hashlib.sha256(Path("/etc/kubernetes/pki/ca.crt").read_bytes()).hexdigest()
        attestation = input_root / "retrofit-attestation.env"
        fields = (
            "SCHEMA=ingress-guard-retrofit-attestation-v1",
            "SOURCE_REVISION=" + SOURCE_REVISION,
            "MANIFEST_SHA256=" + self.manifest_hash,
            "BOOT_ID_SHA256=" + boot_hash,
            "CLUSTER_CA_SHA256=" + ca_hash,
            "OWNED_TABLE_PRESTATE=absent",
            "GUARD_UNIT_PRESTATE=absent",
            "DROPIN_PRESTATE=absent",
            "KUBELET_PRESTATE=active",
            "TWO_RETAINED_SESSIONS=yes",
            "PHYSICAL_LAN_RECOVERY=yes",
            "FRESH_LOGIN_CANARY=yes",
            "MUTATION_WINDOW_AUTHORIZED=yes",
        )
        attestation.write_text("\n".join(fields) + "\n", encoding="ascii")
        attestation.chmod(0o600)
        return attestation

    def set_control(self, phase, verb, mode, journal="main"):
        for name in ("paused.json", "release"):
            (self.harness / name).unlink(missing_ok=True)
        (self.harness / "control.json").write_text(
            json.dumps({
                "phase": phase,
                "verb": verb,
                "mode": mode,
                "journal": journal,
                "consumed": False,
            }),
            encoding="utf-8",
        )

    def clear_control(self):
        paused = self.harness / "paused.json"
        if paused.exists():
            # GNU timeout may place its child in a distinct process group. A
            # caller SIGKILL must not leave the synthetic paused systemctl/load
            # descendant holding the real global lock forever; release the
            # injected pause and wait boundedly for that independently managed
            # service transaction to settle.
            (self.harness / "release").write_text("release\n", encoding="ascii")
            import fcntl

            lock_path = Path(
                "/var/lib/website-infrastructure/ingress-guard/transaction/global.lock"
            )
            deadline = time.monotonic() + 10
            while lock_path.exists() and time.monotonic() < deadline:
                descriptor = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
                try:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        time.sleep(0.02)
                        continue
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    break
                finally:
                    os.close(descriptor)
        for name in ("control.json", "paused.json", "release"):
            (self.harness / name).unlink(missing_ok=True)

    def journal(self):
        path = Path("/var/lib/website-infrastructure/ingress-guard/transaction/journal.v2")
        if not path.is_file():
            return {}
        return dict(line.split("=", 1) for line in path.read_text(encoding="ascii").splitlines())

    def load_journal(self):
        path = Path(
            "/var/lib/website-infrastructure/ingress-guard/transaction/load-journal.v2"
        )
        if not path.is_file():
            return {}
        return dict(line.split("=", 1) for line in path.read_text(encoding="ascii").splitlines())

    def assert_rollback_closed(self):
        journal = self.journal()
        if journal.get("phase") != "rolled-back":
            fail("rollback journal not closed")
        state = json.loads((self.harness / "systemctl.json").read_text(encoding="utf-8"))
        if state != {"guard_active": False, "guard_enabled": False, "kubelet_active": True}:
            fail("service prestate not restored")
        if (self.harness / "nft-state").exists():
            fail("owned table residue")
        for path in (
            "/etc/website-infrastructure",
            "/etc/systemd/system/website-infrastructure-ingress-guard.service",
            "/etc/systemd/system/kubelet.service.d/50-website-infrastructure-ingress-guard.conf",
            "/usr/local/lib/website-infrastructure",
            "/usr/local/sbin/website-infrastructure-ingress-guard-load",
            "/usr/local/sbin/website-infrastructure-ingress-guard-verify",
            "/usr/local/sbin/website-infrastructure-ingress-guard-recover",
            "/usr/local/sbin/website-infrastructure-ingress-guard-retrofit",
        ):
            if Path(path).exists() or Path(path).is_symlink():
                fail("rollback file residue")
        state_root = Path("/var/lib/website-infrastructure/ingress-guard")
        residue = [
            path
            for path in state_root.rglob("*")
            if path.name.endswith(".tmp") or path.name.startswith((".stage.", ".document."))
        ]
        if residue:
            fail("transaction temporary residue")

    def assert_no_transaction_temps(self):
        state_root = Path("/var/lib/website-infrastructure/ingress-guard")
        residue = [path for path in state_root.rglob("*") if path.name.endswith(".tmp")]
        if residue:
            fail("transaction temporary residue")


def success_activation(fixture):
    status, output = fixture.stage()
    if status != 0:
        fail("custody stage failed: " + output[-2000:].decode("utf-8", "replace"))
    fixture.prepare_private_inputs()
    status, output = fixture.pty_run("--retrofit-activate")
    if status != 0 or fixture.journal().get("phase") != "awaiting-reboot":
        ledger_path = fixture.harness / "ledger.jsonl"
        ledger = ledger_path.read_text(encoding="utf-8")[-4000:] if ledger_path.exists() else ""
        fail(
            "retrofit activation failed status="
            + str(status)
            + ": "
            + output[-2000:].decode("utf-8", "replace")
            + " ledger="
            + ledger
        )


def scenario_success(fixture):
    success_activation(fixture)
    fixture.set_boot(synthetic_uuid("2"))
    status, output = fixture.pty_run("--retrofit-close")
    if status != 0 or fixture.journal().get("phase") != "committed":
        fail(
            "reboot closure failed status="
            + str(status)
            + ": "
            + output[-2000:].decode("utf-8", "replace")
        )
    ledger = (fixture.harness / "ledger.jsonl").read_text(encoding="utf-8")
    rows = [json.loads(line) for line in ledger.splitlines()]
    counts = {}
    for row in rows:
        counts[row["verb"]] = counts.get(row["verb"], 0) + 1
    required = {
        "kubectl:api-ready": 1,
        "kubectl:nodes-listed": 1,
        "kubectl:nodes-ready": 1,
        "kubectl:calico-present": 1,
        "kubectl:calico-rollout": 1,
        "kubectl:flux-namespace": 1,
        "kubectl:flux-present": 3,
        "kubectl:flux-rollout": 3,
        "kubectl:tunnel-present": 2,
        "kubectl:tunnel-rollout": 2,
        "kubectl:site-present": 2,
        "kubectl:site-rollout": 2,
    }
    for verb, minimum in required.items():
        if counts.get(verb, 0) < minimum:
            fail("applicable health canary category missing: " + verb)


def scenario_interruption(fixture, phase, mode):
    status, _output = fixture.stage()
    if status != 0:
        fail("custody stage failed")
    fixture.prepare_private_inputs()
    fixture.set_control(phase, PHASE_VERBS[phase], "fail" if mode == "fail" else "pause")
    signal_to_send = None if mode == "fail" else SIGNALS[mode]
    status, _output = fixture.pty_run(
        "--retrofit-activate", signal_to_send=signal_to_send
    )
    protected_term = mode == "term" and phase in {
        "awaiting-reboot-intent",
        "awaiting-reboot",
    }
    if protected_term:
        # The durable pending-receipt window deliberately masks catchable
        # signals. TERM must finish the exact pending state, not manufacture a
        # receipt/journal split; SIGKILL remains covered separately.
        fixture.clear_control()
        if status != 0 or fixture.journal().get("phase") != "awaiting-reboot":
            fail("TERM did not close the protected pending-receipt window")
        fixture.assert_no_transaction_temps()
        fixture.set_boot(synthetic_uuid("2"))
        status, _output = fixture.pty_run("--retrofit-close")
        if status != 0 or fixture.journal().get("phase") != "committed":
            fail("TERM-protected pending transaction did not close")
        return
    if status == 0:
        fail("hostile interruption unexpectedly passed")
    fixture.clear_control()
    if mode == "kill":
        status, _output = fixture.pty_run("--recover")
        if status != 0:
            fail("post-kill recovery failed")
    elif fixture.journal().get("phase") != "rolled-back":
        status, _output = fixture.pty_run("--recover")
        if status != 0:
            fail("deterministic recovery failed")
    fixture.assert_rollback_closed()


def copy_public_tree(repo_root, destination):
    module_path = repo_root / "scripts/validate_ingress_guard.py"
    spec = importlib.util.spec_from_file_location("ingress_fixture_inventory", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for relative in set(module.PUBLIC_CUSTODY_FILES) | {module.MANIFEST_FILE_REL}:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / relative, target)


def scenario_source_attack(fixture, attack):
    source = fixture.scratch / "source"
    copy_public_tree(fixture.repo_root, source)
    target = source / "bootstrap/pi/ingress-guard/transaction-lib.sh"
    if attack == "symlink":
        target.unlink()
        target.symlink_to(fixture.repo_root / "bootstrap/pi/ingress-guard/transaction-lib.sh")
    elif attack == "hardlink":
        original = target.with_suffix(".original")
        target.rename(original)
        os.link(original, target)
    else:
        good = target.read_bytes()
        malicious = b"touch /run/ingress-guard-harness/pre-source-marker\n" + good
        stop = threading.Event()

        def racer():
            index = 0
            while not stop.is_set():
                payload = good if index % 2 == 0 else malicious
                temporary = target.with_name("transaction-lib.race")
                temporary.write_bytes(payload)
                temporary.chmod(0o644)
                os.replace(temporary, target)
                index += 1

        thread = threading.Thread(target=racer, daemon=True)
        thread.start()
        try:
            status, _output = fixture.stage(source)
        finally:
            stop.set()
            thread.join(timeout=2)
        if status == 0:
            custody = Path("/var/lib/website-infrastructure/ingress-guard/custody") / fixture.manifest_hash
            observed = (custody / "bootstrap/pi/ingress-guard/transaction-lib.sh").read_bytes()
            if hashlib.sha256(observed).hexdigest() != hashlib.sha256(good).hexdigest():
                fail("race admitted unbound bytes")
        elif any(Path("/var/lib/website-infrastructure/ingress-guard/custody").glob(".stage.*")):
            fail("race failure left custody stage")
        return
    status, _output = fixture.stage(source)
    if status == 0:
        fail("unsafe source type passed custody")
    custody_root = Path("/var/lib/website-infrastructure/ingress-guard/custody")
    if (custody_root / fixture.manifest_hash).exists() or any(custody_root.glob(".stage.*")):
        fail("source rejection left custody residue")


def scenario_pre_source(fixture):
    status, _output = fixture.stage()
    if status != 0:
        fail("custody stage failed")
    malicious = fixture.scratch / "malicious"
    copy_public_tree(fixture.repo_root, malicious)
    marker = fixture.harness / "pre-source-marker"
    entry = malicious / "bootstrap/pi/ingress-guard/install-ingress-guard.sh"
    library = malicious / "bootstrap/pi/ingress-guard/transaction-lib.sh"
    entry.write_text("touch /run/ingress-guard-harness/pre-source-marker\n" + entry.read_text(), encoding="utf-8")
    library.write_text("touch /run/ingress-guard-harness/pre-source-marker\n" + library.read_text(), encoding="utf-8")
    environment = fixture.environment("--install")
    environment["INGRESS_GUARD_SOURCE_ROOT"] = str(malicious)
    status, _output = fixture.pty_run("--install", environment)
    if status == 0 or marker.exists():
        fail("checkout-relative byte executed before custody")
    if fixture.journal():
        fail("offline refusal mutated transaction state")


def scenario_stale_binding(fixture):
    success_activation(fixture)
    attestation = Path("/var/lib/website-infrastructure/ingress-guard/input/retrofit-attestation.env")
    original = attestation.read_bytes()
    fixture.set_boot(synthetic_uuid("2"))
    current_hash = hashlib.sha256((fixture.fake / "kernel/boot_id").read_bytes()).hexdigest()
    attestation.write_text(
        original.decode("ascii").replace(
            next(line for line in original.decode("ascii").splitlines() if line.startswith("BOOT_ID_SHA256=")),
            "BOOT_ID_SHA256=" + current_hash,
        ),
        encoding="ascii",
    )
    attestation.chmod(0o600)
    status, _output = fixture.pty_run("--retrofit-close")
    if status == 0 or fixture.journal().get("phase") != "awaiting-reboot":
        fail("stale attestation closed transaction")
    attestation.write_bytes(original)
    attestation.chmod(0o600)
    status, _output = fixture.pty_run("--retrofit-close")
    if status != 0 or fixture.journal().get("phase") != "committed":
        fail("restored bound attestation did not close")


def scenario_receipt_tamper(fixture):
    success_activation(fixture)
    journal = fixture.journal()
    receipt = Path("/var/lib/website-infrastructure/ingress-guard/receipts") / (
        f"retrofit.{journal['attempt_id']}.pending-reboot.receipt.v2"
    )
    original = receipt.read_bytes()
    replay = original.replace(
        f"attempt_id={journal['attempt_id']}".encode("ascii"),
        ("attempt_id=" + synthetic_uuid("0")).encode("ascii"),
    )
    receipt.write_bytes(replay)
    receipt.chmod(0o600)
    fixture.set_boot(synthetic_uuid("2"))
    status, _output = fixture.pty_run("--retrofit-close")
    if status == 0 or receipt.read_bytes() != replay:
        fail("replayed receipt was accepted or overwritten")
    receipt.write_bytes(original)
    receipt.chmod(0o600)
    status, _output = fixture.pty_run("--retrofit-close")
    if status != 0:
        fail("valid receipt could not close after replay refusal")


def scenario_unhealthy(fixture):
    status, _output = fixture.stage()
    if status != 0:
        fail("custody stage failed")
    fixture.prepare_private_inputs()
    health = {"healthy": False, "flux": True, "tunnel": True, "naranjo": True, "lidersea": True}
    (fixture.harness / "health.json").write_text(json.dumps(health), encoding="utf-8")
    status, _output = fixture.pty_run("--retrofit-activate")
    if status == 0 or fixture.journal():
        fail("unhealthy cluster produced an exact-prestate journal")
    if (fixture.harness / "nft-state").exists():
        fail("unhealthy prestate mutated nft")


def scenario_receipt_split(fixture, target, mode):
    success_activation(fixture)
    if target == "pending":
        # Re-run activation in a fresh fixture path is not possible; the first
        # activation already reached pending. This branch is initialized below
        # without success_activation.
        fail("pending split setup invalid")
    fixture.set_boot(synthetic_uuid("2"))
    control_mode = "fail-before" if mode == "fail" else "pause-before"
    fixture.set_control("commit-intent", "mv", control_mode)
    signal_to_send = None if mode == "fail" else SIGNALS[mode]
    status, _output = fixture.pty_run("--retrofit-close", signal_to_send=signal_to_send)
    if mode == "term":
        fixture.clear_control()
        if status != 0 or fixture.journal().get("phase") != "committed":
            fail("TERM did not close the protected commit-receipt window")
        fixture.assert_no_transaction_temps()
        return
    if status == 0:
        ledger = (fixture.harness / "ledger.jsonl").read_text(encoding="utf-8")[-4000:]
        fail("commit receipt split unexpectedly passed: " + ledger)
    fixture.clear_control()
    if fixture.journal().get("phase") != "committed":
        status, _output = fixture.pty_run("--recover")
        if status != 0:
            fail("commit receipt split did not reconcile")
    if fixture.journal().get("phase") != "committed":
        fail("commit intent not closed")
    fixture.assert_no_transaction_temps()


def scenario_pending_receipt_split(fixture, mode):
    status, _output = fixture.stage()
    if status != 0:
        fail("custody stage failed")
    fixture.prepare_private_inputs()
    control_mode = "fail-before" if mode == "fail" else "pause-before"
    fixture.set_control("awaiting-reboot-intent", "mv", control_mode)
    signal_to_send = None if mode == "fail" else SIGNALS[mode]
    status, _output = fixture.pty_run(
        "--retrofit-activate", signal_to_send=signal_to_send
    )
    if mode == "term":
        fixture.clear_control()
        if status != 0 or fixture.journal().get("phase") != "awaiting-reboot":
            fail("TERM did not close the protected pending-receipt split")
        fixture.assert_no_transaction_temps()
        fixture.set_boot(synthetic_uuid("2"))
        status, _output = fixture.pty_run("--retrofit-close")
        if status != 0 or fixture.journal().get("phase") != "committed":
            fail("TERM-protected pending split did not close")
        return
    if status == 0:
        fail("pending receipt split unexpectedly passed")
    fixture.clear_control()
    if fixture.journal().get("phase") != "awaiting-reboot":
        status, _output = fixture.pty_run("--recover")
        if status != 0:
            fail("pending receipt split did not reconcile")
    if fixture.journal().get("phase") != "awaiting-reboot":
        fail("pending intent not closed")
    fixture.assert_no_transaction_temps()
    fixture.set_boot(synthetic_uuid("2"))
    status, _output = fixture.pty_run("--retrofit-close")
    if status != 0 or fixture.journal().get("phase") != "committed":
        fail("reconciled pending transaction did not close")


def scenario_load_receipt_split(fixture, mode):
    status, _output = fixture.stage()
    if status != 0:
        fail("custody stage failed")
    fixture.prepare_private_inputs()
    control_mode = "fail-before" if mode == "fail" else "pause-before"
    fixture.set_control(
        "commit-intent", "mv", control_mode, journal="load"
    )
    signal_to_send = None if mode == "fail" else SIGNALS[mode]
    status, _output = fixture.pty_run(
        "--retrofit-activate", signal_to_send=signal_to_send
    )
    fixture.clear_control()
    if status == 0:
        if fixture.journal().get("phase") != "awaiting-reboot":
            fail("reconciled loader did not finish activation")
        fixture.set_boot(synthetic_uuid("2"))
        status, _output = fixture.pty_run("--retrofit-close")
        if status != 0 or fixture.journal().get("phase") != "committed":
            fail("loader-split activation did not close")
    else:
        if fixture.journal().get("phase") != "rolled-back":
            status, output = fixture.pty_run("--recover")
            if status != 0:
                fail(
                    "loader receipt split main recovery failed: "
                    + output[-3000:].decode("utf-8", "replace")
                    + " main="
                    + json.dumps(fixture.journal(), sort_keys=True)
                    + " load="
                    + json.dumps(fixture.load_journal(), sort_keys=True)
                )
        fixture.assert_rollback_closed()
    if fixture.load_journal().get("phase") != "committed":
        fail("published loader receipt was not journal-closed")
    fixture.assert_no_transaction_temps()


def run_inner(repo_root, scratch, scenario):
    fixture = NamespaceFixture(repo_root, scratch)
    fixture.setup()
    if scenario == "success":
        scenario_success(fixture)
    elif scenario.startswith("failure-"):
        scenario_interruption(fixture, scenario.removeprefix("failure-"), "fail")
    elif scenario.startswith("term-"):
        scenario_interruption(fixture, scenario.removeprefix("term-"), "term")
    elif scenario.startswith("kill-"):
        scenario_interruption(fixture, scenario.removeprefix("kill-"), "kill")
    elif scenario.startswith("source-"):
        scenario_source_attack(fixture, scenario.removeprefix("source-"))
    elif scenario == "pre-source":
        scenario_pre_source(fixture)
    elif scenario == "stale-binding":
        scenario_stale_binding(fixture)
    elif scenario == "receipt-tamper":
        scenario_receipt_tamper(fixture)
    elif scenario == "unhealthy":
        scenario_unhealthy(fixture)
    elif scenario.startswith("commit-split-"):
        scenario_receipt_split(fixture, "commit", scenario.removeprefix("commit-split-"))
    elif scenario.startswith("pending-split-"):
        scenario_pending_receipt_split(fixture, scenario.removeprefix("pending-split-"))
    elif scenario.startswith("load-split-"):
        scenario_load_receipt_split(fixture, scenario.removeprefix("load-split-"))
    else:
        fail("unknown scenario")


def run_outer(repo_root, only=None):
    if sys.platform != "linux":
        print("SKIP: Linux namespaces unavailable")
        return 0
    if not shutil.which("unshare") or not shutil.which("mount"):
        print("SKIP: namespace tools unavailable")
        return 0
    probe = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--mount", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if probe.returncode != 0:
        print("SKIP: unprivileged user namespaces unavailable")
        return 0
    phases = tuple(PHASE_VERBS)
    scenarios = (
        ["success"]
        + ["failure-" + phase for phase in phases]
        + [prefix + phase for prefix in ("term-", "kill-") for phase in phases]
        + [
            "source-symlink",
            "source-hardlink",
            "source-race",
            "pre-source",
            "stale-binding",
            "receipt-tamper",
            "unhealthy",
            *["commit-split-" + mode for mode in ("fail", "term", "kill")],
            *["pending-split-" + mode for mode in ("fail", "term", "kill")],
            *["load-split-" + mode for mode in ("fail", "term", "kill")],
        ]
    )
    if only is not None:
        if only not in scenarios:
            fail("unknown selected scenario")
        scenarios = [only]
    completed = []
    for scenario in scenarios:
        # Keep the namespace backing tree outside /tmp because /tmp itself is
        # bind-overlaid by the inner fixture.
        with tempfile.TemporaryDirectory(
            prefix="ingress-guard-fixture-", dir="/var/tmp"
        ) as scratch:
            command = [
                "unshare",
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
                "--mount-proc",
                sys.executable,
                os.fspath(Path(__file__).resolve()),
                "--inner",
                "--repo-root",
                os.fspath(repo_root),
                "--scratch",
                scratch,
                "--scenario",
                scenario,
            ]
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode != 0:
                print(f"FAIL scenario={scenario}", file=sys.stderr)
                print(result.stderr[-4000:], file=sys.stderr)
                return 1
            completed.append(scenario)
    print(
        json.dumps(
            {
                "result": "pass",
                "scenarios": len(completed),
                "failure_phases": len(phases),
                "signal_phases": len(phases) * 2,
                "private_values": "none",
                "live_actions": "none",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--scenario")
    parser.add_argument("--only")
    args = parser.parse_args(argv)
    try:
        if args.inner:
            if args.scratch is None or args.scenario is None:
                fail("inner arguments missing")
            run_inner(args.repo_root, args.scratch, args.scenario)
            return 0
        return run_outer(args.repo_root.resolve(), args.only)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
