#!/usr/bin/env python3
"""Render the two-object private connector artifact, without cluster access.

Only the repository's fixed, dependency-free Helm chart is accepted as input.
This is an offline selection of reviewed source, not a general YAML parser,
installer, credential reader, source approval or activation receipt.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHART = Path("kubernetes/platform/cloudflare-public/chart")
NAMESPACE = "cloudflare-public"
REVISION = re.compile(r"rev-[a-z0-9][a-z0-9._-]{0,62}\Z")
OPERATOR = "obsync-private-operator"
INVENTORY = {
    ("v1", "ServiceAccount", "cloudflared"),
    ("apps/v1", "Deployment", "naranjo-online-tunnel"),
    ("apps/v1", "Deployment", "lidersea-com-tunnel"),
    ("apps/v1", "Deployment", "obsync-tunnel"),
    *(('networking.k8s.io/v1', 'NetworkPolicy', name) for name in (
        "cloudflared-dns", "cloudflared-edge", "cloudflared-naranjo-online",
        "cloudflared-lidersea-com", "cloudflared-obsidian",
    )),
}
# Policy first, Deployment last. Neither a shared prerequisite nor a peer is
# emitted; those objects must already be admitted before owner activation.
SELECTED = (
    ("networking.k8s.io/v1", "NetworkPolicy", "cloudflared-obsidian"),
    ("apps/v1", "Deployment", "obsync-tunnel"),
)


def revision(value):
    if not REVISION.fullmatch(value):
        raise ValueError("a resolved canonical token revision is required")
    return value


def select_artifact(rendered, token_revision, part="all"):
    """Require the complete known Helm inventory before selecting any bytes."""
    revision(token_revision)
    if part not in {"all", "policy", "deployment"}:
        raise ValueError("unknown artifact part")
    if not rendered or len(rendered.encode("utf-8")) > 128 * 1024:
        raise ValueError("the fixed chart render is empty or exceeds its bound")
    parsed = {}
    for raw in re.split(r"(?m)^---[ \t]*$", rendered):
        raw = raw.strip()
        if not raw:
            continue
        fields = []
        for pattern in (
            r"(?m)^apiVersion: (\S+)$", r"(?m)^kind: (\S+)$",
            r"(?m)^  name: (\S+)$", r"(?m)^  namespace: (\S+)$",
        ):
            matches = re.findall(pattern, raw)
            if len(matches) != 1:
                raise ValueError("the fixed chart document identity is ambiguous")
            fields.append(matches[0])
        identity = tuple(fields[:3])
        if fields[3] != NAMESPACE or identity in parsed:
            raise ValueError("the fixed chart namespace or inventory is ambiguous")
        parsed[identity] = raw + "\n"
    if set(parsed) != INVENTORY:
        raise ValueError("the fixed chart inventory has changed; review the selector")
    selected = []
    for identity in SELECTED:
        raw = parsed[identity]
        expected = 2 if identity[1] == "Deployment" else 1
        raw, count = re.subn(
            r"(?m)^([ ]+)app.kubernetes.io/managed-by: Helm$",
            rf"\1app.kubernetes.io/managed-by: {OPERATOR}", raw,
        )
        if count != expected:
            raise ValueError("the selected ownership label shape has changed")
        selected.append(raw)
    annotation = f'platform.snaraj.dev/tunnel-token-revision: "{token_revision}"'
    if selected[1].count(annotation) != 1:
        raise ValueError("the selected Deployment lacks its exact token revision")
    if part == "policy":
        selected = selected[:1]
    elif part == "deployment":
        selected = selected[1:]
    return "---\n" + "---\n".join(selected)


def render(token_revision, root=ROOT, part="all"):
    revision(token_revision)
    chart = root / CHART
    if (chart / "Chart.lock").exists() or (
        (chart / "charts").exists() and any((chart / "charts").iterdir())
    ):
        raise ValueError("chart dependencies are not permitted")
    pins = (root / "versions.env").read_text(encoding="utf-8")
    expected = re.findall(r"(?m)^HELM_VERSION=(v[0-9.]+)$", pins)
    actual = subprocess.run(
        ["helm", "version", "--template", "{{.Version}}"],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()
    if expected != [actual]:
        raise ValueError("Helm does not match the repository version pin")
    rendered = subprocess.run(
        ["helm", "template", NAMESPACE, str(chart), "--namespace", NAMESPACE,
         "--set-string", f"connectors.obsync.tokenRevision={token_revision}"],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout
    return select_artifact(rendered, token_revision, part)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-revision", required=True,
                        help="non-secret rev-* identifier; never a token value")
    parser.add_argument("--part", choices=("all", "policy", "deployment"), default="all",
                        help="fixed parts permit policy-first create-only activation")
    args = parser.parse_args(argv)
    try:
        artifact = render(args.token_revision, part=args.part)
    except (ValueError, OSError, subprocess.SubprocessError):
        # No subprocess diagnostics or caller input are printed. Nothing is
        # emitted to stdout until the whole fixed selection succeeds.
        print("private-connector-render: refused; check source, tool pin and revision",
              file=sys.stderr)
        return 1
    sys.stdout.write(artifact)
    return 0


if __name__ == "__main__":
    sys.exit(main())
