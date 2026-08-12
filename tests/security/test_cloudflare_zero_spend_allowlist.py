"""Merge-path zero-spend guard for the Cloudflare phase roots (issue #45).

The owner's invariant is zero infrastructure spend, always. The strong
controls that enforce it — the closed resource-type allowlist in
``infrastructure/cloudflare/policy/cloudflare-plan.rego`` and the pinned
``cloudflare-cost-policy.yaml`` — previously ran only in the offline
apply ceremony, so a pull request adding a paid resource under
``infrastructure/cloudflare/phases/**`` passed CI clean and was caught
only after merge. This battery moves the check onto the merge path: the
CI unittest sweep now statically proves every declared phase resource is
a member of the allowlist *extracted from the rego source* (the rego
stays the single source of truth; this file carries no second copy of
the list) and that the cost policy's zero-spend pins are byte-exact.

Fail-closed by construction: an empty extraction, a missing phase tree,
a JSON-syntax OpenTofu file the text scan cannot see, an unparseable
declaration line, a symlink anywhere under the scanned tree (rglob does
not traverse symlinked directories), or a tracked OpenTofu file outside
the phase roots (where this scan would never look) is a test failure,
never a skip. The deny-path tests prove each failure mode fires on
synthetic bad input instead of trusting that the checkers would.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLOUDFLARE_ROOT = REPO_ROOT / "infrastructure" / "cloudflare"
PHASE_ROOT = CLOUDFLARE_ROOT / "phases"
REGO_PATH = CLOUDFLARE_ROOT / "policy" / "cloudflare-plan.rego"
COST_POLICY_PATH = CLOUDFLARE_ROOT / "policy" / "cloudflare-cost-policy.yaml"

# Pinned extraction shapes for the rego allowlist. ``expected_types`` maps
# every allowed resource address to its type (one level of alias
# indirection for the tunnel type), and ``critical_fields`` keys the same
# closed type set a second time; extracting both and requiring agreement
# means a drifted or half-edited rego fails here instead of widening the
# scan's idea of what is allowed.
_REGO_TYPE_ALIAS = re.compile(r'(?m)^([a-z][a-z0-9_]*) := "(cloudflare_[a-z0-9_]+)"$')
_REGO_EXPECTED_TYPES_BLOCK = re.compile(r"(?ms)^expected_types := \{$(.+?)^\}$")
_REGO_EXPECTED_ENTRY = re.compile(
    r'(?m)^\s+"cloudflare_[a-z0-9_]+\.[a-z0-9_]+": ("cloudflare_[a-z0-9_]+"|[a-z][a-z0-9_]*),$'
)
_REGO_CRITICAL_BLOCK = re.compile(r"(?ms)^critical_fields := \{$(.+?)^\}$")
_REGO_CRITICAL_KEY = re.compile(r'(?m)^\s+"(cloudflare_[a-z0-9_]+)": \{')

# Any line whose first token is ``resource`` or ``module`` must be a
# well-formed block header; anything else in that position is treated as
# an evasion attempt and fails the scan outright.
_DECLARATION_LINE = re.compile(r"^(?:resource|module)\b")
_RESOURCE_BLOCK = re.compile(r'^resource\s+"([a-z0-9_]+)"\s+"[a-z0-9_-]+"\s+\{$')
_MODULE_BLOCK = re.compile(r'^module\s+"([a-z0-9_-]+)"\s+\{$')


def rego_allowed_resource_types(rego_text):
    """Extract the closed resource-type allowlist from the rego source.

    Raises ``AssertionError`` — a hard failure, not a skip — when the
    ``expected_types`` block is missing, resolves to an empty set, uses
    an alias this scan cannot resolve, or disagrees with the
    ``critical_fields`` key set.
    """

    block = _REGO_EXPECTED_TYPES_BLOCK.search(rego_text)
    if block is None:
        raise AssertionError(
            "fail closed: no expected_types block extracted from the rego "
            "allowlist source"
        )
    aliases = dict(_REGO_TYPE_ALIAS.findall(rego_text))
    types = set()
    for value in _REGO_EXPECTED_ENTRY.findall(block.group(1)):
        if value.startswith('"'):
            types.add(value.strip('"'))
        elif value in aliases:
            types.add(aliases[value])
        else:
            raise AssertionError(
                "fail closed: unresolvable rego type alias: " + value
            )
    if not types:
        raise AssertionError(
            "fail closed: the rego expected_types block yielded an empty "
            "resource-type allowlist"
        )
    critical = _REGO_CRITICAL_BLOCK.search(rego_text)
    if critical is None:
        raise AssertionError(
            "fail closed: no critical_fields block extracted from the rego "
            "allowlist source"
        )
    critical_keys = set(_REGO_CRITICAL_KEY.findall(critical.group(1)))
    if types != critical_keys:
        raise AssertionError(
            "fail closed: expected_types and critical_fields disagree on "
            "the allowed resource types: {} != {}".format(
                sorted(types), sorted(critical_keys)
            )
        )
    return frozenset(types)


def scan_phase_declarations(phase_root):
    """Return ``(resources, modules)`` declared under one phase tree.

    Each entry is ``(path, line_number, name)``. Raises
    ``AssertionError`` when a symlink appears anywhere under the tree
    (``rglob`` does not traverse symlinked directories, so content
    could hide behind one), when no OpenTofu file exists at all, when a
    JSON-syntax variant could hide declarations from this text scan, or
    when a ``resource``/``module`` line is not a well-formed block
    header.
    """

    root = Path(phase_root)
    symlinks = sorted(
        str(path) for path in [root, *root.rglob("*")] if path.is_symlink()
    )
    if symlinks:
        raise AssertionError(
            "fail closed: symlinks are forbidden under the scanned phase "
            "tree (a symlinked directory is not traversed and a symlinked "
            "file points out of scope): " + ", ".join(symlinks)
        )
    json_syntax = sorted(
        str(path)
        for path in root.rglob("*")
        if path.is_file() and path.name.endswith((".tf.json", ".tofu.json"))
    )
    if json_syntax:
        raise AssertionError(
            "fail closed: JSON-syntax OpenTofu files evade the text scan: "
            + ", ".join(json_syntax)
        )
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".tf", ".tofu"}
    )
    if not files:
        raise AssertionError(
            "fail closed: no OpenTofu phase files found under " + str(root)
        )
    resources = []
    modules = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise AssertionError(
                "fail closed: unreadable phase file {}: {}".format(path, error)
            )
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not _DECLARATION_LINE.match(stripped):
                continue
            resource = _RESOURCE_BLOCK.match(stripped)
            if resource is not None:
                resources.append((path, number, resource.group(1)))
                continue
            module = _MODULE_BLOCK.match(stripped)
            if module is not None:
                modules.append((path, number, module.group(1)))
                continue
            raise AssertionError(
                "fail closed: unparseable resource/module declaration at "
                "{}:{}: {!r}".format(path, number, stripped)
            )
    return resources, modules


def allowlist_violations(resources, modules, allowed_types):
    """Judge one scan result against the extracted rego allowlist.

    Module calls are violations unconditionally: the rego denies every
    module call (``configured_module_calls``) and carries no allowlist
    that could admit one, and the premise is itself pinned by the tests
    below.
    """

    violations = [
        "module call is forbidden in closed Cloudflare roots: "
        "{}:{} {}".format(path, number, name)
        for path, number, name in modules
    ]
    violations.extend(
        "resource type is outside the rego allowlist: {}:{} {}".format(
            path, number, resource_type
        )
        for path, number, resource_type in resources
        if resource_type not in allowed_types
    )
    return violations


def cost_policy_violations(cost_policy_text):
    """Return every broken zero-spend pin in the cost policy text.

    Each pinned key must appear exactly once and byte-equal to the pin
    (indentation included), so a value edit, a deletion, a duplicate
    contradicting entry, or a re-nesting all fail loudly.
    """

    pins = (
        ("defaultDecision", "defaultDecision: deny"),
        ("infrastructureCostUsd", "infrastructureCostUsd: 0"),
        ("maximumManagedResourceCount", "  maximumManagedResourceCount: 21"),
    )
    lines = cost_policy_text.splitlines()
    violations = []
    for key, pinned_line in pins:
        declaring = [
            line for line in lines if re.match(r"^\s*{}:".format(key), line)
        ]
        if declaring != [pinned_line]:
            violations.append(
                "cost-policy pin broken for {}: expected exactly {!r}, "
                "found {!r}".format(key, pinned_line, declaring)
            )
    return violations


# The one tree the phase scan reads. A tracked OpenTofu file anywhere
# else in the repository would sit outside this battery's sight and
# outside the seven roots the offline ceremony plans, so its existence
# is itself a violation.
PHASE_TREE_PREFIX = "infrastructure/cloudflare/phases/"


def tracked_tofu_paths(repo_root):
    """Return every tracked OpenTofu-syntax path, failing closed on git."""

    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "ls-files",
            "-z",
            "--",
            "*.tf",
            "*.tf.json",
            "*.tofu",
            "*.tofu.json",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            "fail closed: git ls-files could not enumerate the OpenTofu "
            "inventory: " + result.stderr.strip()
        )
    return sorted(entry for entry in result.stdout.split("\0") if entry)


def tofu_inventory_violations(tracked_paths):
    """Judge the tracked OpenTofu inventory against the phase-tree scope.

    Raises ``AssertionError`` when the inventory holds nothing under the
    phase tree at all — an empty inventory means the enumeration (or
    the tree) is broken, and must never read as a clean pass.
    """

    if not any(path.startswith(PHASE_TREE_PREFIX) for path in tracked_paths):
        raise AssertionError(
            "fail closed: the tracked OpenTofu inventory holds nothing "
            "under " + PHASE_TREE_PREFIX
        )
    return [
        "tracked OpenTofu file outside the guarded phase roots: " + path
        for path in tracked_paths
        if not path.startswith(PHASE_TREE_PREFIX)
    ]


def single_pinned_integer(cost_policy_text, key):
    """Extract one integer pin from the cost policy, failing closed."""

    matches = re.findall(
        r"(?m)^\s*{}:\s*(\d+)\s*$".format(key), cost_policy_text
    )
    if len(matches) != 1:
        raise AssertionError(
            "fail closed: expected exactly one {} pin, found {}".format(
                key, len(matches)
            )
        )
    return int(matches[0])


class CloudflareZeroSpendAllowlistTests(unittest.TestCase):
    """Prove the committed phase roots cannot leave the zero-cost set."""

    @classmethod
    def setUpClass(cls):
        cls.rego = REGO_PATH.read_text(encoding="utf-8")
        cls.cost_policy = COST_POLICY_PATH.read_text(encoding="utf-8")
        cls.allowed_types = rego_allowed_resource_types(cls.rego)

    def test_rego_extraction_yields_the_closed_six_type_allowlist(self):
        """The extraction must produce the documented closed set shape.

        Six, not five: the two website roots carry ``cloudflare_zone_setting``
        for the zone security target state. It is a free zone-level control on
        every Cloudflare plan, so the zero-cost boundary is unchanged; the
        count is pinned here so a seventh type cannot arrive unnoticed.
        """

        self.assertEqual(len(self.allowed_types), 6)
        for resource_type in self.allowed_types:
            with self.subTest(resource_type=resource_type):
                self.assertRegex(resource_type, r"^cloudflare_[a-z0-9_]+$")

    def test_rego_still_denies_every_module_call(self):
        """Pin the premise that no module allowlist exists in the rego."""

        self.assertIn("count(configured_module_calls) != 0", self.rego)
        self.assertIn(
            "module calls are forbidden in closed Cloudflare roots", self.rego
        )

    def test_phase_tree_matches_the_pinned_independent_root_count(self):
        """The phase inventory itself is covered by the cost policy pin."""

        expected_roots = single_pinned_integer(
            self.cost_policy, "requiredIndependentRootCount"
        )
        phase_directories = sorted(
            path for path in PHASE_ROOT.iterdir() if path.is_dir()
        )
        self.assertEqual(len(phase_directories), expected_roots)
        for directory in phase_directories:
            with self.subTest(phase=directory.name):
                self.assertTrue(
                    any(directory.glob("*.tf")),
                    "phase root without OpenTofu files: " + str(directory),
                )

    def test_every_phase_resource_type_is_in_the_rego_allowlist(self):
        """A paid product under phases/** must fail CI, not the ceremony."""

        resources, modules = scan_phase_declarations(PHASE_ROOT)
        self.assertEqual(allowlist_violations(resources, modules, self.allowed_types), [])
        self.assertGreaterEqual(
            len(resources), 1, "fail closed: phase scan found no resources"
        )
        ceiling = single_pinned_integer(
            self.cost_policy, "maximumManagedResourceCount"
        )
        self.assertLessEqual(len(resources), ceiling)

    def test_cost_policy_zero_spend_pins_are_exact(self):
        """deny / 0 USD / resource ceiling must survive byte-for-byte."""

        self.assertEqual(cost_policy_violations(self.cost_policy), [])

    def test_the_zone_setting_type_is_the_only_allowlist_growth(self):
        """Name the exact closed set so a silent widening fails here."""

        self.assertEqual(
            self.allowed_types,
            frozenset({
                "cloudflare_dns_record",
                "cloudflare_zero_trust_gateway_policy",
                "cloudflare_zero_trust_tunnel_cloudflared",
                "cloudflare_zero_trust_tunnel_cloudflared_config",
                "cloudflare_zero_trust_tunnel_cloudflared_route",
                "cloudflare_zone_setting",
            }),
        )

    def test_no_tracked_opentofu_file_exists_outside_the_phase_roots(self):
        """Out-of-tree resources must not be able to dodge the scanner."""

        self.assertEqual(
            tofu_inventory_violations(tracked_tofu_paths(REPO_ROOT)), []
        )


class CloudflareZeroSpendDenyPathTests(unittest.TestCase):
    """Prove each checker actually fails on bad input, hermetically."""

    @classmethod
    def setUpClass(cls):
        cls.rego = REGO_PATH.read_text(encoding="utf-8")
        cls.cost_policy = COST_POLICY_PATH.read_text(encoding="utf-8")
        cls.allowed_types = rego_allowed_resource_types(cls.rego)

    def _scan_synthetic(self, name, content):
        with tempfile.TemporaryDirectory() as directory:
            phase = Path(directory) / "phases" / "synthetic"
            phase.mkdir(parents=True)
            (phase / name).write_text(content, encoding="utf-8")
            return scan_phase_declarations(Path(directory) / "phases")

    def test_paid_resource_type_is_a_violation(self):
        """The exact regression from the finding: an R2 bucket in a phase."""

        resources, modules = self._scan_synthetic(
            "main.tf",
            'resource "cloudflare_r2_bucket" "spend" {\n'
            "  account_id = var.cloudflare_account_id\n"
            "}\n",
        )
        violations = allowlist_violations(resources, modules, self.allowed_types)
        self.assertEqual(len(violations), 1)
        self.assertIn("cloudflare_r2_bucket", violations[0])

    def test_module_call_is_a_violation(self):
        """Modules could smuggle arbitrary resources past a type scan."""

        resources, modules = self._scan_synthetic(
            "main.tf",
            'module "spend" {\n  source = "./anything"\n}\n',
        )
        violations = allowlist_violations(resources, modules, self.allowed_types)
        self.assertEqual(len(violations), 1)
        self.assertIn("module call is forbidden", violations[0])

    def test_empty_phase_tree_fails_closed(self):
        """Zero scanned files must never read as a clean pass."""

        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "phases"
            empty.mkdir()
            with self.assertRaisesRegex(AssertionError, "no OpenTofu phase files"):
                scan_phase_declarations(empty)

    def test_json_syntax_phase_file_fails_closed(self):
        """A .tf.json file would hide declarations from the text scan."""

        with tempfile.TemporaryDirectory() as directory:
            phase = Path(directory) / "phases" / "synthetic"
            phase.mkdir(parents=True)
            (phase / "main.tf").write_text("", encoding="utf-8")
            (phase / "extra.tf.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "JSON-syntax"):
                scan_phase_declarations(Path(directory) / "phases")

    def test_malformed_declaration_fails_closed(self):
        """An unparseable resource header is a failure, not a skip."""

        with self.assertRaisesRegex(AssertionError, "unparseable"):
            self._scan_synthetic(
                "main.tf", 'resource "cloudflare_dns_record" unnamed {\n'
            )

    def test_undecodable_phase_file_fails_closed(self):
        """Bytes the scan cannot read must fail rather than pass silently."""

        with tempfile.TemporaryDirectory() as directory:
            phase = Path(directory) / "phases" / "synthetic"
            phase.mkdir(parents=True)
            (phase / "main.tf").write_bytes(b"\xff\xfe\x00resource")
            with self.assertRaisesRegex(AssertionError, "unreadable phase file"):
                scan_phase_declarations(Path(directory) / "phases")

    def test_symlinked_phase_directory_fails_closed(self):
        """A symlinked subdirectory is not traversed, so it is forbidden.

        Reviewer probe m4: a symlinked subdir whose paid .tf rglob would
        silently skip. The scan must fail on the symlink itself.
        """

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            hidden = base / "hidden"
            hidden.mkdir()
            (hidden / "main.tf").write_text(
                'resource "cloudflare_r2_bucket" "spend" {\n}\n',
                encoding="utf-8",
            )
            phases = base / "phases"
            phases.mkdir()
            (phases / "honest").mkdir()
            (phases / "honest" / "main.tf").write_text("", encoding="utf-8")
            try:
                (phases / "synthetic").symlink_to(
                    hidden, target_is_directory=True
                )
            except OSError as error:
                self.skipTest("cannot create symlinks here: " + str(error))
            with self.assertRaisesRegex(AssertionError, "symlink"):
                scan_phase_declarations(phases)

    def test_out_of_tree_opentofu_files_are_violations(self):
        """Both plain and JSON-syntax files outside phases/** must fail."""

        violations = tofu_inventory_violations(
            [
                PHASE_TREE_PREFIX + "admin-tunnel/main.tf",
                "websites/spend/main.tf",
                "kubernetes/sneaky.tf.json",
            ]
        )
        self.assertEqual(len(violations), 2)
        self.assertTrue(
            any("websites/spend/main.tf" in item for item in violations)
        )
        self.assertTrue(
            any("kubernetes/sneaky.tf.json" in item for item in violations)
        )

    def test_empty_opentofu_inventory_fails_closed(self):
        """A broken enumeration must never read as a clean pass."""

        with self.assertRaisesRegex(AssertionError, "holds nothing"):
            tofu_inventory_violations([])
        with self.assertRaisesRegex(AssertionError, "holds nothing"):
            tofu_inventory_violations(["kubernetes/sneaky.tf.json"])

    def test_rego_without_an_allowlist_fails_closed(self):
        """Empty extraction is the canonical fail-closed case."""

        with self.assertRaisesRegex(AssertionError, "no expected_types"):
            rego_allowed_resource_types("package main\n")

    def test_rego_with_unresolvable_alias_fails_closed(self):
        """An alias the extraction cannot resolve must not vanish silently."""

        synthetic = (
            "expected_types := {\n"
            '  "phase": {\n'
            '    "cloudflare_dns_record.example": mystery_alias,\n'
            "  },\n"
            "}\n"
        )
        with self.assertRaisesRegex(AssertionError, "unresolvable"):
            rego_allowed_resource_types(synthetic)

    def test_rego_with_internal_disagreement_fails_closed(self):
        """expected_types and critical_fields must stay one closed set."""

        mutated = self.rego.replace(
            '  "cloudflare_dns_record": {"zone_id", "name", "type", '
            '"content", "proxied", "ttl"},\n',
            "",
        )
        self.assertNotEqual(mutated, self.rego)
        with self.assertRaisesRegex(AssertionError, "disagree"):
            rego_allowed_resource_types(mutated)

    def test_each_cost_policy_pin_edit_fails_loudly(self):
        """Every guarded key edit must surface as a broken pin."""

        mutations = (
            ("defaultDecision: deny", "defaultDecision: allow"),
            ("infrastructureCostUsd: 0", "infrastructureCostUsd: 1"),
            (
                "  maximumManagedResourceCount: 21",
                "  maximumManagedResourceCount: 22",
            ),
            ("defaultDecision: deny", ""),
            (
                "defaultDecision: deny",
                "defaultDecision: deny\ndefaultDecision: allow",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(replacement=replacement or "<deleted>"):
                mutated = self.cost_policy.replace(original, replacement)
                self.assertNotEqual(mutated, self.cost_policy)
                self.assertNotEqual(cost_policy_violations(mutated), [])


if __name__ == "__main__":
    unittest.main()
