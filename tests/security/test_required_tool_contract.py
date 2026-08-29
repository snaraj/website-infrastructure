"""Every module-level tool probe becomes a value through ``required_tool``.

``support.required_tool`` is the fail-closed floor under the ``skipUnless``
guards: the batteries resolve host executables with ``shutil.which`` at module
scope, which leaves a ``str | None`` constant, and a ``None`` that slips past a
lost, moved, or bypassed skip guard would otherwise ride silently into a
subprocess ``argv``. PR #50 routed its own files through the helper and issue
#51 recorded that roughly a dozen sites in other batteries still passed the raw
constant. Some of those were merely confusing (``TypeError`` deep inside
``subprocess``); the ``str(HELM)`` shape was worse, because ``str(None)`` is the
literal string ``"None"`` and the run failed as ``FileNotFoundError: 'None'`` —
a missing tool wearing the costume of a missing file.

This battery is what stops the sweep decaying. It parses every battery module,
finds the module-level constants assigned from a ``shutil.which`` expression,
and reports any of them read as a VALUE without passing through
``required_tool``. Reading one to decide about it — ``if BASH is None``, ``not
GITLEAKS``, ``assertIsNotNone(KUBECTL, ...)`` — is the guard, not the hazard,
and is not reported.

Two scope decisions, both deliberate. The report is not confined to arguments
written inside a ``subprocess`` call: the common style here builds the argv into
a local list and passes the name, so that reading would have missed the very
site that motivated the issue. And it covers MODULE-LEVEL constants only: a
probe made inside a function and immediately checked for ``None`` carries its
guard in the same few lines, and requiring the helper there would convert a host
that legitimately lacks the tool from a skip into a failure.
"""

from __future__ import annotations

import ast
import unittest

from .support import REPO_ROOT

BATTERIES = REPO_ROOT / "tests" / "security"

HELPER = "required_tool"

# No exceptions today. An entry here would have to name the site and say why a
# raw Optional reaching argv is safe there — which is exactly the argument the
# helper exists to make unnecessary.
JUSTIFIED_EXCEPTIONS: dict[str, str] = {}


def _is_which_call(node):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "which"
    )


def _is_helper_call(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == HELPER
    return isinstance(func, ast.Attribute) and func.attr == HELPER


def module_tool_constants(tree):
    """Module-level names bound to a ``shutil.which(...)`` result.

    Both the direct form and the platform-fallback form count, because the
    fallback reassigns the SAME name and leaves it just as Optional::

        BASH = shutil.which("bash")
        if BASH is None and os.name == "nt":
            BASH = str(candidate)
    """

    names = set()

    def collect(statements):
        for node in statements:
            if isinstance(node, ast.If):
                collect(node.body)
                collect(node.orelse)
                continue
            if not isinstance(node, ast.Assign) or node.value is None:
                continue
            if not any(_is_which_call(item) for item in ast.walk(node.value)):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)

    collect(tree.body)
    return names


# Reading the constant to DECIDE something about it — `if BASH is None`,
# `not GITLEAKS`, `KUBECTL or ""`, `skipUnless(HELM, ...)` — is the guard, not
# the hazard. Only a read that flows into a VALUE is reported.
_DECISION_NODES = (ast.Compare, ast.BoolOp, ast.UnaryOp)
# The assertion forms that ask ONLY "is this constant present": the same
# decision `if X is None` makes, written as a test assertion.
_DECISION_ASSERTIONS = frozenset(
    {"assertIsNotNone", "assertIsNone", "assertTrue", "assertFalse"}
)


def _is_decision_assertion(node):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _DECISION_ASSERTIONS
    )


def _collect(node, constants, guarded, findings):
    if (
        _is_helper_call(node)
        or _is_decision_assertion(node)
        or isinstance(node, _DECISION_NODES)
    ):
        guarded = True
    if isinstance(node, ast.Name) and node.id in constants:
        if not guarded:
            findings.append((node.id, node.lineno))
        return
    for child in ast.iter_child_nodes(node):
        _collect(child, constants, guarded, findings)


def unguarded_tool_uses(source, filename="<battery>"):
    """Report ``(constant, line)`` for each raw Optional used as a value.

    Scoping the report to arguments written INSIDE a ``subprocess`` call was
    the obvious shape and it is not enough: the common style here builds the
    argv into a local list first and passes the name, so a raw constant in
    ``command = [str(HELM), "template", ...]`` would be invisible to that
    reading. This walks the body of every function and class instead, and
    treats only the decision contexts above as guards.

    Statements at module scope are skipped: that is where the constants are
    defined and re-bound by the platform fallbacks. ``inspected`` counts the
    bodies walked, so a scan that stops finding code fails its own floor.
    """

    tree = ast.parse(source, filename=filename)
    constants = module_tool_constants(tree)
    if not constants:
        return [], 0
    findings = []
    inspected = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
        elif isinstance(node, ast.ClassDef):
            # Class-body statements that are not methods: a constant copied
            # onto a class attribute reaches argv just as easily.
            body = [
                statement
                for statement in node.body
                if not isinstance(
                    statement, (ast.FunctionDef, ast.AsyncFunctionDef)
                )
            ]
        else:
            continue
        inspected += 1
        for statement in body:
            _collect(statement, constants, False, findings)
    findings.sort(key=lambda entry: (entry[1], entry[0]))
    return findings, inspected


class RequiredToolSweepTests(unittest.TestCase):
    """Issue #51: finish the sweep, and keep it finished."""

    @classmethod
    def setUpClass(cls):
        cls.results = {}
        cls.constants = {}
        cls.inspected = 0
        for path in sorted(BATTERIES.glob("test_*.py")):
            source = path.read_text(encoding="utf-8")
            findings, inspected = unguarded_tool_uses(source, str(path))
            cls.inspected += inspected
            names = module_tool_constants(ast.parse(source, filename=str(path)))
            if names:
                cls.constants[path.name] = sorted(names)
            if findings:
                cls.results[path.name] = findings

    def test_the_sweep_actually_reaches_the_batteries(self):
        """A scan that finds no constants and no calls passes everything."""

        self.assertGreaterEqual(
            len(self.constants),
            10,
            "module-level tool probes were found in {} batteries; the scan is "
            "no longer looking at the tree it audits".format(len(self.constants)),
        )
        self.assertGreaterEqual(self.inspected, 40, self.inspected)

    def test_no_raw_optional_tool_constant_is_used_as_a_value(self):
        offenders = {
            name: findings
            for name, findings in self.results.items()
            if name not in JUSTIFIED_EXCEPTIONS
        }
        self.assertEqual(
            offenders,
            {},
            "each entry is (constant, line): a shutil.which() result is "
            "str | None, so a lost or bypassed skipUnless lets None (or the "
            "string 'None', via str()) into an argv or a Path. Wrap it where "
            "the value is built with support.required_tool(CONSTANT, "
            "DESCRIPTION).",
        )

    def test_every_justification_still_names_a_real_offender(self):
        """A stale exception fails as loudly as a missing check."""

        stale = sorted(set(JUSTIFIED_EXCEPTIONS) - set(self.results))
        self.assertEqual(stale, [], "these justifications no longer apply")

    def test_the_analyzer_reports_the_shapes_it_exists_for(self):
        """Vacuity probe: four known-bad shapes, each reported by line.

        The list-built argv is the one a subprocess-scoped reading misses, and
        it is the shape this repository actually writes — ``render()`` in the
        capacity battery builds ``command`` first and passes the name.
        """

        hostile = (
            "import shutil, subprocess\n"
            "HELM = shutil.which('helm')\n"
            "BASH = shutil.which('bash')\n"
            "if BASH is None:\n"
            "    BASH = 'x'\n"
            "def one():\n"
            "    subprocess.run([str(HELM), 'template'])\n"
            "def two():\n"
            "    subprocess.run([BASH, '-n'])\n"
            "def three():\n"
            "    command = [BASH, '-c', 'true']\n"
            "    subprocess.Popen(command)\n"
            "def four():\n"
            "    return Path(HELM).resolve()\n"
        )
        findings, inspected = unguarded_tool_uses(hostile)
        self.assertEqual(inspected, 4)
        self.assertEqual(
            findings, [("HELM", 7), ("BASH", 9), ("BASH", 11), ("HELM", 14)]
        )

    def test_the_analyzer_treats_a_decision_as_a_guard(self):
        """Reading the constant to decide about it is the guard, not a use."""

        deciding = (
            "import shutil\n"
            "BASH = shutil.which('bash')\n"
            "def one(case):\n"
            "    if BASH is None:\n"
            "        case.skipTest('no bash')\n"
            "    if not BASH:\n"
            "        return None\n"
            "    case.assertIsNotNone(BASH, 'CI must have bash')\n"
            "    return BASH or ''\n"
        )
        findings, _inspected = unguarded_tool_uses(deciding)
        self.assertEqual(findings, [])

    def test_the_analyzer_accepts_the_wrapped_shape(self):
        """The other direction: wrapping must actually clear the finding."""

        compliant = (
            "import shutil, subprocess\n"
            "from .support import required_tool\n"
            "HELM = shutil.which('helm')\n"
            "HELM_REQUIRED = 'helm is required'\n"
            "def one():\n"
            "    subprocess.run([required_tool(HELM, HELM_REQUIRED), 'template'])\n"
        )
        findings, inspected = unguarded_tool_uses(compliant)
        self.assertEqual(inspected, 1)
        self.assertEqual(findings, [])

    def test_a_function_local_probe_is_out_of_scope_by_construction(self):
        """The scope boundary, pinned so it is a decision and not an omission.

        A probe made inside a function and checked there carries its guard in
        the same few lines; requiring the helper there would convert a host
        that legitimately lacks the tool from a skip into a failure.
        """

        local = (
            "import shutil, subprocess\n"
            "def one(case):\n"
            "    bash = shutil.which('bash')\n"
            "    if bash is None:\n"
            "        case.skipTest('bash is unavailable')\n"
            "    subprocess.run([bash, '-n'])\n"
        )
        findings, _inspected = unguarded_tool_uses(local)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
