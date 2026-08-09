"""Exercise safe mixed GitOps release-state transitions."""

import contextlib
import importlib.util
import io
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_release_transition.py"
SPEC = importlib.util.spec_from_file_location("validate_release_transition", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("release transition validator could not be loaded")
TRANSITION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSITION)

RELEASE_FILES = (
    ".sops.yaml",
    "kubernetes/websites/naranjo-online/release.yaml",
    "kubernetes/reconciliation/naranjo-online.yaml",
    "kubernetes/websites/lidersea-com/release.yaml",
    "kubernetes/reconciliation/lidersea-com.yaml",
    "kubernetes/platform/cloudflare-public/release/release.yaml",
    "kubernetes/platform/cloudflare-public/release/kustomization.yaml",
    "kubernetes/reconciliation/platform-services.yaml",
    "kubernetes/reconciliation/admission.yaml",
) + tuple(
    path.as_posix()
    for path in sorted(TRANSITION.CLOUDFLARE_TERRAFORM_SOURCE_FILES)
)
SYNTHETIC_RECIPIENT = (
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp5hcal"
)
SITE_FILES = {
    "naranjo-online": (
        "kubernetes/websites/naranjo-online/release.yaml",
        "kubernetes/reconciliation/naranjo-online.yaml",
        "1",
    ),
    "lidersea-com": (
        "kubernetes/websites/lidersea-com/release.yaml",
        "kubernetes/reconciliation/lidersea-com.yaml",
        "2",
    ),
}


class ReleaseTransitionTests(unittest.TestCase):
    """Reject unsafe mixtures while allowing staged promotion and rollback."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in RELEASE_FILES:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / relative, destination)

    def tearDown(self):
        self.temporary.cleanup()

    def replace_once(self, relative, before, after):
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(before), 1, relative)
        with path.open("w", encoding="utf-8", newline="\n") as output:
            output.write(text.replace(before, after))

    def set_suspended(self, relative, suspended):
        before = "  suspend: false\n" if suspended else "  suspend: true\n"
        after = "  suspend: true\n" if suspended else "  suspend: false\n"
        self.replace_once(relative, before, after)

    def promote_site(self, name):
        release, _, digit = SITE_FILES[name]
        self.replace_once(
            release, "    deploymentReady: false\n", "    deploymentReady: true\n"
        )
        self.replace_once(
            release,
            "      digest: {}\n".format(TRANSITION.STATE.ZERO_DIGEST),
            "      digest: sha256:{}\n".format(digit * 64),
        )

    def activate_site(self, name):
        release, parent, _ = SITE_FILES[name]
        self.promote_site(name)
        self.set_suspended(release, False)
        self.set_suspended(parent, False)

    def configure_cloudflare_revision(self):
        self.replace_once(
            "kubernetes/platform/cloudflare-public/release/release.yaml",
            "      tokenRevision: not-configured\n",
            "      tokenRevision: rev-reviewed-test\n",
        )

    def write_cloudflare_secret(self, *, listed=True, recipient=None):
        if recipient is None:
            recipient = SYNTHETIC_RECIPIENT
        self.root.joinpath(".sops.yaml").write_bytes((
            "creation_rules:\n"
            "  - path_regex: ^kubernetes/.+\\.sops\\.ya?ml$\n"
            "    encrypted_regex: ^(data|stringData)$\n"
            "    age:\n"
            "      - {}\n".format(recipient)
        ).encode("utf-8"))
        secret = self.root / TRANSITION.CLOUDFLARE_TUNNEL_SECRET
        secret.write_bytes((
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: pi-websites-tunnel-token\n"
            "  namespace: cloudflare-public\n"
            "type: Opaque\n"
            "data:\n"
            "  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n"
            "sops:\n"
            "  age:\n"
            "    - recipient: {}\n"
            "      enc: |\n"
            "        -----BEGIN AGE ENCRYPTED FILE-----\n"
            "        synthetic-test-ciphertext\n"
            "        -----END AGE ENCRYPTED FILE-----\n"
            "  mac: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n".format(recipient)
        ).encode("utf-8"))
        if listed:
            self.replace_once(
                TRANSITION.CLOUDFLARE_RELEASE_KUSTOMIZATION,
                "  # Add tunnel-token.sops.yaml only after the user-run encryption ceremony.\n",
                "  - tunnel-token.sops.yaml\n",
            )

    def configure_cloudflare(self):
        self.configure_cloudflare_revision()
        self.write_cloudflare_secret()

    def activate_admission_and_platform(self):
        self.set_suspended("kubernetes/reconciliation/admission.yaml", False)
        self.set_suspended(
            "kubernetes/reconciliation/platform-services.yaml", False
        )

    def make_full_release(self):
        self.activate_admission_and_platform()
        for site in SITE_FILES:
            self.activate_site(site)
        self.configure_cloudflare()
        self.set_suspended(
            "kubernetes/platform/cloudflare-public/release/release.yaml", False
        )

    def test_exact_initial_state_is_scaffold(self):
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "scaffold")
        self.assertEqual(
            (plan.naranjo_online, plan.lidersea_com, plan.cloudflare_public),
            ("initial", "initial", "initial"),
        )
        self.assertFalse(plan.any_website_active)

    def test_single_promoted_suspended_site_is_safe_transition(self):
        self.promote_site("naranjo-online")
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.naranjo_online, "staged")
        self.assertEqual(plan.lidersea_com, "initial")

    def test_initial_site_with_active_parent_is_transition_not_scaffold(self):
        """An outer-only resume step must never be mislabeled fully inert."""

        _, parent, _ = SITE_FILES["naranjo-online"]
        self.set_suspended(parent, False)
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.naranjo_online, "initial")
        self.assertTrue(plan.any_website_active)
        self.assertTrue(plan.any_workload_active)

    def test_complete_active_state_is_release(self):
        self.make_full_release()
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "release")
        self.assertTrue(plan.any_website_active)

    def test_suspending_one_promoted_site_from_release_is_safe_transition(self):
        self.make_full_release()
        release, parent, _ = SITE_FILES["naranjo-online"]
        self.set_suspended(release, True)
        self.set_suspended(parent, True)
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.naranjo_online, "staged")
        self.assertEqual(plan.lidersea_com, "active")

    def test_rollback_suspends_inner_release_before_parent(self):
        """The parent must remain active long enough to apply HR suspension."""

        self.make_full_release()
        release, parent, _ = SITE_FILES["naranjo-online"]
        self.set_suspended(release, True)
        intermediate = TRANSITION.classify(self.root)
        self.assertEqual(intermediate.mode, "transition")
        self.assertEqual(intermediate.naranjo_online, "staged")
        self.assertFalse(intermediate.naranjo_parent_suspended)
        self.assertTrue(intermediate.any_website_active)

        self.set_suspended(parent, True)
        frozen = TRANSITION.classify(self.root)
        self.assertEqual(frozen.mode, "transition")
        self.assertEqual(frozen.naranjo_online, "staged")

    def test_resume_activates_parent_before_inner_release(self):
        """A staged digest remains inert while its parent is resumed first."""

        self.make_full_release()
        release, parent, _ = SITE_FILES["naranjo-online"]
        self.set_suspended(release, True)
        self.set_suspended(parent, True)

        self.set_suspended(parent, False)
        intermediate = TRANSITION.classify(self.root)
        self.assertEqual(intermediate.mode, "transition")
        self.assertEqual(intermediate.naranjo_online, "staged")
        self.assertFalse(intermediate.naranjo_parent_suspended)
        self.assertTrue(intermediate.any_website_active)

        self.set_suspended(release, False)
        resumed = TRANSITION.classify(self.root)
        self.assertEqual(resumed.mode, "release")

    def test_unsuspended_sentinel_site_is_rejected(self):
        release, parent, _ = SITE_FILES["naranjo-online"]
        self.set_suspended(release, False)
        self.set_suspended(parent, False)
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_active_release_below_suspended_parent_is_rejected(self):
        release, _, _ = SITE_FILES["naranjo-online"]
        self.set_suspended(release, False)
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_active_unresolved_tunnel_is_rejected(self):
        self.activate_admission_and_platform()
        self.set_suspended(
            "kubernetes/platform/cloudflare-public/release/release.yaml", False
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_configured_revision_without_encrypted_secret_is_rejected(self):
        self.configure_cloudflare_revision()
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_listed_tunnel_secret_must_exist(self):
        self.configure_cloudflare_revision()
        self.replace_once(
            TRANSITION.CLOUDFLARE_RELEASE_KUSTOMIZATION,
            "  # Add tunnel-token.sops.yaml only after the user-run encryption ceremony.\n",
            "  - tunnel-token.sops.yaml\n",
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_present_tunnel_secret_must_be_listed(self):
        self.configure_cloudflare_revision()
        self.write_cloudflare_secret(listed=False)
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_tunnel_secret_recipient_must_match_sops_configuration(self):
        self.configure_cloudflare_revision()
        self.write_cloudflare_secret()
        secret = self.root / TRANSITION.CLOUDFLARE_TUNNEL_SECRET
        secret.write_bytes(
            secret.read_text(encoding="utf-8").replace(
                "recipient: {}".format(SYNTHETIC_RECIPIENT),
                "recipient: age1mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm",
            ).encode("utf-8")
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_tunnel_secret_token_must_remain_sops_ciphertext(self):
        self.configure_cloudflare_revision()
        self.write_cloudflare_secret()
        secret = self.root / TRANSITION.CLOUDFLARE_TUNNEL_SECRET
        secret.write_bytes(
            secret.read_bytes().replace(
                b"ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]",
                b"plaintext-token",
                1,
            )
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_tunnel_secret_rejects_quoted_kind_key(self):
        self.configure_cloudflare_revision()
        self.write_cloudflare_secret()
        secret = self.root / TRANSITION.CLOUDFLARE_TUNNEL_SECRET
        secret.write_bytes(
            secret.read_bytes().replace(b"kind: Secret\n", b'"kind": Secret\n', 1)
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_tunnel_secret_rejects_quoted_plaintext_string_data_override(self):
        self.configure_cloudflare_revision()
        self.write_cloudflare_secret()
        secret = self.root / TRANSITION.CLOUDFLARE_TUNNEL_SECRET
        secret.write_bytes(
            secret.read_bytes().replace(
                b"sops:\n",
                b'"stringData":\n  token: plaintext-override\nsops:\n',
                1,
            )
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_unresolved_revision_must_not_have_a_staged_secret(self):
        self.write_cloudflare_secret()
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_cloudflare_resource_switch_must_remain_exactly_false(self):
        self.replace_once(
            TRANSITION.CLOUDFLARE_VARIABLES,
            "  default     = false\n",
            "  default     = true\n",
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_cloudflare_local_switch_must_remain_exactly_wired(self):
        self.replace_once(
            TRANSITION.CLOUDFLARE_LOCALS,
            "  enabled = var.enable_cloudflare_resources ? 1 : 0\n",
            "  enabled = 1\n",
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_every_cloudflare_resource_must_use_the_default_off_switch(self):
        self.replace_once(
            "infrastructure/cloudflare/dns.tf",
            'resource "cloudflare_zero_trust_tunnel_cloudflared_config" "pi_websites" {\n'
            "  count = local.enabled\n",
            'resource "cloudflare_zero_trust_tunnel_cloudflared_config" "pi_websites" {\n'
            "  count = 1\n",
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_cloudflare_resource_identity_inventory_is_closed(self):
        path = self.root / "infrastructure/cloudflare/dns.tf"
        with path.open("a", encoding="utf-8", newline="\n") as output:
            output.write(
                '\nresource "cloudflare_dns_record" "unexpected" {\n'
                "  count = local.enabled\n"
                "}\n"
            )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_active_site_requires_active_admission(self):
        self.activate_site("naranjo-online")
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_active_site_requires_active_platform_services(self):
        self.set_suspended("kubernetes/reconciliation/admission.yaml", False)
        self.activate_site("naranjo-online")
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_active_platform_with_suspended_connector_is_allowed(self):
        self.activate_admission_and_platform()
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.cloudflare_public, "initial")
        self.assertTrue(plan.any_workload_active)

    def test_active_admission_alone_enters_the_workload_safety_envelope(self):
        self.set_suspended("kubernetes/reconciliation/admission.yaml", False)
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertTrue(plan.any_workload_active)

    def test_active_connector_without_active_site_is_a_workload_transition(self):
        self.activate_admission_and_platform()
        self.configure_cloudflare()
        self.set_suspended(
            "kubernetes/platform/cloudflare-public/release/release.yaml", False
        )
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.cloudflare_public, "active")
        self.assertFalse(plan.any_website_active)
        self.assertTrue(plan.any_workload_active)

    def test_extra_admission_field_is_rejected(self):
        self.replace_once(
            "kubernetes/reconciliation/admission.yaml",
            "  wait: true\n",
            "  wait: true\n  unexpected: false\n",
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_cli_failure_is_generic_and_does_not_disclose_paths(self):
        release, _, _ = SITE_FILES["naranjo-online"]
        self.set_suspended(release, False)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = TRANSITION.main(
                ["--root", str(self.root), "select-mode"]
            )
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "ERROR release transition state is unavailable or unsafe\n",
        )
        self.assertNotIn(str(self.root), stderr.getvalue())

    def test_plan_requires_the_selected_mode_and_has_fixed_shape(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = TRANSITION.main(
                ["--root", str(self.root), "plan", "--expect-mode", "scaffold"]
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            stdout.getvalue().splitlines(),
            [
                "mode=scaffold",
                "naranjo-online=initial",
                "lidersea-com=initial",
                "cloudflare-public=initial",
                "any-website-active=false",
                "any-workload-active=false",
            ],
        )


if __name__ == "__main__":
    unittest.main()
