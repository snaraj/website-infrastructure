import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "test-kind.sh"
RELEASE_GATE = REPO_ROOT / "scripts" / "release-gate.sh"
LOCAL_KIND_RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "local-kind.md"


def function_body(script, name, next_name):
    start = script.index("{}() {{".format(name))
    end = script.index("{}() {{".format(next_name), start)
    return script[start:end]


class KindReleaseValuesContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.render = function_body(
            cls.script, "render_local_artifacts", "assert_release_sentinels"
        )
        cls.detect = function_body(
            cls.script, "detect_repository_release_mode", "write_kind_config"
        )
        cls.runtime = function_body(
            cls.script, "render_runtime_sites", "assert_service_ready"
        )
        cls.exercise = function_body(
            cls.script, "exercise_runtime_sites", "exercise_transition_runtime_site"
        )
        cls.transition_render = function_body(
            cls.script,
            "render_transition_runtime_site",
            "revalidate_transition_runtime_state",
        )
        cls.transition_revalidate = function_body(
            cls.script,
            "revalidate_transition_runtime_state",
            "write_disposable_capacity_gates",
        )
        cls.transition_inventory = function_body(
            cls.script,
            "validate_transition_render_inventory",
            "normalize_namespace_inventory",
        )
        cls.transition_namespace_contract = function_body(
            cls.script,
            "normalize_namespace_inventory",
            "revalidate_transition_runtime_state",
        )
        cls.transition_exercise = function_body(
            cls.script, "exercise_transition_runtime_site", "exercise_cluster"
        )
        cls.cluster = function_body(cls.script, "exercise_cluster", "usage")
        cls.cleanup = function_body(cls.script, "cleanup", "require_command")
        cls.network_identity = function_body(
            cls.script, "docker_network_identity", "assert_owned_docker_network"
        )
        cls.network_create = function_body(
            cls.script, "create_owned_docker_network", "assert_owned_node_network"
        )
        cls.network_attachment = function_body(
            cls.script, "assert_owned_node_network", "cleanup"
        )
        cls.prerequisites = function_body(
            cls.script, "check_prerequisites", "run_canonical_transition_static_gate"
        )
        cls.transition_static_gate = function_body(
            cls.script, "run_canonical_transition_static_gate", "new_temp_file"
        )
        cls.readiness = function_body(
            cls.script, "assert_service_ready", "exercise_runtime_sites"
        )
        program_start = cls.transition_inventory.index("from pathlib import Path\n")
        program_end = cls.transition_inventory.index("\nPY\n", program_start)
        cls.transition_inventory_program = cls.transition_inventory[
            program_start:program_end
        ]
        cls.release_gate = RELEASE_GATE.read_text(encoding="utf-8")
        cls.local_kind_runbook = LOCAL_KIND_RUNBOOK.read_text(encoding="utf-8")

    @staticmethod
    def canonical_transition_render(site="naranjo-online"):
        network_policy = "cloudflared-to-{}".format(site)
        documents = (
            (
                "networking.k8s.io/v1",
                "NetworkPolicy",
                network_policy,
                "spec:\n  podSelector: {}\n",
            ),
            ("v1", "Service", site, "spec:\n  type: ClusterIP\n"),
            (
                "v1",
                "ServiceAccount",
                site,
                "automountServiceAccountToken: false\n",
            ),
            ("apps/v1", "Deployment", site, "spec:\n  replicas: 2\n"),
        )
        return "".join(
            "---\n"
            "# Source: test/{kind}.yaml\n"
            "apiVersion: {api_version}\n"
            "kind: {kind}\n"
            "metadata:\n"
            "  name: {name}\n"
            "  namespace: {site}\n"
            "{tail}".format(
                api_version=api_version,
                kind=kind,
                name=name,
                site=site,
                tail=tail,
            )
            for api_version, kind, name, tail in documents
        )

    def run_transition_inventory(self, manifest, site="naranjo-online"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "render.yaml"
            with path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(manifest)
            return subprocess.run(
                [sys.executable, "-B", "-", str(path), site],
                input=self.transition_inventory_program,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_release_render_uses_strict_authoritative_values_for_each_release(self):
        self.assertIn("if [[ \"$repository_release_mode\" == 'release' ]]", self.render)
        for release, variable, argument_array in (
            (
                "naranjo-online",
                "naranjo_release_values_path",
                "naranjo_helm_values_args",
            ),
            (
                "lidersea-com",
                "lidersea_release_values_path",
                "lidersea_helm_values_args",
            ),
            (
                "cloudflare-public",
                "cloudflare_release_values_path",
                "cloudflare_helm_values_args",
            ),
        ):
            with self.subTest(release=release):
                self.assertIn(
                    'validate_release_state.py\" emit-values \\\n'
                    "      --release {}".format(release),
                    self.render,
                )
                self.assertIn('--values \"${{{}}}\"'.format(variable), self.render)
                self.assertEqual(
                    self.render.count('\"${' + argument_array + '[@]}\"'),
                    2,
                    "the same effective values must reach Helm lint and template",
                )

    def test_active_detection_never_reads_inert_chart_readiness_or_digest(self):
        active_branch = self.detect.split(
            "elif (( active == 7 && suspended == 0 )); then", 1
        )[1].split("else", 1)[0]
        self.assertIn("repository_release_mode='release'", active_branch)
        self.assertNotIn("chart/values.yaml", active_branch)
        self.assertNotIn("deploymentReady", active_branch)
        self.assertNotIn("sha256:0", active_branch)

    def test_scaffold_keeps_empty_helm_overrides_and_exact_sentinel_checks(self):
        before_release_values = self.render.split(
            "if [[ \"$repository_release_mode\" == 'release' ]]", 1
        )[0]
        self.assertNotIn("emit-values", before_release_values)
        for argument_array in (
            "naranjo_helm_values_args",
            "lidersea_helm_values_args",
            "cloudflare_helm_values_args",
        ):
            with self.subTest(argument_array=argument_array):
                self.assertIn(
                    "local -a {}=()".format(argument_array), before_release_values
                )

        scaffold_branch = self.detect.split(
            "if (( suspended == 7 && active == 0 )); then", 1
        )[1].split("elif", 1)[0]
        self.assertIn("repository_release_mode='scaffold'", scaffold_branch)
        self.assertIn("assert_release_sentinels", scaffold_branch)

    def test_runtime_release_path_reuses_effective_values_and_only_overrides_pull(self):
        release_branch, scaffold_branch = self.runtime.split("  else\n", 1)
        for variable in (
            "naranjo_release_values_path",
            "lidersea_release_values_path",
        ):
            with self.subTest(variable=variable):
                self.assertIn('--values \"${}\"'.format(variable), release_branch)
        self.assertNotIn("--set deploymentReady=true", release_branch)
        self.assertNotIn("--set-string \"image.digest=", release_branch)
        self.assertIn("--set deploymentReady=true", scaffold_branch)
        self.assertIn("--set image.pullPolicy=Never", self.runtime)
        for argument_array in (
            "naranjo_runtime_values_args",
            "lidersea_runtime_values_args",
        ):
            with self.subTest(argument_array=argument_array):
                self.assertEqual(
                    self.runtime.count('\"${' + argument_array + '[@]}\"'),
                    1,
                    "runtime Helm render must consume the selected values path",
                )

    def test_release_runtime_installs_then_removes_only_a_disposable_zero_gate(self):
        self.assertIn(
            "if [[ \"$repository_release_mode\" == 'release' ]]", self.exercise
        )
        self.assertIn("write_disposable_capacity_gates", self.exercise)
        self.assertIn("kubectl_local apply -f \"$capacity_gate\"", self.exercise)
        for namespace in ("naranjo-online", "lidersea-com"):
            with self.subTest(namespace=namespace):
                self.assertIn(
                    "kubectl_local -n {} delete resourcequota capacity-not-ready".format(
                        namespace
                    ),
                    self.exercise,
                )

        fixture = function_body(
            self.script, "write_disposable_capacity_gates", "write_capacity_probe"
        )
        self.assertEqual(fixture.count("kind: ResourceQuota"), 2)
        self.assertEqual(fixture.count("name: capacity-not-ready"), 2)
        self.assertEqual(
            fixture.count(
                "platform.snaraj.dev/readiness: blocked-until-pi-capacity-evidence"
            ),
            2,
        )
        self.assertEqual(fixture.count('pods: \"0\"'), 2)
        self.assertNotIn("namespace-budget", fixture)

    def test_transition_mode_requires_authoritative_plan_and_selected_staged_phase(self):
        transition_branch = self.detect.split(
            'if [[ -n "$transition_runtime_site" ]]', 1
        )[1].split("  for file in", 1)[0]
        self.assertIn('validate_release_transition.py" plan', transition_branch)
        self.assertIn("--expect-mode transition", transition_branch)
        self.assertIn("((${#transition_plan_lines[@]} == 6))", transition_branch)
        self.assertIn("'mode=transition'", transition_branch)
        for site, index in (("naranjo-online", 1), ("lidersea-com", 2)):
            with self.subTest(site=site):
                self.assertIn(
                    '"${{transition_plan_lines[{}]}}" == \'{}=staged\''.format(
                        index, site
                    ),
                    transition_branch,
                )
        self.assertIn("repository_release_mode='transition'", transition_branch)
        self.assertNotIn("chart/values.yaml", transition_branch)

    def test_transition_render_binds_one_image_to_selected_effective_values(self):
        self.assertIn('validate_release_state.py" emit-values', self.transition_render)
        self.assertIn(
            '--release "$transition_runtime_site"', self.transition_render
        )
        self.assertEqual(
            self.transition_render.count('--values "$transition_release_values_path"'),
            3,
        )
        self.assertIn("((${#desired_images[@]} == 1))", self.transition_render)
        self.assertIn("((${#runtime_images[@]} == 1))", self.transition_render)
        self.assertIn(
            '[[ "$desired_image" == "$transition_runtime_image" ]]',
            self.transition_render,
        )
        self.assertIn(
            '[[ "${runtime_images[0]}" == "$transition_runtime_image" ]]',
            self.transition_render,
        )
        self.assertIn("--set image.pullPolicy=Never", self.transition_render)
        self.assertNotIn("--set deploymentReady", self.transition_render)
        self.assertNotIn("--set-string", self.transition_render)
        self.assertEqual(
            self.transition_render.count(
                'validate_transition_render_inventory "$'
            ),
            2,
        )

    def test_transition_render_inventory_is_exact_and_namespaced(self):
        self.assertIn("len(documents) != 4", self.transition_inventory)
        for kind in ("Deployment", "Service", "ServiceAccount", "NetworkPolicy"):
            with self.subTest(kind=kind):
                self.assertIn('"{}"'.format(kind), self.transition_inventory)
        self.assertNotIn("ClusterRole", self.transition_inventory)
        self.assertIn("1024 * 1024", self.transition_inventory)
        self.assertIn("duplicate top-level key", self.transition_inventory)
        self.assertIn("duplicate direct key", self.transition_inventory)
        self.assertIn("non-canonical top-level YAML", self.transition_inventory)

    def test_transition_render_inventory_accepts_only_canonical_four_objects(self):
        for site in ("naranjo-online", "lidersea-com"):
            with self.subTest(site=site):
                result = self.run_transition_inventory(
                    self.canonical_transition_render(site), site
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_transition_render_inventory_rejects_duplicate_flow_metadata(self):
        manifest = self.canonical_transition_render().replace(
            "  namespace: naranjo-online\nspec:\n",
            "  namespace: naranjo-online\n"
            "metadata: {name: escaped, namespace: default}\n"
            "spec:\n",
            1,
        )
        result = self.run_transition_inventory(manifest)
        self.assertNotEqual(result.returncode, 0)

    def test_transition_render_inventory_rejects_quoted_direct_metadata_key(self):
        manifest = self.canonical_transition_render().replace(
            "  namespace: naranjo-online\n",
            "  namespace: naranjo-online\n  \"namespace\": default\n",
            1,
        )
        result = self.run_transition_inventory(manifest)
        self.assertNotEqual(result.returncode, 0)

    def test_transition_render_inventory_rejects_extra_namespace_document(self):
        manifest = self.canonical_transition_render() + (
            "---\napiVersion: v1\nkind: Namespace\nmetadata:\n"
            "  name: escaped\n  namespace: naranjo-online\nspec:\n  finalizers: []\n"
        )
        result = self.run_transition_inventory(manifest)
        self.assertNotEqual(result.returncode, 0)

    def test_transition_namespace_and_quota_absence_checks_fail_closed(self):
        self.assertNotIn(r"\${", self.transition_namespace_contract)
        self.assertIn(
            'namespace_names="$(kubectl_local get namespaces',
            self.transition_namespace_contract,
        )
        self.assertIn(
            'transition_namespace_baseline="$(read_transition_namespace_inventory)"',
            self.transition_namespace_contract,
        )
        self.assertIn(
            "flux-system cloudflare-public naranjo-online lidersea-com",
            self.transition_namespace_contract,
        )
        self.assertIn(
            'expected_source="${transition_namespace_baseline}"',
            self.transition_namespace_contract,
        )
        self.assertIn(
            '[[ "${current_namespaces}" == "${expected_namespaces}" ]]',
            self.transition_namespace_contract,
        )
        self.assertIn(
            'if ! quota_names="$(kubectl_local -n "$transition_runtime_site" get resourcequota -o name)"',
            self.transition_exercise,
        )
        self.assertIn(
            'if ! remaining_quotas="$(kubectl_local -n "$transition_runtime_site" get resourcequota -o name)"',
            self.transition_exercise,
        )

    def test_transition_runtime_mutates_only_selected_site_in_owned_kind(self):
        self.assertEqual(self.transition_exercise.count("kind load docker-image"), 1)
        self.assertIn("capture_transition_namespace_baseline", self.transition_exercise)
        self.assertLess(
            self.transition_exercise.index("capture_transition_namespace_baseline"),
            self.transition_exercise.index('kubectl_local apply -f "$namespace_fixture"'),
        )
        self.assertIn(
            '--name "$cluster_name" "$transition_runtime_image"',
            self.transition_exercise,
        )
        self.assertIn(
            "assert_transition_namespace_boundary",
            self.transition_exercise,
        )
        self.assertEqual(
            self.transition_exercise.count("assert_transition_namespace_boundary"),
            2,
        )
        self.assertNotIn('apply -f "${repo_root}/kubernetes', self.transition_exercise)
        self.assertEqual(
            self.transition_exercise.count("delete resourcequota capacity-not-ready"),
            1,
        )
        self.assertEqual(
            self.transition_exercise.count('apply -f "$transition_render_path"'),
            1,
        )
        self.assertIn(
            'assert_service_ready "$transition_runtime_site" "$transition_runtime_site"',
            self.transition_exercise,
        )
        self.assertIn("assert_owned_docker_network", self.transition_exercise)
        self.assertIn("assert_owned_node_network", self.transition_exercise)
        self.assertLess(
            self.transition_exercise.index("assert_service_ready"),
            self.transition_exercise.index("assert_owned_node_network"),
        )

        fixture = function_body(
            self.script, "write_selected_capacity_gate", "write_selected_capacity_probe"
        )
        self.assertEqual(fixture.count("kind: ResourceQuota"), 1)
        self.assertEqual(fixture.count("name: capacity-not-ready"), 1)
        self.assertEqual(fixture.count('pods: "0"'), 1)
        self.assertIn("namespace: ${transition_runtime_site}", fixture)
        self.assertIn(
            "platform.snaraj.dev/readiness: blocked-until-pi-capacity-evidence",
            fixture,
        )

    def test_owned_internal_docker_network_has_closed_identity_and_cleanup(self):
        acknowledgement = (
            "I_ACKNOWLEDGE_KIND_WILL_CREATE_AND_DELETE_website-infra-local-test"
            "_AND_ITS_INTERNAL_DOCKER_NETWORK"
        )
        for document in (self.script, self.release_gate, self.local_kind_runbook):
            self.assertIn(acknowledgement, document)
        self.assertIn("docker network ls --format '{{.Name}}'", self.script)
        self.assertIn("docker_network_exists", self.prerequisites)
        self.assertIn("{{.Id}}|{{.Name}}|{{.Driver}}|{{.Internal}}", self.network_identity)
        self.assertIn("{{.Attachable}}|{{.Ingress}}|{{.Scope}}", self.network_identity)
        self.assertIn("{{json .Labels}}", self.network_identity)
        self.assertIn("docker_network_owner_label", self.cleanup)
        self.assertIn("docker network create", self.network_create)
        self.assertIn("--driver bridge", self.network_create)
        self.assertIn("--internal", self.network_create)
        self.assertIn("--label", self.network_create)
        self.assertIn("network_cleanup_authorized=1", self.network_create)
        self.assertIn("docker_network_identity", self.cleanup)
        self.assertIn('docker network rm "${owned_network_id}"', self.cleanup)
        self.assertNotIn('docker network rm "${docker_network_name}"', self.cleanup)

    def test_kind_node_is_sole_endpoint_on_only_the_owned_internal_network(self):
        self.assertIn(".NetworkSettings.Networks", self.network_attachment)
        self.assertIn(".Containers", self.network_attachment)
        self.assertIn(
            '[[ "${node_networks}" == "${docker_network_name}" ]]',
            self.network_attachment,
        )
        self.assertIn(
            '[[ "${attached_containers}" == "${owned_container_id}" ]]',
            self.network_attachment,
        )
        self.assertIn("create_owned_docker_network", self.cluster)
        self.assertLess(
            self.cluster.index("create_owned_docker_network"),
            self.cluster.index("kind create cluster"),
        )
        self.assertIn("assert_owned_node_network", self.cluster)
        self.assertGreaterEqual(
            self.script.count("KIND_EXPERIMENTAL_DOCKER_NETWORK"),
            5,
        )

    def test_failed_kind_create_recovers_only_exact_partial_container(self):
        self.assertIn("cluster_creation_started=0", self.script)
        self.assertIn("cluster_creation_started=1", self.cluster)
        self.assertLess(
            self.cluster.index("cluster_creation_started=1"),
            self.cluster.index("kind create cluster"),
        )
        self.assertLess(
            self.cluster.index("cluster_cleanup_authorized=1"),
            self.cluster.index("cluster_creation_started=0"),
        )
        for proof in (
            "candidate_container_id",
            "^[0-9a-f]{64}$",
            '"/${cluster_name}-control-plane"',
            'io.x-k8s.kind.cluster',
            'io.x-k8s.kind.role',
            '"control-plane"',
            ".Config.Image",
            "KIND_NODE_IMAGE",
            ".NetworkSettings.Networks",
            ".Containers",
            "docker_network_identity",
        ):
            with self.subTest(proof=proof):
                self.assertIn(proof, self.cleanup)
        adoption = self.cleanup.index('owned_container_id="${candidate_container_id}"')
        self.assertLess(self.cleanup.index("expected_network_identity"), adoption)
        self.assertLess(self.cleanup.index("candidate_container_name"), adoption)
        self.assertLess(self.cleanup.index("candidate_role_label"), adoption)
        self.assertLess(self.cleanup.index("candidate_image"), adoption)
        self.assertLess(self.cleanup.index("candidate_networks"), adoption)
        self.assertLess(self.cleanup.index("attached_containers"), adoption)

    def test_readiness_kubectl_substitutions_are_status_checked(self):
        for variable in (
            "observed_generation",
            "desired_generation",
            "ready_replicas",
        ):
            with self.subTest(variable=variable):
                self.assertIn('if ! {}="$(kubectl_local'.format(variable), self.readiness)
        self.assertNotIn('[[ "$(kubectl_local', self.readiness)

    def test_transition_cluster_returns_before_flux_or_other_site_bootstrap(self):
        branch = self.cluster.split(
            'if [[ "$repository_release_mode" == \'transition\' ]]', 2
        )[2].split("  fi", 1)[0]
        self.assertIn("exercise_transition_runtime_site", branch)
        self.assertIn("return", branch)
        self.assertLess(
            self.cluster.index("exercise_transition_runtime_site"),
            self.cluster.index('kubectl_local apply -f "${flux_namespace}"'),
        )
        self.assertLess(
            self.cluster.index("cluster_cleanup_authorized=1"),
            self.cluster.index("exercise_transition_runtime_site"),
        )
        self.assertLess(
            self.cluster.index("https://127\\.0\\.0\\.1:"),
            self.cluster.index("exercise_transition_runtime_site"),
        )
        self.assertLess(
            self.cluster.index("detect_repository_release_mode"),
            self.cluster.index("kind create cluster"),
        )
        self.assertLess(
            self.cluster.index("render_transition_runtime_site"),
            self.cluster.index("kind create cluster"),
        )
        self.assertLess(
            self.cluster.index("revalidate_transition_runtime_state"),
            self.cluster.index("kind create cluster"),
        )

    def test_transition_state_is_revalidated_before_and_after_kind(self):
        self.assertEqual(
            self.transition_revalidate.count("detect_repository_release_mode"), 2
        )
        self.assertIn("emit-values", self.transition_revalidate)
        self.assertIn(
            '--release "$transition_runtime_site"', self.transition_revalidate
        )
        self.assertIn(
            '[[ "$current_values" == "$rendered_values" ]]',
            self.transition_revalidate,
        )
        self.assertIn(
            'if ! expected_render="$(<"$transition_render_path")"',
            self.transition_revalidate,
        )
        self.assertIn(
            '[[ "$current_render" == "$expected_render" ]]',
            self.transition_revalidate,
        )
        self.assertIn("--set image.pullPolicy=Never", self.transition_revalidate)
        self.assertEqual(
            self.cluster.count("revalidate_transition_runtime_state"), 1
        )
        self.assertEqual(
            self.transition_exercise.count("revalidate_transition_runtime_state"),
            1,
        )

    def test_transition_runtime_reruns_complete_static_gate_at_final_boundary(self):
        final_state = self.transition_exercise.index(
            "revalidate_transition_runtime_state"
        )
        final_static = self.transition_exercise.index(
            "run_canonical_transition_static_gate", final_state
        )
        evidence_pass = self.transition_exercise.index(
            "TRANSITION RUNTIME EVIDENCE PASS"
        )
        self.assertLess(final_state, final_static)
        self.assertLess(final_static, evidence_pass)
        self.assertEqual(
            self.transition_exercise.count("run_canonical_transition_static_gate"),
            1,
        )

    def test_transition_runtime_has_static_gates_on_both_sides_of_kind(self):
        dispatch = self.script.split("  --transition-runtime)\n", 1)[1].split(
            "\n  *)\n", 1
        )[0]
        pre_kind_static = dispatch.index("run_canonical_transition_static_gate")
        kind_execution = dispatch.index("exercise_cluster")
        self.assertLess(pre_kind_static, kind_execution)
        self.assertIn(
            "run_canonical_transition_static_gate", self.transition_exercise
        )

    def test_transition_cli_requires_site_ack_and_only_selected_image(self):
        dispatch = self.script.split("  --transition-runtime)\n", 1)[1].split(
            "\n  *)\n", 1
        )[0]
        self.assertIn("(( $# == 3 ))", dispatch)
        self.assertIn("naranjo-online|lidersea-com)", dispatch)
        self.assertIn('transition_runtime_site="$2"', dispatch)
        self.assertIn('[[ "$3" == "${apply_ack}" ]]', dispatch)
        self.assertIn("run_canonical_transition_static_gate", dispatch)
        self.assertIn("check_transition_runtime_input", dispatch)
        self.assertIn("exercise_cluster", dispatch)
        self.assertLess(
            dispatch.index("run_canonical_transition_static_gate"),
            dispatch.index("check_prerequisites"),
        )
        self.assertIn(
            'release-gate.sh" --transition-check', self.transition_static_gate
        )

        inputs = function_body(
            self.script, "check_transition_runtime_input", "write_transition_namespace"
        )
        self.assertIn("NARANJO_RUNTIME_IMAGE", inputs)
        self.assertIn("LIDERSEA_RUNTIME_IMAGE", inputs)
        self.assertIn("transition_runtime_image=", inputs)
        self.assertEqual(inputs.count("require_runtime_image"), 2)

    def test_release_gate_exposes_offline_transition_then_same_kind_mode(self):
        static_dispatch = self.release_gate.split("  --transition-check)\n", 1)[
            1
        ].split("  --transition-runtime)", 1)[0]
        self.assertIn("run_static_gate --transition", static_dispatch)
        dispatch = self.release_gate.split("  --transition-runtime)\n", 1)[1].split(
            "  --live)", 1
        )[0]
        self.assertIn(
            'test-kind.sh" --transition-runtime "$2" "$KIND_ACK"', dispatch
        )
        self.assertNotIn("run_static_gate --transition", dispatch)
        self.assertNotIn("run_live_gate", dispatch)
        self.assertNotIn("PROD_KUBECONFIG", dispatch)
        self.assertNotIn("verify-exposure", dispatch)


if __name__ == "__main__":
    unittest.main()
