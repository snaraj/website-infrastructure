import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "platform_bootstrap_closure_test",
    ROOT / "scripts/ci/platform_bootstrap_closure.py",
)
assert SPEC and SPEC.loader
closure = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = closure
SPEC.loader.exec_module(closure)


def obj(namespace, name, spec):
    return {"metadata": {"namespace": namespace, "name": name}, "spec": spec}


def live(value, uid="uid-1", rv="10"):
    result = copy.deepcopy(value)
    annotations = copy.deepcopy(result["metadata"].get("annotations", {}))
    annotations["kubectl.kubernetes.io/last-applied-configuration"] = "public"
    result["metadata"].update(
        {
            "uid": uid,
            "resourceVersion": rv,
            "annotations": annotations,
        }
    )
    return result


def target_oci(site="naranjo-online"):
    return {
        "apiVersion": "source.toolkit.fluxcd.io/v1",
        "kind": "OCIRepository",
        "metadata": {
            "name": site + "-chart",
            "namespace": site,
            "annotations": {closure.RELEASE_ANNOTATION: "0.1.51"},
        },
        "spec": {
            "interval": "10m0s",
            "ref": {"digest": "sha256:" + "1" * 64},
            "timeout": "60s",
            "url": "oci://ghcr.io/snaraj/charts/" + site,
        },
    }


def old_oci(target):
    result = copy.deepcopy(target)
    result["metadata"].pop("annotations")
    result["metadata"].update(
        {
            "uid": "oci-uid",
            "resourceVersion": "20",
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "public"},
            "finalizers": ["finalizers.fluxcd.io"],
        }
    )
    result["spec"]["ref"] = {"semver": closure.SEMVER}
    return result


class ConsumerTests(unittest.TestCase):
    def collections(self):
        source = {"kind": "GitRepository", "name": "flux-system"}
        return {
            "kustomizations": [obj("flux-system", "naranjo-online-reconciler", {"sourceRef": source})],
            "helmcharts": [obj("legacy", "chart", {"sourceRef": source})],
            "helmreleases": [obj("legacy", "release", {"chart": {"spec": {"sourceRef": source}}})],
            "externalartifacts": [obj("legacy", "artifact", {"sourceRef": source})],
        }

    def test_all_four_effective_consumer_forms_are_enumerated(self):
        consumers = closure.enumerate_git_consumers(self.collections())
        self.assertEqual(len(consumers), 4)
        self.assertEqual({item["key"].split("|", 1)[0] for item in consumers}, set(closure.CONSUMER_GVRS.values()))

    def test_unrelated_refs_are_ignored_but_inline_chart_is_not(self):
        values = self.collections()
        values["kustomizations"][0]["spec"]["sourceRef"]["kind"] = "OCIRepository"
        values["helmcharts"][0]["spec"]["sourceRef"]["kind"] = "HelmRepository"
        values["helmreleases"][0]["spec"] = {"chartRef": {"kind": "OCIRepository", "name": "chart"}}
        values["externalartifacts"][0]["spec"]["sourceRef"]["kind"] = "OCIRepository"
        self.assertEqual(closure.enumerate_git_consumers(values), [])

    def test_external_artifact_without_optional_source_ref_is_not_a_consumer(self):
        values = {key: [] for key in closure.CONSUMER_GVRS}
        values["externalartifacts"] = [obj("other", "detached", {})]
        self.assertEqual(closure.enumerate_git_consumers(values), [])

    def test_post_accepts_only_two_scoped_parents(self):
        values = {key: [] for key in closure.CONSUMER_GVRS}
        source = {"kind": "GitRepository", "name": "flux-system"}
        values["kustomizations"] = [
            obj("flux-system", "naranjo-online-reconciler", {"sourceRef": source}),
            obj("flux-system", "lidersea-com-reconciler", {"sourceRef": source}),
        ]
        consumers = closure.enumerate_git_consumers(values)
        closure.validate_consumers(consumers, "post")
        with self.assertRaisesRegex(closure.ClosureError, "legacy or foreign"):
            closure.validate_consumers(consumers[:1], "post")
        with self.assertRaisesRegex(closure.ClosureError, "legacy or foreign"):
            closure.validate_consumers(consumers, "pre")

    def test_initial_accepts_only_exact_interrupted_parent_subsets(self):
        values = {key: [] for key in closure.CONSUMER_GVRS}
        source = {"kind": "GitRepository", "name": "flux-system"}
        values["kustomizations"] = [
            obj("flux-system", site + "-reconciler", {"sourceRef": source})
            for site in closure.SITES
        ]
        consumers = closure.enumerate_git_consumers(values)
        for subset in ([], consumers[:1], consumers[1:], consumers):
            with self.subTest(initial_subset=len(subset)):
                closure.validate_consumers(subset, "initial")
        foreign = copy.deepcopy(consumers[:1])
        foreign[0]["key"] = foreign[0]["key"].rsplit("|", 1)[0] + "|foreign"
        with self.assertRaisesRegex(closure.ClosureError, "legacy or foreign"):
            closure.validate_consumers(foreign, "initial")

    def test_malformed_or_incomplete_api_inventory_fails(self):
        cases = []
        missing = self.collections(); missing.pop("externalartifacts"); cases.append(missing)
        bad_ref = self.collections(); bad_ref["helmcharts"][0]["spec"]["sourceRef"] = {"kind": "GitRepository"}; cases.append(bad_ref)
        both = self.collections(); both["helmreleases"][0]["spec"]["chartRef"] = {"kind": "OCIRepository", "name": "x"}; cases.append(both)
        duplicate = self.collections(); duplicate["kustomizations"].append(copy.deepcopy(duplicate["kustomizations"][0])); cases.append(duplicate)
        for case in cases:
            with self.subTest(case=cases.index(case)):
                with self.assertRaises(closure.ClosureError):
                    closure.enumerate_git_consumers(case)

    def test_explicit_foreign_api_version_cannot_alias_target(self):
        values = {key: [] for key in closure.CONSUMER_GVRS}
        values["kustomizations"] = [obj("flux-system", site + "-reconciler", {"sourceRef": {"apiVersion": "evil/v1", "kind": "GitRepository", "name": "flux-system"}}) for site in closure.SITES]
        with self.assertRaisesRegex(closure.ClosureError, "legacy or foreign"):
            closure.validate_consumers(closure.enumerate_git_consumers(values), "post")


class SiteChainTests(unittest.TestCase):
    def objects(self):
        return {key: live(value, uid=key, rv="10") for key, value in closure.expected_site_chain().items()}

    def test_exact_ten_objects_accept_order_only_variance(self):
        values = self.objects()
        key = "naranjo-online|Role|helm-reconciler"
        values[key]["rules"] = list(reversed(values[key]["rules"]))
        values[key]["rules"][0]["verbs"] = list(reversed(values[key]["rules"][0]["verbs"]))
        closure.validate_site_chain(values)
        self.assertEqual(closure.validate_site_chain_state(values), "active")

    def test_preflight_classifies_both_exact_mixed_interruption_states(self):
        values = self.objects()
        keys = [f"{site}|RoleBinding|helm-reconciler" for site in closure.SITES]
        for key in keys:
            values[key].pop("subjects")
        self.assertEqual(
            closure.validate_site_chain_state(values), "quarantined"
        )
        values[keys[0]]["subjects"] = copy.deepcopy(
            closure.expected_site_chain()[keys[0]]["subjects"]
        )
        self.assertEqual(closure.validate_site_chain_state(values), "mixed")
        values[keys[0]].pop("subjects")
        values[keys[1]]["subjects"] = copy.deepcopy(
            closure.expected_site_chain()[keys[1]]["subjects"]
        )
        self.assertEqual(closure.validate_site_chain_state(values), "mixed")

    def test_missing_or_widened_chain_fails(self):
        missing = self.objects(); missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(closure.ClosureError, "exactly ten"):
            closure.validate_site_chain(missing)
        widened = self.objects()
        widened["naranjo-online|Role|flux-controller-impersonation"]["rules"][0]["resourceNames"].append("default")
        with self.assertRaisesRegex(closure.ClosureError, "foreign"):
            closure.validate_site_chain(widened)
        cross = self.objects()
        cross["lidersea-com|RoleBinding|helm-reconciler"]["subjects"][0]["namespace"] = "naranjo-online"
        with self.assertRaisesRegex(closure.ClosureError, "foreign"):
            closure.validate_site_chain(cross)
        pull_secret = self.objects()
        pull_secret["naranjo-online|ServiceAccount|helm-reconciler"]["imagePullSecrets"] = [{"name": "foreign"}]
        with self.assertRaisesRegex(closure.ClosureError, "foreign"):
            closure.validate_site_chain(pull_secret)

    def test_each_late_restore_rechecks_the_exact_ordered_chain(self):
        values = self.objects()
        expected = closure.expected_site_chain()
        for site in closure.SITES:
            key = f"{site}|RoleBinding|helm-reconciler"
            values[key]["subjects"] = []
        closure.validate_site_restore_boundary(values, "naranjo-online")
        values["naranjo-online|RoleBinding|helm-reconciler"]["subjects"] = (
            copy.deepcopy(
                expected["naranjo-online|RoleBinding|helm-reconciler"]["subjects"]
            )
        )
        closure.validate_site_restore_boundary(values, "lidersea-com")

        widened = copy.deepcopy(values)
        widened["lidersea-com|Role|helm-reconciler"]["rules"].append({
            "apiGroups": [""], "resources": ["pods"], "verbs": ["create"],
        })
        with self.assertRaisesRegex(closure.ClosureError, "restore boundary"):
            closure.validate_site_restore_boundary(widened, "lidersea-com")

        wrong_phase = copy.deepcopy(values)
        wrong_phase["lidersea-com|RoleBinding|helm-reconciler"]["subjects"] = (
            copy.deepcopy(
                expected["lidersea-com|RoleBinding|helm-reconciler"]["subjects"]
            )
        )
        with self.assertRaisesRegex(closure.ClosureError, "restore boundary"):
            closure.validate_site_restore_boundary(wrong_phase, "lidersea-com")


class RoleBindingTransitionTests(unittest.TestCase):
    def setUp(self):
        self.expected = closure.expected_site_chain()["naranjo-online|RoleBinding|helm-reconciler"]
        self.active = live(self.expected, uid="binding-uid", rv="10")

    def test_quarantine_and_restore_bind_uid_and_current_resource_version(self):
        request = closure.rolebinding_replace(self.active, self.expected, True)
        self.assertEqual(request["metadata"]["uid"], "binding-uid")
        self.assertEqual(request["metadata"]["resourceVersion"], "10")
        self.assertEqual(request["subjects"], [])
        quarantined = copy.deepcopy(request); quarantined["metadata"]["resourceVersion"] = "11"
        closure.validate_rolebinding_result(self.active, quarantined, self.expected, True)
        omitted = copy.deepcopy(quarantined); omitted.pop("subjects")
        closure.validate_rolebinding_result(self.active, omitted, self.expected, True)
        restored_request = closure.rolebinding_replace(quarantined, self.expected, False)
        restored = copy.deepcopy(restored_request); restored["metadata"]["resourceVersion"] = "12"
        closure.validate_rolebinding_result(quarantined, restored, self.expected, False)

    def test_replacement_or_no_rv_advance_fails(self):
        request = closure.rolebinding_replace(self.active, self.expected, True)
        same_rv = copy.deepcopy(request)
        with self.assertRaisesRegex(closure.ClosureError, "did not advance"):
            closure.validate_rolebinding_result(self.active, same_rv, self.expected, True)
        replaced = copy.deepcopy(request); replaced["metadata"].update(uid="replacement", resourceVersion="11")
        with self.assertRaisesRegex(closure.ClosureError, "UID changed"):
            closure.validate_rolebinding_result(self.active, replaced, self.expected, True)

    def test_both_sites_must_be_quarantined_before_source_mutation(self):
        expected = closure.expected_site_chain()
        values = {}
        for site in closure.SITES:
            key = f"{site}|RoleBinding|helm-reconciler"
            values[key] = live(expected[key]); values[key]["subjects"] = []
        closure.require_both_helm_bindings_quarantined(values)
        values["lidersea-com|RoleBinding|helm-reconciler"]["subjects"] = copy.deepcopy(expected["lidersea-com|RoleBinding|helm-reconciler"]["subjects"])
        with self.assertRaisesRegex(closure.ClosureError, "foreign"):
            closure.require_both_helm_bindings_quarantined(values)


class OciMigrationTests(unittest.TestCase):
    def test_patch_is_exact_cas_and_only_moves_ref_and_release_annotation(self):
        target = target_oci(); old = old_oci(target)
        patch = closure.oci_migration_patch(old, target)
        self.assertEqual([item["op"] for item in patch], ["test", "test", "test", "test", "replace", "add"])
        self.assertEqual([item["path"] for item in patch[:4]], ["/metadata/uid", "/metadata/resourceVersion", "/spec/ref", "/metadata/annotations"])
        self.assertEqual(patch[4], {"op": "replace", "path": "/spec/ref", "value": target["spec"]["ref"]})
        self.assertEqual(patch[5]["path"], "/metadata/annotations/platform.snaraj.dev~1chart-release")
        after = copy.deepcopy(target)
        after["metadata"].update(uid="oci-uid", resourceVersion="21", finalizers=["finalizers.fluxcd.io"])
        closure.validate_oci_result(old, after, target)

    def test_partial_moved_or_conflicting_old_state_fails(self):
        target = target_oci()
        mutants = []
        moved = old_oci(target); moved["spec"]["ref"] = target["spec"]["ref"]; mutants.append(moved)
        partial = old_oci(target); partial["spec"]["ref"]["digest"] = target["spec"]["ref"]["digest"]; mutants.append(partial)
        tagged = old_oci(target); tagged["spec"]["ref"] = {"tag": "latest"}; mutants.append(tagged)
        annotated = old_oci(target); annotated["metadata"]["annotations"][closure.RELEASE_ANNOTATION] = "0.1.45"; mutants.append(annotated)
        for mutant in mutants:
            with self.subTest(mutant=mutants.index(mutant)):
                with self.assertRaisesRegex(closure.ClosureError, "exact old"):
                    closure.oci_migration_patch(mutant, target)

    def test_absent_annotation_map_is_still_bound_by_full_metadata_test(self):
        target = target_oci(); old = old_oci(target); old["metadata"].pop("annotations")
        patch = closure.oci_migration_patch(old, target)
        self.assertEqual(patch[3]["path"], "/metadata")
        self.assertEqual(patch[-1]["path"], "/metadata/annotations")

    def test_requested_at_is_preserved_by_the_exact_oci_cas(self):
        target = target_oci(); old = old_oci(target)
        old["metadata"]["annotations"]["reconcile.fluxcd.io/requestedAt"] = (
            "2026-08-28T00:00:00Z"
        )
        patch = closure.oci_migration_patch(old, target)
        self.assertEqual(
            patch[3]["value"]["reconcile.fluxcd.io/requestedAt"],
            "2026-08-28T00:00:00Z",
        )
        after = copy.deepcopy(target)
        after["metadata"]["annotations"]["reconcile.fluxcd.io/requestedAt"] = (
            "2026-08-28T00:00:00Z"
        )
        after["metadata"].update(
            uid="oci-uid", resourceVersion="21", finalizers=["finalizers.fluxcd.io"]
        )
        closure.validate_oci_result(old, after, target)


class ParentInventoryTests(unittest.TestCase):
    def good(self, site="naranjo-online"):
        return [
            {"id": f"{site}_{site}_helm.toolkit.fluxcd.io_HelmRelease", "v": "v2"},
            {"id": f"{site}_{site}-chart_source.toolkit.fluxcd.io_OCIRepository", "v": "v1"},
            {"id": f"{site}_default-deny_networking.k8s.io_NetworkPolicy", "v": "v1"},
        ]

    def test_exact_three_item_inventory_accepts_order_only(self):
        normalized = closure.normalized_parent_inventory("naranjo-online", self.good())
        self.assertEqual(len(normalized), 3)

    def test_extra_missing_duplicate_and_wrong_version_fail(self):
        good = self.good()
        mutants = [good[:2], good + [{"id": "x", "v": "v1"}], good[:2] + [copy.deepcopy(good[0])]]
        wrong = copy.deepcopy(good); wrong[0]["v"] = "v1"; mutants.append(wrong)
        for mutant in mutants:
            with self.subTest(mutant=mutants.index(mutant)):
                with self.assertRaisesRegex(closure.ClosureError, "exact three"):
                    closure.normalized_parent_inventory("naranjo-online", mutant)


class ChildClosureTests(unittest.TestCase):
    def setUp(self):
        self.site = "naranjo-online"
        self.oci = target_oci(self.site)
        self.expected = closure.expected_site_children(self.site, self.oci)

    def live_children(self):
        values = {
            key: live(value, uid=f"{key}-uid", rv="30")
            for key, value in self.expected.items()
        }
        for key in ("oci", "helmrelease"):
            values[key]["metadata"]["finalizers"] = ["finalizers.fluxcd.io"]
        return values

    def test_exact_three_specs_accept_only_server_metadata(self):
        closure.validate_site_children(self.site, self.live_children(), self.oci)

    def test_flux_request_annotation_is_operational_metadata(self):
        values = self.live_children()
        for key in ("oci", "helmrelease"):
            values[key]["metadata"]["annotations"][
                "reconcile.fluxcd.io/requestedAt"
            ] = "2026-08-28T00:00:00Z"
        closure.validate_site_children(self.site, values, self.oci)

    def test_similar_annotations_and_non_boolean_suspend_remain_foreign(self):
        cases = []
        lookalike = self.live_children()
        lookalike["helmrelease"]["metadata"]["annotations"][
            "reconcile.fluxcd.io/requestedAt-lookalike"
        ] = "2026-08-28T00:00:00Z"
        cases.append(lookalike)
        malformed = self.live_children()
        malformed["helmrelease"]["metadata"]["annotations"][
            "reconcile.fluxcd.io/requestedAt"
        ] = {"not": "a string"}
        cases.append(malformed)
        non_flux = self.live_children()
        non_flux["networkpolicy"]["metadata"]["annotations"][
            "reconcile.fluxcd.io/requestedAt"
        ] = "2026-08-28T00:00:00Z"
        cases.append(non_flux)
        string_false = self.live_children()
        string_false["helmrelease"]["spec"]["suspend"] = "false"
        cases.append(string_false)
        absent_false = self.live_children()
        absent_false["helmrelease"]["spec"].pop("suspend")
        cases.append(absent_false)
        for value in cases:
            with self.subTest(case=cases.index(value)), self.assertRaises(
                closure.ClosureError
            ):
                closure.validate_site_children(self.site, value, self.oci)

    def test_foreign_retained_fields_and_extra_objects_fail(self):
        cases = []
        secret_ref = self.live_children()
        secret_ref["helmrelease"]["spec"]["kubeConfig"] = {
            "secretRef": {"name": "foreign"}
        }
        cases.append(secret_ref)
        mutable_ref = self.live_children()
        mutable_ref["oci"]["spec"]["ref"] = {"tag": "latest"}
        cases.append(mutable_ref)
        extra = self.live_children()
        extra["foreign"] = copy.deepcopy(extra["networkpolicy"])
        cases.append(extra)
        for value in cases:
            with self.subTest(case=cases.index(value)), self.assertRaises(
                closure.ClosureError
            ):
                closure.validate_site_children(self.site, value, self.oci)

    def test_oci_and_helm_readiness_are_current_and_unique(self):
        values = self.live_children()
        for key, condition_types in (
            ("oci", ("SourceVerified", "Ready")),
            ("helmrelease", ("Ready",)),
        ):
            values[key]["metadata"]["generation"] = 4
            values[key]["status"] = {
                "observedGeneration": 4,
                "conditions": [
                    {"type": kind, "status": "True", "observedGeneration": 4}
                    for kind in condition_types
                ],
            }
        closure.validate_oci_ready(values["oci"], self.oci)
        closure.validate_helmrelease_ready(
            values["helmrelease"], self.expected["helmrelease"]
        )
        stale = copy.deepcopy(values["oci"])
        stale["status"]["observedGeneration"] = 3
        with self.assertRaisesRegex(closure.ClosureError, "current generation"):
            closure.validate_oci_ready(stale, self.oci)
        duplicate = copy.deepcopy(values["helmrelease"])
        duplicate["status"]["conditions"].append(
            copy.deepcopy(duplicate["status"]["conditions"][0])
        )
        with self.assertRaisesRegex(closure.ClosureError, "uniquely current"):
            closure.validate_helmrelease_ready(
                duplicate, self.expected["helmrelease"]
            )

    def test_parent_intermediate_requires_exact_attempt_and_inventory(self):
        parent = {
            "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
            "kind": "Kustomization",
            "metadata": {
                "name": self.site + "-reconciler",
                "namespace": "flux-system",
                "uid": "parent-uid",
                "resourceVersion": "40",
                "generation": 3,
                "finalizers": ["finalizers.fluxcd.io"],
            },
            "spec": {
                "force": False,
                "prune": False,
                "sourceRef": {"kind": "GitRepository", "name": "flux-system"},
                "suspend": False,
            },
        }
        expected = copy.deepcopy(parent)
        expected["metadata"] = {
            "name": self.site + "-reconciler", "namespace": "flux-system"
        }
        revision = "v0.1.40@sha1:" + "a" * 40
        parent["status"] = {
            "observedGeneration": 3,
            "lastAttemptedRevision": revision,
            "inventory": {"entries": ParentInventoryTests().good(self.site)},
        }
        closure.validate_parent_attempted(self.site, parent, expected, revision)
        for mutate in (
            lambda value: value["spec"].update(force=True),
            lambda value: value["status"].update(lastAttemptedRevision="v0.1.34@sha1:" + "b" * 40),
            lambda value: value["status"]["inventory"]["entries"].pop(),
        ):
            hostile = copy.deepcopy(parent)
            mutate(hostile)
            with self.assertRaises(closure.ClosureError):
                closure.validate_parent_attempted(
                    self.site, hostile, expected, revision
                )


if __name__ == "__main__":
    unittest.main()
