"""Keep digest promotion exact while sharing its verification machinery."""

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMOTION = REPO_ROOT / "scripts" / "promote-image.sh"


class PromotionContractTests(unittest.TestCase):
    """Protect each site's independent provenance and values boundary."""

    @classmethod
    def setUpClass(cls):
        cls.script = PROMOTION.read_text(encoding="utf-8")

    def test_each_site_has_one_exact_identity_tuple(self):
        tuples = {
            "naranjo-online": (
                "ghcr.io/snaraj/naranjo-online",
                "websites/naranjo.online/chart/values.yaml",
                "publish-naranjo-online-image.yml@refs/heads/main",
            ),
            "lidersea-com": (
                "ghcr.io/snaraj/lidersea-com",
                "websites/lidersea.com/chart/values.yaml",
                "publish-lidersea-com-image.yml@refs/heads/main",
            ),
        }
        for site, fragments in tuples.items():
            with self.subTest(site=site):
                match = re.search(
                    r"(?ms)^  {}\)\n(?P<body>.*?)^    ;;$".format(re.escape(site)),
                    self.script,
                )
                self.assertIsNotNone(match)
                body = match.group("body")
                for fragment in fragments:
                    self.assertIn(fragment, body)
                for other_site, other_fragments in tuples.items():
                    if other_site == site:
                        continue
                    for fragment in other_fragments:
                        self.assertNotIn(fragment, body)

    def test_promotion_stays_review_only_and_digest_bound(self):
        for fragment in (
            "cosign verify --certificate-identity",
            "cosign verify-attestation --type slsaprovenance1",
            '[[ "${digest}" != "sha256:',
            "working tree must be clean before promotion",
            "Verified and updated",
            "This script did not commit, push, or deploy",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.script)
        self.assertNotIn("Verified and staged", self.script)


if __name__ == "__main__":
    unittest.main()
