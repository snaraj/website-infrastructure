terraform {
  required_version = "= 1.12.5"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.22.0"
    }
  }
  backend "local" {}
}

# This phase deliberately uses a different JIT token from admin-tunnel. The
# Cloudflare Zero Trust permission remains account-wide, so the exact plan gate,
# short TTL, source-IP condition, and immediate revocation are mandatory.
provider "cloudflare" {}
