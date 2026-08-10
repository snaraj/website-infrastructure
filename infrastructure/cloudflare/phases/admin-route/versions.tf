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

# This phase needs Cloudflare One Networks Write only. It must not receive DNS
# or general Zero Trust policy write authority.
provider "cloudflare" {}
