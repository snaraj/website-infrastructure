terraform {
  required_version = "= 1.12.5"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.22.0"
    }
  }

  # Supply a protected, encrypted-volume path through -backend-config. Never
  # initialize a live phase against repository-adjacent state.
  backend "local" {}
}

# Authentication is accepted only from CLOUDFLARE_API_TOKEN in the operator's
# private process environment. This phase token needs no DNS permission.
provider "cloudflare" {}
