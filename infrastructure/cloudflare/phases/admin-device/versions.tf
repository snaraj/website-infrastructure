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

# This phase receives a fresh Zero Trust Write token, separate from every
# Gateway-policy token even though Cloudflare exposes the same broad scope.
provider "cloudflare" {}
