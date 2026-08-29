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

# This phase receives a distinct source-restricted JIT credential with only
# Account SSL and Certificates Write. The private CA key never enters
# Cloudflare, OpenTofu state, this repository, or the provider environment.
provider "cloudflare" {}
