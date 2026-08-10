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

# This independent token is scoped to DNS edit for lidersea.com only.
provider "cloudflare" {}
