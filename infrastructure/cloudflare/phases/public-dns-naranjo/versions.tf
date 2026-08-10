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

# This token is scoped to DNS edit for the naranjo.online zone only. Cloudflare
# cannot scope it to one record, so JIT TTL/source-IP/revocation gates remain mandatory.
provider "cloudflare" {}
