terraform {
  required_version = "= 1.12.5"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.22.0"
    }
  }

  # Supply a protected, encrypted-volume path through -backend-config. Never
  # initialize a live root against repository-adjacent state.
  backend "local" {}
}

# Authentication is accepted only from CLOUDFLARE_API_TOKEN in the operator's
# private process environment. This root's just-in-time token needs account
# Cloudflare Tunnel write plus zone DNS write and zone settings write on the
# one zone this root owns; it must never carry the other site's zone.
provider "cloudflare" {}
