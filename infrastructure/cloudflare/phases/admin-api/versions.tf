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

# This later phase needs Zero Trust Write only for one Gateway policy. It must
# not receive DNS permission.
provider "cloudflare" {}
