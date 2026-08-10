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

# CLOUDFLARE_API_TOKEN is a single-phase, source-IP-restricted JIT token. The
# provider accepts no credential from variables or committed files.
provider "cloudflare" {}
