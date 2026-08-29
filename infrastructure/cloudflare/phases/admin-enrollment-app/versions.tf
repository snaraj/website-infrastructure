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

# A second JIT Access credential prevents the app plan from hiding an unknown
# newly-created policy ID inside the same transaction.
provider "cloudflare" {}
