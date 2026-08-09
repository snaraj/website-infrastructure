# Authentication is accepted only from CLOUDFLARE_API_TOKEN in the local
# operator environment. Never add an API-token variable or commit credentials.
provider "cloudflare" {}
