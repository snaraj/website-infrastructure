# Provider v5 imports — Draft / external mutation checkpoint

Set `enable_cloudflare_resources=true` only in ignored local variables. Replace
the bracketed identifiers from read-only discovery without placing them in shell
history where practical. Run one import and one refresh-only plan at a time:

```powershell
tofu import 'cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0]' '<account_id>/<tunnel_id>'
tofu import 'cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0]' '<account_id>/<tunnel_id>'
tofu import 'cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]' '<account_id>/<tunnel_id>'
tofu import 'cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin[0]' '<account_id>/<route_id>'
tofu import 'cloudflare_zero_trust_gateway_policy.pi_admin_allow[0]' '<account_id>/<rule_id>'
tofu import 'cloudflare_zero_trust_gateway_policy.pi_admin_block[0]' '<account_id>/<rule_id>'
tofu import 'cloudflare_dns_record.naranjo_online[0]' '<naranjo_online_zone_id>/<dns_record_id>'
tofu import 'cloudflare_dns_record.lidersea_com[0]' '<lidersea_com_zone_id>/<dns_record_id>'
```

Import writes sensitive local state and therefore requires the same protected
state boundary and explicit checkpoint as planning. Do not import or manage the
existing zone, plan, subscription, or Registrar. For legacy provider-v4 state,
stop and follow the official v5 migration guide; these commands are only for the
new/import-only scaffold.
