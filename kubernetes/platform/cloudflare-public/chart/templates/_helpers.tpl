{{- define "cloudflare-public.name" -}}
cloudflare-public
{{- end -}}

{{/*
Shared labels for objects that both site connectors own jointly: the
ServiceAccount and the DNS/edge egress NetworkPolicies. The instance is the
release itself because these objects are not scoped to one per-site connector,
and a name-only podSelector against them reaches every connector Pod.
*/}}
{{- define "cloudflare-public.labels" -}}
app.kubernetes.io/name: {{ include "cloudflare-public.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Per-connector labels. Each site connector carries the shared platform name
(app.kubernetes.io/name=cloudflare-public) plus its own site-scoped instance
(<site>-tunnel), so a name+instance selector reaches exactly one connector
while the shared name-only selector reaches both. This double identity is the
symmetry the reconciled contract enforces on both the connector-egress side
(this chart) and the site-ingress side (each site chart, in its own repo).
Argument: dict "root" $ "instance" <site>-tunnel.
*/}}
{{- define "cloudflare-public.connectorLabels" -}}
app.kubernetes.io/name: {{ include "cloudflare-public.name" .root }}
app.kubernetes.io/instance: {{ .instance }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{- end -}}
