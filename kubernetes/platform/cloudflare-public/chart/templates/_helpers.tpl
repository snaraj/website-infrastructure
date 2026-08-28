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
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{/*
Per-connector labels. Each site connector carries the shared platform name
(app.kubernetes.io/name=cloudflare-public) plus its own site-scoped instance
(<site>-tunnel), so a name+instance selector reaches exactly one connector
while the shared name-only selector reaches both. This double identity is the
symmetry the reconciled contract enforces on both the connector-egress side
(this chart) and the site-ingress side (each site chart, in its own repo).
Argument: dict "root" $ "instance" <site>-tunnel.

app.kubernetes.io/version carries the connector's running release so
`kubectl get po -L app.kubernetes.io/version` answers "what is deployed"
without reading a digest. It is DERIVED from .Chart.AppVersion, never from a
value, so it cannot disagree with the chart that rendered it; it is a label,
never a selector key, so adding it changes no NetworkPolicy, Service, or
Deployment selector, and no retained policy or selector reads it as identity.
*/}}
{{- define "cloudflare-public.connectorLabels" -}}
app.kubernetes.io/name: {{ include "cloudflare-public.name" .root }}
app.kubernetes.io/instance: {{ .instance }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
{{- end -}}
