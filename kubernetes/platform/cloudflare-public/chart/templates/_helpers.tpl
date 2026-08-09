{{- define "cloudflare-public.name" -}}
cloudflare-public
{{- end -}}

{{- define "cloudflare-public.labels" -}}
app.kubernetes.io/name: {{ include "cloudflare-public.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
