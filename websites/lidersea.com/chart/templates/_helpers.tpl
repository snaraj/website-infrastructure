{{/* Canonical labels keep policy selectors bound to only this site's release. */}}
{{- define "lidersea-com.name" -}}
lidersea-com
{{- end -}}

{{- define "lidersea-com.labels" -}}
app.kubernetes.io/name: {{ include "lidersea-com.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
