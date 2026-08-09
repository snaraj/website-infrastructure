{{- define "naranjo-online.name" -}}
naranjo-online
{{- end -}}

{{- define "naranjo-online.labels" -}}
app.kubernetes.io/name: {{ include "naranjo-online.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
