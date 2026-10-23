{{- define "security.name" -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "security.labels" -}}
app.kubernetes.io/name: matrixhub-security
app.kubernetes.io/instance: {{ .Release.Name }}
matrixhub.security/owner: {{ .Values.deploymentId | quote }}
{{- end -}}
{{- define "security.selector" -}}
app.kubernetes.io/name: matrixhub-security
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
