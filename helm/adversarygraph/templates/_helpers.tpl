{{- define "adversarygraph.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "adversarygraph.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "adversarygraph.labels" -}}
app.kubernetes.io/name: {{ include "adversarygraph.name" . }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "adversarygraph.selectorLabels" -}}
app.kubernetes.io/name: {{ include "adversarygraph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "adversarygraph.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "adversarygraph.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "adversarygraph.componentImage" -}}
{{- if .digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .digest) -}}
{{- fail "image digest must use the form sha256:<64 lowercase hexadecimal characters>" -}}
{{- end -}}
{{- printf "%s@%s" .repository .digest -}}
{{- else -}}
{{- printf "%s:%s" .repository .tag -}}
{{- end -}}
{{- end -}}

{{- define "adversarygraph.fullImage" -}}
{{- if .digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .digest) -}}
{{- fail "image digest must use the form sha256:<64 lowercase hexadecimal characters>" -}}
{{- end -}}
{{- printf "%s@%s" .image .digest -}}
{{- else -}}
{{- .image -}}
{{- end -}}
{{- end -}}

{{- define "adversarygraph.databaseHost" -}}
{{- if .Values.postgresql.enabled -}}
{{- printf "%s-postgres" (include "adversarygraph.fullname" .) -}}
{{- else -}}
{{- $host := trim (toString .Values.postgresql.externalHost) -}}
{{- if or (empty $host) (contains "://" $host) -}}
{{- fail "postgresql.externalHost must be a non-empty hostname or IP address without a URL scheme when postgresql.enabled=false" -}}
{{- end -}}
{{- $host -}}
{{- end -}}
{{- end -}}

{{- define "adversarygraph.databasePort" -}}
{{- if .Values.postgresql.enabled -}}
{{- "5432" -}}
{{- else -}}
{{- $port := toString (.Values.postgresql.externalPort | default "5432") -}}
{{- if not (regexMatch "^[0-9]{1,5}$" $port) -}}
{{- fail "postgresql.externalPort must be an integer from 1 to 65535" -}}
{{- end -}}
{{- $numericPort := int $port -}}
{{- if or (lt $numericPort 1) (gt $numericPort 65535) -}}
{{- fail "postgresql.externalPort must be an integer from 1 to 65535" -}}
{{- end -}}
{{- $port -}}
{{- end -}}
{{- end -}}

{{- define "adversarygraph.databaseEnvironment" -}}
- name: DB_HOST
  value: {{ include "adversarygraph.databaseHost" . | quote }}
- name: DB_PORT
  value: {{ include "adversarygraph.databasePort" . | quote }}
- name: DB_NAME
  valueFrom:
    secretKeyRef:
      name: {{ include "adversarygraph.secretName" . }}
      key: DB_NAME
- name: DB_USER
  valueFrom:
    secretKeyRef:
      name: {{ include "adversarygraph.secretName" . }}
      key: DB_USER
- name: DB_PASS
  valueFrom:
    secretKeyRef:
      name: {{ include "adversarygraph.secretName" . }}
      key: DB_PASS
- name: HOME
  value: /tmp
{{- end -}}

{{- define "adversarygraph.schemaAuthorityInitContainer" -}}
- name: schema-authority
  image: {{ include "adversarygraph.componentImage" .Values.image | quote }}
  imagePullPolicy: {{ .Values.global.imagePullPolicy }}
  command: ["python", "-c"]
  args:
    - |
      import asyncio

      from sqlalchemy import text

      from app.core.database import engine, verify_migration_owned_schema
      from app.core.migration_policy import REQUIRED_SCHEMA_REVISION


      async def wait_for_schema_authority() -> None:
          try:
              for _attempt in range(150):
                  try:
                      async with engine.begin() as connection:
                          relation = await connection.scalar(
                              text("SELECT to_regclass('alembic_version')")
                          )
                          if relation is None:
                              raise RuntimeError("migration ledger is absent")
                          rows = await connection.execute(
                              text("SELECT version_num FROM alembic_version ORDER BY version_num")
                          )
                          revisions = tuple(str(value) for value in rows.scalars())
                          if revisions != (REQUIRED_SCHEMA_REVISION,):
                              raise RuntimeError("migration ledger is not at the required head")
                          await verify_migration_owned_schema(connection)
                      return
                  except Exception:
                      await asyncio.sleep(2)
              raise RuntimeError("database schema authority did not become ready")
          finally:
              await engine.dispose()


      try:
          asyncio.run(wait_for_schema_authority())
      except Exception:
          raise SystemExit("database schema authority is not ready") from None
  env:
    {{- include "adversarygraph.databaseEnvironment" . | nindent 4 }}
  volumeMounts:
    - name: tmp
      mountPath: /tmp
  resources:
    {{- toYaml .Values.migration.gateResources | nindent 4 }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
{{- end -}}
