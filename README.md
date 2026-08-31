# sshaudit

Auditoría **interna post-autenticación** de escalada de privilegios en servidores
Linux, vía SSH. Simula la fase de post-explotación de un pentest: partiendo de
una shell autenticada sin privilegios, enumera el host y **razona en términos de
rutas de ataque hacia root**, confirmando de forma no destructiva las de bajo
riesgo.

> ⚠️ **Solo para infraestructura propia o con autorización explícita por escrito.**
> sshaudit abre sesiones SSH autenticadas y ejecuta código de enumeración en los
> servidores del inventario. Usarlo contra sistemas de terceros sin permiso es
> ilegal. Los reportes contienen información sensible (rutas de binarios,
> permisos, ubicación de claves, condiciones explotables): trátelos con permisos
> restrictivos y **no los suba a repositorios**.

## Qué hace y qué no

**Sí:**
- Enumera kernel/distro, usuarios y grupos, SUID/SGID, capabilities, sudoers,
  cron y systemd timers, PATH, world-writable, NFS, credenciales expuestas,
  Docker/LXD, wildcard injection.
- Cruza los datos contra listas locales versionadas (GTFOBins-like, CVEs de
  kernel, grupos privilegiados).
- **Valida de forma controlada y reversible** las rutas de bajo riesgo (ej.
  `sudo -n` sobre un binario de GTFOBins ejecuta `id` y comprueba `uid=0`;
  cron script escribible → `test -w`). Nunca modifica el sistema, no crea
  usuarios ni backdoors.
- Produce datos crudos en JSON + un reporte narrativo tipo bitácora de pentester
  (rutas confirmadas vs. potenciales vs. teóricas).
- Compara cada corrida con la anterior y notifica (Slack/Discord/email).

**No:**
- Reconocimiento externo, escaneo de puertos, fuerza bruta.
- Ejecución de exploits reales (kernel LPE, escapes destructivos): solo se
  reporta la condición necesaria, marcada como *teórico / no probado*.
- Persistir nada en disco del servidor auditado: el script de enumeración viaja
  por `stdin` y vive solo en memoria durante la corrida.

## Requisitos

| Dónde | Qué |
|---|---|
| Máquina del operador | Python 3.8+ y el cliente `ssh` del sistema. Corre igual en Linux y macOS. **Sin `pip install`** — solo librería estándar. |
| Opcional | `sshpass` (solo si algún host usa `auth: password`; con claves/agent no hace falta). |
| Servidores auditados | Linux (probado en Debian/Ubuntu y RHEL/CentOS). Herramientas estándar ya presentes; no se instala nada. |

## Instalación

```sh
git clone <este-repo> sshaudit
cd sshaudit
cp inventory.example.yml inventory.yml     # editar
cp .env.example .env                        # editar si se usan notificaciones
make test                                   # opcional: 150+ tests, sin red
./bin/sshaudit --help
```

No hay paso de build. Opcionalmente, agregá `bin/` al PATH o creá un symlink.

## Configuración

### `inventory.yml` (no se versiona)

```yaml
authorized: true            # confirmás que podés auditar estos hosts
defaults: { user: audit, port: 22, auth: agent }
hosts:
  - alias: web-prod-1
    host: 10.0.1.20
    user: www-data
    auth: key
    key: ~/.ssh/audit_ed25519
    tags: [prod, web]
  - alias: db-1
    host: db1.internal        # puede ser un alias de ~/.ssh/config
    auth: agent
    tags: [prod, db]
  - alias: staging-1
    host: 10.0.2.15
    auth: password
    password_env: STAGING1_SSH_PASSWORD   # el valor va en .env, nunca acá
```

`auth`: `agent` (SSH agent), `key` (requiere `key:`), `password` (requiere
`password_env:` — el **nombre** de una variable de entorno, jamás la contraseña).

### `.env` (no se versiona)

Copiá `.env.example`. Todo es opcional; un canal de notificación queda
deshabilitado si faltan sus variables.

```sh
SSHAUDIT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SSHAUDIT_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SSHAUDIT_SMTP_HOST=smtp.example.com
SSHAUDIT_EMAIL_FROM=alerts@example.com
SSHAUDIT_EMAIL_TO=secops@example.com, oncall@example.com
STAGING1_SSH_PASSWORD=...
```

## Uso

```sh
./bin/sshaudit                       # menú interactivo

./bin/sshaudit list                  # ver inventario
./bin/sshaudit check                 # verificar acceso SSH a todos
./bin/sshaudit check web-prod-1

./bin/sshaudit scan                  # escanear todos los hosts habilitados
./bin/sshaudit scan web-prod-1 db-1  # solo algunos
./bin/sshaudit scan --tag prod       # por tag
./bin/sshaudit scan --sequential     # uno por uno (default: en paralelo)
./bin/sshaudit scan --mode enumerate # solo recolectar, sin validar nada
./bin/sshaudit scan --aggressive     # habilita pruebas Tier B (ver abajo)

./bin/sshaudit report web-prod-1     # imprimir el último reporte narrativo
./bin/sshaudit diff web-prod-1       # qué cambió desde la corrida anterior
./bin/sshaudit show                  # historial de corridas por host
```

### Modos de validación

| Modo | Qué prueba | Cuándo |
|---|---|---|
| `enumerate` | Nada. Solo recolecta datos. Todo queda como *potencial*. | Baseline, entornos muy sensibles. |
| `validate` (default) | **Tier A**: pruebas de solo lectura (ejecutar `id`, `test -w`, leer un archivo solo-root). Reversibles, no destructivas. | Uso normal. |
| `aggressive` | Además **Tier B**: escape de contenedor con imagen local (`docker run --rm`), PoC de cron con append+revert. Sigue sin dejar cambios permanentes. | Solo con autorización específica. |

Los exploits de kernel y todo lo que pueda causar daño (**Tier C**) nunca se
ejecutan: se reportan como *teórico / no probado — alto riesgo*.

### Cron

```cron
# /etc/cron.d/sshaudit  — auditoría diaria a las 03:15
15 3 * * *  audit  cd /opt/sshaudit && ./bin/sshaudit --inventory inventory.yml scan --auto >> /var/log/sshaudit.log 2>&1
```

`--auto`: sin prompts, escanea todos los hosts habilitados, envía
notificaciones. Código de salida `1` si se confirmó root en algún host, si
aparecieron rutas confirmadas nuevas, o si algún host falló; `0` si todo OK.
Un host caído o sin acceso **no interrumpe** el resto de la corrida.

## Resultados

```
results/<alias>/<UTC timestamp>/
├── enumeration.json    # datos crudos por sección (para diffear)
├── findings.json       # correlación: rutas + hallazgos (máquina)
├── report.md           # reporte narrativo de ataque
├── diff.json / diff.md # cambios respecto de la corrida anterior
├── meta.json           # metadatos: hash del payload, versión, duración, estado
└── raw_stderr.txt      # diagnósticos del script remoto (si hubo)
results/<alias>/latest -> <UTC timestamp más reciente>
```

Archivos `0600` dentro de directorios `0700`. `results/` está en `.gitignore`.

## Agregar reglas de correlación

Cada regla es un archivo YAML en `rules/`:

```yaml
id: mi-regla
title: "Descripción corta"
severity: critical            # critical | high | medium | low | info
category: sudo
tier: A                       # A (auto) | B (--aggressive) | C (nunca)
reaches_root: true
validator: from_validation    # función en sshaudit/correlation/validators.py
validation_hint: mi-hint      # matchea validations[].rule_hint del script remoto
match:                        # cuándo aplica (DSL declarativo)
  all:
    - path: sudo.nopasswd_binaries
      not_empty: true
exploitation_steps: | ...
remediation: | ...
references: [ ... ]
```

Operadores del `match`: `not_empty`, `empty`, `equals`, `in`, `contains`,
`contains_any`, `regex`, `gte`, `lte`, `truthy`, más `where:` para cuantificar
sobre listas, y `all` / `any` / `not`.

Si la regla reusa un validador existente (`from_validation`, `list_items`,
`kernel_cve`, `nfs_no_root_squash`, `readable_secrets`) el cambio es **solo
YAML**. Las reglas se validan al arrancar: un error tira el proceso.

## Actualizar listas de referencia

Archivos versionados en `data/`, editados a mano:
- `dangerous_binaries.yml` — binarios GTFOBins-like con técnicas de prueba/exploit.
- `kernel_cves.yml` — CVEs de LPE de kernel con rangos de versión y backports.
- `privileged_groups.yml` — grupos root-equivalentes.

## Tests

```sh
make test          # o:  python3 -m unittest discover
```

Cubren: parseo y validación de inventario; el lector YAML propio; parseo y diff
de resultados; el motor de correlación con fixtures simulados (sin servidor
real); construcción de argv SSH; aislamiento del runner; notificaciones con
transporte falso; y un smoke test del script de enumeración.

## Diseño (resumen)

- **Orquestador y motor de correlación:** Python 3.8+, solo stdlib. Se hace
  shell-out al `ssh` del sistema (hereda `~/.ssh/config`, agent, ProxyJump).
- **Script remoto:** bash portable (3.2+), se envía por `ssh host 'bash -s'`,
  emite un único JSON. Las listas de referencia se le inyectan en un preámbulo
  generado desde `data/*.yml` — una sola fuente de verdad, local.
- **Reglas:** declarativas (YAML) + validadores nombrados en Python. Lo mecánico
  (probar) vive en el script remoto; lo decisorio (severidad, estado, narrativa)
  en Python.
- **Sin dependencias externas en runtime.** Ni linPEAS ni PEASS-ng ni APIs: todo
  el código de enumeración es propio y auditable.
