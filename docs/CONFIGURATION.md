# Privacy Shield MCP — Configuración

## Tabla de Contenido

1. [Archivo de configuración](#archivo-de-configuración)
2. [Modo Allowlist](#modo-allowlist)
3. [Presets de fábrica](#presets-de-fábrica)
4. [Allowlist personalizada](#allowlist-personalizada)
5. [Archivos de estado de los hooks](#archivos-de-estado-de-los-hooks)
6. [Carpeta de datos](#carpeta-de-datos)

---

## Archivo de configuración

Privacy Shield lee un archivo de configuración opcional en:

```
~/.privacy-shield/config.json
```

Si este archivo no existe, Privacy Shield opera en **modo estricto por defecto** (sin allowlist, bloqueando todos los patrones peligrosos).

**Estructura del archivo:**
```json
{
  "allowlist_mode": true,
  "allowlist_preset": "development",
  "allowlist_extra": ["mi-herramienta", "otro-comando"]
}
```

---

## Modo Allowlist

El **modo allowlist** es un modo alternativo donde Privacy Shield **solo permite comandos explícitamente listados** y bloquea todo lo demás.

### ¿Cuándo usarlo?

| Situación | Modo recomendado |
|-----------|-----------------|
| Entorno de producción sin privilegios | Modo estricto (sin config) |
| Desarrollo activo con herramientas conocidas | Modo allowlist `development` |
| Revisión de código o auditoría | Modo allowlist `read-only` |
| CI/CD automatizado | Modo estricto (sin config) |

### Activar modo allowlist

Crear `~/.privacy-shield/config.json`:
```json
{
  "allowlist_mode": true,
  "allowlist_preset": "development"
}
```

> **Nota:** Los bloques de seguridad crítica (reverse shells, rm -rf /, fork bombs) siempre se aplican, incluso en modo allowlist.

---

## Presets de fábrica

### `development` — Desarrollo activo

Permite ~40 herramientas comunes para desarrollo:

```
# Gestores de paquetes y runtimes
git, npm, npx, yarn, pnpm, bun, node, tsc, tsx

# Herramientas de testing y calidad
vitest, jest, eslint, prettier

# Lenguajes
python, python3, pip, pip3, uv, cargo, rustc, go

# Build tools
make, cmake, docker, docker-compose

# Red (con restricciones de los hooks)
curl, wget, ssh, scp

# Utilidades Unix
ls, cat, head, tail, grep, rg, find, wc, sort
uniq, diff, echo, printf, mkdir, cp, mv, touch
pwd, which, env

# Equivalentes Windows
dir, type, more, findstr, where, copy, move, md
```

### `read-only` — Solo lectura

Permite únicamente comandos de lectura:

```
ls, cat, head, tail, grep, rg, wc, find, diff
echo, pwd, which, env, git log, git status, git diff
dir, type, more, findstr, where
```

> **Importante:** `read-only` NO permite writes, edits, installs, o cualquier modificación.

---

## Allowlist personalizada

Puedes agregar comandos adicionales a cualquier preset:

```json
{
  "allowlist_mode": true,
  "allowlist_preset": "development",
  "allowlist_extra": [
    "mi-cli-custom",
    "herramienta-interna",
    "deploy-script"
  ]
}
```

> **Nota de seguridad:** Los comandos en `allowlist_extra` se comparan por **basename** del ejecutable (sin argumentos ni path). El comando `my-tool --flag arg` se compara como `my-tool`.

### Ejemplo completo — equipo de desarrollo

```json
{
  "allowlist_mode": true,
  "allowlist_preset": "development",
  "allowlist_extra": [
    "aws",
    "terraform",
    "kubectl",
    "helm",
    "pytest",
    "ruff",
    "mypy"
  ]
}
```

---

## Archivos de estado de los hooks

El hook de archivos (`hook-pre-file.js`) mantiene un estado persistente para implementar el patrón "warn once":

**Ubicación:** `~/.privacy-shield/content_warnings_{sessionId}.json`

**Qué almacena:**
- Claves únicas de advertencias ya mostradas (path del archivo + tipo de patrón)
- Permite que el segundo intento de escritura pase sin bloqueo

**Limpieza automática:**
- Se eliminan archivos con más de **30 días** de antigüedad
- La limpieza se ejecuta con **10% de probabilidad** en cada llamada al hook

**Limpiar manualmente:**
```bash
rm ~/.privacy-shield/content_warnings_*.json
```

---

## Carpeta de datos

Todos los datos de Privacy Shield se almacenan en:
```
~/.privacy-shield/
├── audit.jsonl              # Log de auditoría (JSON Lines, max 10MB)
├── stats.json               # Estadísticas de detección
├── config.json              # Tu configuración (opcional)
└── content_warnings_*.json  # Estado de advertencias por sesión
```

### Permisos recomendados (Linux/macOS)

```bash
chmod 700 ~/.privacy-shield/
chmod 600 ~/.privacy-shield/audit.jsonl
chmod 600 ~/.privacy-shield/stats.json
chmod 600 ~/.privacy-shield/config.json
```

### Respaldo

Si quieres preservar el historial de auditoría:
```bash
cp ~/.privacy-shield/audit.jsonl ~/backup/audit-$(date +%Y%m%d).jsonl
```
