# Privacy Shield MCP — Guía de Solución de Problemas

## Índice

1. [El MCP server no inicia](#el-mcp-server-no-inicia)
2. [Los hooks no se ejecutan](#los-hooks-no-se-ejecutan)
3. [Error de permisos en scripts](#error-de-permisos-en-scripts)
4. [npm audit falla en la instalación](#npm-audit-falla-en-la-instalación)
5. [Falsos positivos (detecciones incorrectas)](#falsos-positivos-detecciones-incorrectas)
6. [Demoras de 25-30 segundos en Windows](#demoras-de-25-30-segundos-en-windows)
7. [Error: "cannot be loaded because running scripts is disabled"](#error-cannot-be-loaded-because-running-scripts-is-disabled)
8. [El log de auditoría crece demasiado](#el-log-de-auditoría-crece-demasiado)
9. [Estado de advertencia no se limpia entre sesiones](#estado-de-advertencia-no-se-limpia-entre-sesiones)

---

## El MCP server no inicia

### Síntomas
- Claude Code no muestra las herramientas de Privacy Shield
- Errores en el log de Claude Code relacionados con `privacy-shield`

### Diagnóstico paso a paso

**1. Verificar Node.js ≥ 18:**
```bash
node --version
# Debe mostrar v18.x.x o superior
```

**2. Verificar que el SDK está instalado:**
```bash
cd /ruta/al/privacy-shield-MCP/server
npm ls @modelcontextprotocol/sdk
```

**3. Verificar que el build existe:**
```bash
ls -la dist/index.js
# Debe existir. Si no, ejecuta: npm run build
```

**4. Probar el server manualmente:**
```bash
echo '{}' | node dist/index.js
# Debe responder sin error (puede quedar esperando input — eso es normal)
# Ctrl+C para salir
```

**5. Verificar el registro del plugin (`~/.claude/installed_plugins.json`):**
```json
{
  "privacy-shield@local": {
    "enabled": true,
    "installPath": "ruta/absoluta/al/plugin"
  }
}
```

---

## Los hooks no se ejecutan

### Síntomas
- Privacy Shield no bloquea comandos peligrosos
- No aparecen mensajes `PRIVACY-SHIELD:` en el terminal

### Diagnóstico

**1. Verificar que los scripts son ejecutables (macOS/Linux):**
```bash
ls -la scripts/*.js
# Debe mostrar -rwxr-xr-x (x = ejecutable)
# Si no, ejecutar:
chmod +x scripts/*.js
```

**2. En Windows, verificar la política de PowerShell:**
```powershell
Get-ExecutionPolicy
# Si muestra "Restricted", ejecutar:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**3. Verificar `hooks/hooks.json`:**
```bash
cat hooks/hooks.json
# Debe tener los matchers para Bash, Edit, Write, MultiEdit, WebFetch
```

**4. Verificar que el plugin tiene el hook registrado en `enabledPlugins` de settings.json:**
```json
{
  "enabledPlugins": ["privacy-shield@local"]
}
```

---

## Error de permisos en scripts

### Windows: "Access is denied" o "Permission denied"

**Causa:** Los scripts `.js` no tienen permiso de ejecución en la carpeta de destino.

**Solución:**
```powershell
# En PowerShell como usuario normal:
icacls "C:\ruta\al\plugin\scripts\*.js" /grant "%USERNAME%:RX"
```

### macOS/Linux: "Permission denied"

**Causa:** Falta el bit de ejecución.

**Solución:**
```bash
chmod +x /ruta/al/plugin/scripts/*.js
```

---

## npm audit falla en la instalación

### Síntomas
- `npm install` muestra vulnerabilidades y se detiene

### Solución

Las vulnerabilidades reportadas son en dependencias de desarrollo (hono, ajv) y tienen bajo impacto real (no usadas en rutas vulnerables).

```bash
cd server
npm audit fix
npm test          # Verificar que los 122 tests pasan
npm run build     # Reconstruir
```

Si `npm audit fix` no resuelve todo:
```bash
npm audit fix --force
```

---

## Falsos positivos (detecciones incorrectas)

### Síntomas
- Privacy Shield bloquea comandos o archivos legítimos
- Muchas advertencias innecesarias

### Solución 1: Modo Allowlist

Crear `~/.privacy-shield/config.json`:
```json
{
  "allowlist_mode": true,
  "allowlist_preset": "development",
  "allowlist_extra": ["mi-herramienta-custom"]
}
```

Presets disponibles:
- `"development"` — 40+ herramientas (git, npm, python, docker, etc.)
- `"read-only"` — 20 comandos seguros solo de lectura

### Solución 2: Reintentar la operación

Para patrones de código (Layer 2 del hook de archivos), Privacy Shield bloquea la **primera vez** y permite en el **segundo intento**. Esto es intencional — te fuerza a revisar el contenido antes de proceder.

### Solución 3: Limpiar estado de advertencias

```bash
rm ~/.privacy-shield/content_warnings_*.json
```

---

## Demoras de 25-30 segundos en Windows

### Causa
CrowdStrike Falcon u otro antivirus empresarial escanea cada `.js` cuando se ejecuta por primera vez.

### Comportamiento esperado
- **Primera ejecución de cada hook:** 25-30 segundos (scan de CrowdStrike)
- **Ejecuciones posteriores:** <100ms (archivo ya en caché del AV)

### Solución
No hay workaround para usuarios sin permisos de administrador. La demora desaparece después del primer uso.

**Para IT/Administradores:** Agregar la ruta del plugin a la whitelist de CrowdStrike:
```
C:\Users\%USERNAME%\.claude\plugins\cache\local\privacy-shield\
```

---

## Error: "cannot be loaded because running scripts is disabled"

### Causa
La política de ejecución de PowerShell bloquea scripts externos.

### Solución
```powershell
# Ejecutar UNA VEZ por usuario:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Verificar:
Get-ExecutionPolicy
# Debe mostrar: RemoteSigned
```

---

## El log de auditoría crece demasiado

### Comportamiento normal
El log en `~/.privacy-shield/audit.jsonl` se rota automáticamente al superar **10MB**, conservando las últimas 5,000 líneas.

### Si el archivo crece más rápido de lo esperado

**Ver tamaño actual:**
```bash
ls -lh ~/.privacy-shield/audit.jsonl
```

**Limpiar manualmente:**
```bash
# Opción A: Borrar completamente (se crea nuevo vacío)
rm ~/.privacy-shield/audit.jsonl

# Opción B: Conservar las últimas 1000 líneas
tail -1000 ~/.privacy-shield/audit.jsonl > /tmp/audit_temp.jsonl
mv /tmp/audit_temp.jsonl ~/.privacy-shield/audit.jsonl
```

---

## Estado de advertencia no se limpia entre sesiones

### Síntomas
- Privacy Shield sigue bloqueando algo que ya aprobaste en una sesión anterior
- Los archivos `content_warnings_*.json` son muy antiguos

### Solución

Los archivos de estado se limpian automáticamente después de **30 días** (con 10% de probabilidad por ejecución de hook).

**Limpiar manualmente:**
```bash
rm ~/.privacy-shield/content_warnings_*.json
```

---

## Obtener más información

Para reporte de bugs o contribuciones, visita:
[https://github.com/xpm-cmd/privacy-shield-MCP](https://github.com/xpm-cmd/privacy-shield-MCP)
