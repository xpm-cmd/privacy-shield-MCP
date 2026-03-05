# Privacy Shield MCP — Instalación en Windows

## Requisitos del sistema

| Requisito | Versión mínima | Recomendada |
|-----------|---------------|-------------|
| Windows | 10 (1903+) | 11 |
| Node.js | 18.0.0 | 20 LTS |
| PowerShell | 5.1 | 7.x |
| Claude Code | Última versión | Última versión |

---

## Paso 0: Configurar PowerShell (OBLIGATORIO)

> ⚠️ **Importante:** Omitir este paso causará errores de ejecución de scripts.

Abrir PowerShell como usuario normal (no administrador) y ejecutar:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Verificar:
```powershell
Get-ExecutionPolicy
# Debe mostrar: RemoteSigned
```

---

## Paso 1: Verificar Node.js

```powershell
node --version
# Debe mostrar v18.x.x o superior

npm --version
# Debe mostrar 8.x o superior
```

Si Node.js no está instalado, descargarlo desde [nodejs.org](https://nodejs.org) y elegir la versión **LTS**.

---

## Paso 2: Clonar el repositorio

```powershell
git clone https://github.com/xpm-cmd/privacy-shield-MCP.git
cd privacy-shield-MCP
```

---

## Paso 3: Instalar dependencias y construir

```powershell
cd server
npm install --omit=dev
npm run build
```

> **Nota:** Si `npm audit` reporta vulnerabilidades, ejecutar:
> ```powershell
> npm audit fix
> npm run build
> ```

---

## Paso 4: Registrar el plugin en Claude Code

### 4a. Editar `installed_plugins.json`

Abrir `%USERPROFILE%\.claude\installed_plugins.json` y agregar:

```json
{
  "privacy-shield@local": {
    "enabled": true,
    "installPath": "C:\\ruta\\completa\\al\\privacy-shield-MCP"
  }
}
```

> **Importante en Windows:** Usar barras dobles `\\` o barras normales `/` en la ruta.

### 4b. Activar en `settings.json`

Editar `%USERPROFILE%\.claude\settings.json` y agregar al array `enabledPlugins`:

```json
{
  "enabledPlugins": ["privacy-shield@local"]
}
```

---

## Paso 5: Verificar la instalación

**Reiniciar Claude Code** y probar ejecutando en el chat:

```
Usa la herramienta full_security_scan con el texto "password=test123"
```

Si Privacy Shield está activo, deberías ver una respuesta con las herramientas de seguridad.

---

## Problemas comunes en Windows

### Error: "cannot be loaded because running scripts is disabled"

```powershell
# Solución: Ejecutar el Paso 0
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Error: "node is not recognized"

```powershell
# Verificar PATH de Node.js:
where node

# Si no aparece, agregar al PATH manualmente:
# Panel de Control → Sistema → Variables de entorno
# Agregar C:\Program Files\nodejs\ a la variable PATH
```

### Las herramientas de Privacy Shield no aparecen en Claude Code

1. Verificar que `installed_plugins.json` usa rutas con `\\` o `/`
2. Verificar que el `installPath` es la ruta COMPLETA (no relativa)
3. Verificar que `dist/index.js` existe en la carpeta `server/`
4. Reiniciar Claude Code completamente

### Demoras de 25-30 segundos

**Causa:** CrowdStrike Falcon (u otro antivirus empresarial) escanea los scripts `.js` la primera vez que se ejecutan.

**Comportamiento:** Solo ocurre la primera ejecución. Las siguientes son instantáneas.

**Para IT/Administradores:** Agregar la ruta del plugin a la whitelist de CrowdStrike:
```
C:\Users\%USERNAME%\.claude\plugins\cache\local\privacy-shield\
```

### El hook no bloquea comandos peligrosos

Verificar que `hooks/hooks.json` tiene los matchers correctos:
```json
{
  "hooks": [
    {
      "event": "PreToolUse",
      "matchers": [{"tool_name": "Bash"}],
      "command": "node ${CLAUDE_PLUGIN_ROOT}/scripts/hook-pre-bash.js"
    }
  ]
}
```

---

## Desinstalar Privacy Shield

```powershell
# 1. Eliminar de installed_plugins.json y enabledPlugins en settings.json

# 2. Eliminar datos de sesión (opcional):
Remove-Item -Recurse -Force "$env:USERPROFILE\.privacy-shield"

# 3. Eliminar el repositorio clonado:
Remove-Item -Recurse -Force "C:\ruta\al\privacy-shield-MCP"
```

---

## Rutas de archivos en Windows

| Archivo | Ubicación |
|---------|-----------|
| Configuración del usuario | `%USERPROFILE%\.privacy-shield\config.json` |
| Log de auditoría | `%USERPROFILE%\.privacy-shield\audit.jsonl` |
| Estadísticas | `%USERPROFILE%\.privacy-shield\stats.json` |
| Plugins de Claude | `%USERPROFILE%\.claude\plugins\` |
| Settings de Claude | `%USERPROFILE%\.claude\settings.json` |
