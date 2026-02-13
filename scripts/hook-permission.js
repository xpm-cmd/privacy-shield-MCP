// Privacy Shield - PermissionRequest hook
// Adds context to permission dialogs so the user gets informed justification
// Reads JSON from stdin, outputs JSON with additionalContext

let data = '';
process.stdin.on('data', c => data += c);
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(data);
    const tool = input.tool_name || '';
    const toolInput = input.tool_input || {};

    // Build context message based on tool type
    let context = '';

    if (tool === 'Bash') {
      const cmd = (toolInput.command || '').slice(0, 300);
      const risks = [];

      if (/rm\s/.test(cmd)) risks.push('ELIMINA archivos');
      if (/curl|wget|fetch/i.test(cmd)) risks.push('CONEXION de red');
      if (/sudo|chmod|chown/i.test(cmd)) risks.push('PERMISOS del sistema');
      if (/pip install|npm install|gem install/i.test(cmd)) risks.push('INSTALA paquetes');
      if (/git push|git reset/i.test(cmd)) risks.push('MODIFICA repositorio remoto');
      if (/docker|kubectl/i.test(cmd)) risks.push('CONTENEDORES/CLUSTER');
      if (/kill|pkill|systemctl/i.test(cmd)) risks.push('PROCESOS del sistema');
      if (/>\s|>>|tee\s/i.test(cmd)) risks.push('ESCRIBE a archivo');
      if (/ssh|scp|rsync/i.test(cmd)) risks.push('ACCESO remoto');
      if (/env|export\s/i.test(cmd)) risks.push('VARIABLES de entorno');

      const riskStr = risks.length > 0
        ? `Operaciones detectadas: [${risks.join(', ')}]`
        : 'Operacion de bajo riesgo';

      context = [
        `PRIVACY-SHIELD requiere que Claude justifique esta accion:`,
        `Comando: ${cmd}`,
        `${riskStr}`,
        ``,
        `Claude: antes de que el usuario apruebe, DEBES explicar:`,
        `1. QUE hace este comando exactamente`,
        `2. POR QUE es necesario para la tarea actual`,
        `3. QUE archivos o sistemas afecta`,
        `4. Es REVERSIBLE? Si no, explica las consecuencias`,
      ].join('\n');

    } else if (tool === 'Write' || tool === 'Edit') {
      const filePath = toolInput.file_path || '';
      const isNew = tool === 'Write';

      context = [
        `PRIVACY-SHIELD requiere que Claude justifique esta accion:`,
        `${isNew ? 'Crear/Sobrescribir' : 'Editar'}: ${filePath}`,
        ``,
        `Claude: antes de que el usuario apruebe, DEBES explicar:`,
        `1. QUE cambios se haran en este archivo`,
        `2. POR QUE son necesarios para la tarea actual`,
        `3. Hay RIESGO de romper funcionalidad existente?`,
      ].join('\n');

    } else if (tool === 'WebFetch' || tool === 'WebSearch') {
      const url = toolInput.url || toolInput.query || '';

      context = [
        `PRIVACY-SHIELD requiere que Claude justifique esta accion:`,
        `Acceso web: ${url}`,
        ``,
        `Claude: antes de que el usuario apruebe, DEBES explicar:`,
        `1. QUE informacion necesitas de esta URL/busqueda`,
        `2. POR QUE no puedes resolver esto sin acceso web`,
      ].join('\n');

    } else if (/^mcp__/.test(tool)) {
      context = [
        `PRIVACY-SHIELD requiere que Claude justifique esta accion:`,
        `Herramienta MCP: ${tool}`,
        ``,
        `Claude: antes de que el usuario apruebe, DEBES explicar:`,
        `1. QUE hace esta herramienta`,
        `2. POR QUE es necesaria para la tarea actual`,
      ].join('\n');

    } else {
      // Generic fallback
      context = [
        `PRIVACY-SHIELD: Claude debe justificar por que necesita usar "${tool}" antes de que el usuario apruebe.`,
      ].join('\n');
    }

    // Output JSON with additionalContext for Claude
    const output = {
      hookSpecificOutput: {
        hookEventName: "PermissionRequest",
        additionalContext: context
      }
    };

    process.stdout.write(JSON.stringify(output));

  } catch {
    // On error, allow through silently
    process.exit(0);
  }
});
