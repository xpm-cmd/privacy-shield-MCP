/**
 * execution.ts - Módulo de Seguridad de Ejecución (Capa 3)
 *
 * Analiza comandos y código antes de ejecución:
 * - Comandos bash destructivos
 * - Prompt injection en archivos
 * - Código con patrones maliciosos
 * - Dependencias vulnerables
 */
const BASH_PATTERNS = [
    // Destructivos
    { pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\s+[\/~]/, risk: "critical", desc: "Eliminación recursiva forzada en directorios sistema/home" },
    { pattern: /rm\s+-rf?\s+\/(?!\w)/, risk: "critical", desc: "Eliminación del sistema de archivos raíz" },
    { pattern: /mkfs\b/, risk: "critical", desc: "Formateo de disco" },
    { pattern: /dd\s+if=.*of=\/dev\//, risk: "critical", desc: "Escritura directa a dispositivo de bloque" },
    { pattern: /:\s*\(\)\s*\{.*\|.*&\s*\}/, risk: "critical", desc: "Fork bomb" },
    // Ejecución remota
    { pattern: /curl\s+.*\|\s*(bash|sh|zsh|python)/, risk: "critical", desc: "Pipe de descarga a shell (ejecución remota ciega)" },
    { pattern: /wget\s+.*\|\s*(bash|sh|zsh|python)/, risk: "critical", desc: "Pipe de descarga a shell (ejecución remota ciega)" },
    { pattern: /curl\s+.*-o\s+.*&&\s*(bash|sh|chmod\s+\+x)/, risk: "high", desc: "Descarga + ejecución de script" },
    { pattern: /curl\s+.*--data.*@/, risk: "high", desc: "curl enviando archivo como datos (posible exfiltración)" },
    { pattern: /curl\s+.*-F\s+.*=@/, risk: "high", desc: "curl enviando archivo vía form (posible exfiltración)" },
    // Reverse shells
    { pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp/, risk: "critical", desc: "Reverse shell bash" },
    { pattern: /nc\s+(-e|-c|--exec)\s/, risk: "critical", desc: "Netcat con ejecución de shell" },
    { pattern: /python.*-c.*socket.*connect/, risk: "critical", desc: "Reverse shell Python" },
    { pattern: /perl.*-e.*socket.*INET/, risk: "critical", desc: "Reverse shell Perl" },
    { pattern: /socat.*EXEC.*TCP/, risk: "critical", desc: "Reverse shell Socat" },
    // Exfiltración
    { pattern: /cat\s+.*\.(env|pem|key|ssh).*\|\s*curl/, risk: "critical", desc: "Exfiltración de archivos sensibles vía curl" },
    { pattern: /tar\s+.*\|\s*(curl|nc|ncat)/, risk: "critical", desc: "Empaquetado y exfiltración de datos" },
    { pattern: /base64\s+.*\|\s*curl/, risk: "critical", desc: "Encoding y exfiltración de datos" },
    // Escalada de privilegios
    { pattern: /chmod\s+(-R\s+)?[47]77/, risk: "high", desc: "Permisos excesivamente abiertos (777)" },
    { pattern: /chmod\s+[+]s/, risk: "high", desc: "Establecimiento de bit SUID" },
    { pattern: /chown\s+.*root/, risk: "high", desc: "Cambio de propiedad a root" },
    // Modificación de seguridad
    { pattern: /\/etc\/(passwd|shadow|sudoers)/, risk: "high", desc: "Acceso/modificación de archivos de autenticación del sistema" },
    { pattern: /visudo|sudoers/, risk: "high", desc: "Modificación de políticas sudo" },
    { pattern: /iptables\s+.*-F/, risk: "high", desc: "Flush de reglas de firewall" },
    { pattern: /ufw\s+disable/, risk: "high", desc: "Desactivación de firewall" },
    { pattern: /setenforce\s+0/, risk: "high", desc: "Desactivación de SELinux" },
    // Variables de entorno sensibles
    { pattern: /export\s+(PATH|LD_PRELOAD|LD_LIBRARY_PATH)\s*=/, risk: "medium", desc: "Modificación de variables de entorno críticas" },
    // Persistencia
    { pattern: /crontab\s+(-e|-r|-)/, risk: "medium", desc: "Modificación de tareas programadas" },
    { pattern: /systemctl\s+(enable|start)\s+/, risk: "medium", desc: "Habilitación de servicio del sistema" },
    { pattern: /\.bashrc|\.bash_profile|\.zshrc|\.profile/, risk: "medium", desc: "Modificación de archivos de perfil de shell" },
    // Ofuscación
    { pattern: /\$\(echo\s+.*\|\s*base64\s+-d\)/, risk: "critical", desc: "Decodificación y ejecución de base64 inline" },
    { pattern: /echo\s+.*\|\s*base64\s+-d\s*\|\s*(bash|sh)/, risk: "critical", desc: "Decodificación base64 a shell" },
    { pattern: /eval\s+["']\$\(/, risk: "high", desc: "Evaluación dinámica de subshell" },
    { pattern: /printf\s+.*\\x[0-9a-f].*\|\s*(bash|sh)/, risk: "critical", desc: "Ejecución de shellcode hex-encoded" },
];
// ============================================================
// Patrones de prompt injection
// ============================================================
const PROMPT_INJECTION_PATTERNS = [
    // Override directo
    { pattern: /ignore\s+(all\s+)?previous\s+(instructions|rules|context)/i, risk: "critical", desc: "Intento de override de instrucciones previas" },
    { pattern: /disregard\s+(all\s+)?prior\s+(instructions|rules|context)/i, risk: "critical", desc: "Intento de descartar reglas anteriores" },
    { pattern: /forget\s+(everything|all)\s+(about|you|that)/i, risk: "high", desc: "Intento de reset de contexto" },
    { pattern: /you\s+are\s+now\s+(a|an)\s+/i, risk: "high", desc: "Intento de cambio de identidad" },
    { pattern: /new\s+(system\s+)?instructions?\s*:/i, risk: "critical", desc: "Inyección de nuevas instrucciones de sistema" },
    { pattern: /\[\s*SYSTEM\s*\]/i, risk: "critical", desc: "Etiqueta falsa de sistema" },
    { pattern: /<\s*system\s*>/i, risk: "critical", desc: "Tag XML falso de sistema" },
    { pattern: /BEGIN\s+HIDDEN\s+(INSTRUCTIONS?|PROMPT)/i, risk: "critical", desc: "Instrucciones ocultas declaradas" },
    // Exfiltración de prompt
    { pattern: /repeat\s+(back|all)\s+(your|the)\s+(instructions|prompt|system)/i, risk: "high", desc: "Intento de extraer el prompt del sistema" },
    { pattern: /what\s+(are|is|were)\s+your\s+(system\s+)?prompt/i, risk: "medium", desc: "Pregunta sobre el prompt del sistema" },
    { pattern: /print\s+your\s+(system|initial)\s+(message|prompt|instructions)/i, risk: "high", desc: "Intento de imprimir prompt del sistema" },
    { pattern: /output\s+the\s+above\s+text/i, risk: "high", desc: "Intento de extraer texto previo" },
    // Jailbreak
    { pattern: /\bDAN\b\s+mode/i, risk: "high", desc: "Intento de jailbreak DAN" },
    { pattern: /developer\s+mode\s+(enabled|on|activated)/i, risk: "high", desc: "Intento de activar modo desarrollador" },
    { pattern: /act\s+as\s+if\s+you\s+have\s+no\s+(restrictions|limits|rules)/i, risk: "high", desc: "Intento de remoción de restricciones" },
    { pattern: /pretend\s+(you\s+)?(are|have)\s+no\s+(filters|restrictions)/i, risk: "high", desc: "Intento de bypass de filtros" },
    { pattern: /in\s+this\s+hypothetical\s+scenario/i, risk: "medium", desc: "Posible frameo hipotético para bypass" },
    { pattern: /for\s+(educational|research)\s+purposes\s+only/i, risk: "low", desc: "Disclaimer educativo (usado frecuentemente en jailbreaks)" },
    // Social engineering al agente
    { pattern: /this\s+is\s+(a|an)\s+(authorized|official)\s+(test|request)/i, risk: "high", desc: "Suplantación de autorización" },
    { pattern: /admin\s+(override|access|mode)/i, risk: "critical", desc: "Intento de acceso administrativo falso" },
    { pattern: /authorized\s+(by|from)\s+(anthropic|openai|admin|developer|management)/i, risk: "critical", desc: "Suplantación de autorización empresarial" },
    // Instrucciones ocultas en caracteres invisibles
    { pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF]{3,}/g, risk: "critical", desc: "Caracteres Unicode invisibles (posible texto oculto)" },
    { pattern: /[\u0400-\u04FF]{5,}/g, risk: "medium", desc: "Texto cirílico extenso (posible homoglyph attack)" },
];
// ============================================================
// Patrones de código malicioso
// ============================================================
const CODE_PATTERNS = [
    // Ejecución de sistema
    { pattern: /child_process\s*[.(]|require\s*\(\s*['"]child_process['"]\s*\)/, risk: "high", desc: "Acceso a child_process (ejecución de comandos)" },
    { pattern: /\.exec\s*\(|\.spawn\s*\(|\.execSync\s*\(/, risk: "high", desc: "Ejecución de comandos del sistema" },
    { pattern: /subprocess|os\.system|os\.popen|os\.exec/, risk: "high", desc: "Ejecución de comandos del sistema (Python)" },
    { pattern: /eval\s*\(/, risk: "high", desc: "eval() — ejecución dinámica de código" },
    { pattern: /Function\s*\(/, risk: "high", desc: "Constructor Function (ejecución dinámica)" },
    { pattern: /__import__\s*\(/, risk: "high", desc: "Import dinámico Python" },
    // Acceso a datos sensibles
    { pattern: /document\.cookie/, risk: "high", desc: "Acceso a cookies del navegador" },
    { pattern: /localStorage|sessionStorage/, risk: "medium", desc: "Acceso a almacenamiento del navegador" },
    { pattern: /process\.env\b/, risk: "medium", desc: "Acceso a variables de entorno" },
    // Inyección web
    { pattern: /innerHTML\s*=/, risk: "medium", desc: "Asignación innerHTML (posible XSS)" },
    { pattern: /dangerouslySetInnerHTML\s*[=:{]/, risk: "medium", desc: "dangerouslySetInnerHTML en React (posible XSS) — sanitizar con DOMPurify" },
    { pattern: /document\.write\s*\(/, risk: "medium", desc: "document.write (posible XSS)" },
    { pattern: /\.outerHTML\s*=/, risk: "medium", desc: "Manipulación outerHTML" },
    // Red / exfiltración
    { pattern: /new\s+WebSocket\s*\(/, risk: "medium", desc: "Conexión WebSocket" },
    { pattern: /net\.createServer/, risk: "medium", desc: "Creación de servidor de red" },
    { pattern: /socket\.socket/, risk: "medium", desc: "Creación de socket" },
    { pattern: /fetch\s*\(.*process\.env/, risk: "high", desc: "Envío de variables de entorno vía fetch" },
    { pattern: /XMLHttpRequest.*process\.env|process\.env.*XMLHttpRequest/, risk: "high", desc: "Envío de env vars vía XHR" },
    // Serialización insegura
    { pattern: /pickle\.loads?\s*\(/, risk: "high", desc: "Deserialización pickle (ejecución arbitraria de código)" },
    { pattern: /yaml\.load\s*\((?!.*Loader)/, risk: "high", desc: "yaml.load sin Loader seguro" },
    { pattern: /JSON\.parse\s*\(\s*(?!.*try)/, risk: "low", desc: "JSON.parse sin try-catch" },
    // Crypto (contexto de ransomware)
    { pattern: /crypto\.createCipher(?!iv)/, risk: "medium", desc: "createCipher depreciado (sin IV)" },
    { pattern: /fs\.readdir.*crypto.*fs\.writeFile/, risk: "high", desc: "Patrón de lectura+cifrado+escritura (posible ransomware)" },
];
// ============================================================
// Patrones de GitHub Actions workflow injection
// ============================================================
const GITHUB_ACTIONS_RISKY_INPUTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
];
/**
 * Detects GitHub Actions workflow injection vulnerabilities.
 * Unsafe pattern: using ${{ github.event.* }} directly in run: commands
 * Safe pattern: pass through env: variables instead
 */
function analyzeGitHubActionsInjection(code, filePath) {
    const findings = [];
    // Only analyze if it looks like a GitHub Actions workflow
    const isWorkflow = filePath
        ? /\.github[/\\]workflows[/\\].*\.ya?ml$/i.test(filePath)
        : /on:\s*\n\s+(push|pull_request|issues|issue_comment|workflow_dispatch)/m.test(code);
    if (!isWorkflow)
        return findings;
    // Check for direct interpolation of risky inputs in run: blocks
    for (const input of GITHUB_ACTIONS_RISKY_INPUTS) {
        const escaped = input.replace(/\./g, "\\.").replace(/\*/g, "[^}]+");
        const pattern = new RegExp(`run:.*\\$\\{\\{\\s*${escaped}\\s*\\}\\}`, "gm");
        if (pattern.test(code)) {
            findings.push({
                category: "code",
                description: `GitHub Actions injection: $\{${input}} usado directamente en run: — usar env: variable en su lugar`,
                risk: "high",
                detail: `Patrón inseguro: run: echo "$\{${input}}". Patrón seguro: env: TITLE: $\{${input}} + run: echo "$TITLE"`,
            });
        }
    }
    // Generic check: any ${{ github.event.* }} in run: blocks
    const genericPattern = /run:.*\$\{\{\s*github\.event\.[^}]+\}\}/gm;
    const matches = code.match(genericPattern);
    if (matches && findings.length === 0) {
        findings.push({
            category: "code",
            description: "GitHub Actions injection: interpolación directa de github.event.* en run: — riesgo de inyección de comandos",
            risk: "high",
            detail: matches[0].slice(0, 200),
        });
    }
    return findings;
}
// ============================================================
// Funciones de análisis
// ============================================================
export function analyzeBash(command) {
    const findings = [];
    let maxRisk = "safe";
    const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const { pattern, risk, desc } of BASH_PATTERNS) {
        if (pattern.test(command)) {
            findings.push({ category: "bash", description: desc, risk, detail: command.trim().slice(0, 200) });
            if (riskOrder[risk] > riskOrder[maxRisk])
                maxRisk = risk;
        }
    }
    // Detectar pipes encadenados excesivos
    const pipeCount = (command.match(/\|/g) || []).length;
    if (pipeCount > 6) {
        findings.push({
            category: "bash",
            description: `Cadena de ${pipeCount} pipes (posible ofuscación)`,
            risk: "medium",
            detail: command.trim().slice(0, 200),
        });
        if (riskOrder["medium"] > riskOrder[maxRisk])
            maxRisk = "medium";
    }
    return {
        safe: findings.length === 0,
        risk_level: maxRisk,
        findings,
        summary: findings.length === 0
            ? "✅ Comando parece seguro."
            : `⚠️ ${findings.length} riesgo(s) detectado(s) — Nivel: ${maxRisk.toUpperCase()}`,
        recommendations: maxRisk === "critical"
            ? ["🚫 NO EJECUTAR — Comando potencialmente destructivo o malicioso"]
            : maxRisk === "high"
                ? ["⚠️ Revisar cuidadosamente antes de ejecutar"]
                : ["Proceder con precaución"],
    };
}
export function analyzePromptInjection(text) {
    const findings = [];
    let maxRisk = "safe";
    const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const { pattern, risk, desc } of PROMPT_INJECTION_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(text);
        if (match) {
            findings.push({
                category: "prompt_injection",
                description: desc,
                risk,
                detail: match[0].slice(0, 100),
            });
            if (riskOrder[risk] > riskOrder[maxRisk])
                maxRisk = risk;
        }
    }
    return {
        safe: findings.length === 0,
        risk_level: maxRisk,
        findings,
        summary: findings.length === 0
            ? "✅ No se detectó prompt injection."
            : `🛡️ ${findings.length} patrón(es) de prompt injection detectado(s) — Nivel: ${maxRisk.toUpperCase()}`,
        recommendations: findings.length > 0
            ? ["No procesar el contenido sin revisión manual",
                "El texto podría estar diseñado para manipular al agente de IA"]
            : ["Contenido parece limpio"],
    };
}
export function analyzeCode(code, filePath) {
    const findings = [];
    let maxRisk = "safe";
    const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const { pattern, risk, desc } of CODE_PATTERNS) {
        const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
        const matches = code.match(new RegExp(pattern.source, flags));
        if (matches) {
            findings.push({
                category: "code",
                description: `${desc} (${matches.length}x)`,
                risk,
                detail: matches[0].slice(0, 100),
            });
            if (riskOrder[risk] > riskOrder[maxRisk])
                maxRisk = risk;
        }
    }
    // GitHub Actions workflow injection detection
    const ghaFindings = analyzeGitHubActionsInjection(code, filePath);
    for (const f of ghaFindings) {
        findings.push(f);
        if (riskOrder[f.risk] > riskOrder[maxRisk])
            maxRisk = f.risk;
    }
    // Detección de código ofuscado
    const lines = code.split("\n").filter(l => l.trim());
    const avgLen = lines.reduce((s, l) => s + l.length, 0) / (lines.length || 1);
    if (avgLen > 300) {
        findings.push({
            category: "code",
            description: "Código con líneas muy largas — posiblemente ofuscado/minificado",
            risk: "medium",
            detail: `Promedio: ${Math.round(avgLen)} chars/línea`,
        });
        if (riskOrder["medium"] > riskOrder[maxRisk])
            maxRisk = "medium";
    }
    return {
        safe: findings.length === 0,
        risk_level: maxRisk,
        findings,
        summary: findings.length === 0
            ? "✅ Código parece seguro (análisis estático)."
            : `🔍 ${findings.length} patrón(es) de riesgo en código — Nivel: ${maxRisk.toUpperCase()}`,
        recommendations: findings.length > 0
            ? ["Revisar los patrones detectados antes de ejecutar",
                "Verificar que las operaciones de red/archivos son intencionales"]
            : ["Código parece seguro en análisis estático"],
    };
}
//# sourceMappingURL=execution.js.map