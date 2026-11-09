/**
 * execution.ts - Modulo de Seguridad de Ejecucion (Capa 3) v2
 *
 * Analiza comandos y codigo antes de ejecucion:
 * - Comandos bash destructivos
 * - Prompt injection en archivos (con confidence scoring)
 * - Codigo con patrones maliciosos
 * - Dependencias vulnerables
 * - GitHub Actions workflow injection
 */

import type { RiskLevel, Finding, AnalysisResult, InjectionThreat } from './types.js';
import { RISK_ORDER } from './types.js';

// ============================================================
// Internal types
// ============================================================

interface BashPattern {
  pattern: RegExp;
  risk: RiskLevel;
  desc: string;
}

interface PromptInjectionPattern {
  pattern: RegExp;
  risk: RiskLevel;
  desc: string;
  baseConfidence: number;
  category: InjectionThreat['category'];
}

interface CodePattern {
  pattern: RegExp;
  risk: RiskLevel;
  desc: string;
}

// ============================================================
// Patrones de bash peligrosos
// ============================================================

const BASH_PATTERNS: BashPattern[] = [
  // Destructivos
  { pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\s+[\/~]/, risk: "critical", desc: "Eliminacion recursiva forzada en directorios sistema/home" },
  { pattern: /rm\s+-rf?\s+\/(?!\w)/, risk: "critical", desc: "Eliminacion del sistema de archivos raiz" },
  { pattern: /mkfs\b/, risk: "critical", desc: "Formateo de disco" },
  { pattern: /dd\s+if=.*of=\/dev\//, risk: "critical", desc: "Escritura directa a dispositivo de bloque" },
  { pattern: /:\s*\(\)\s*\{.*\|.*&\s*\}/, risk: "critical", desc: "Fork bomb" },

  // Ejecucion remota
  { pattern: /curl\s+.*\|\s*(bash|sh|zsh|python)/, risk: "critical", desc: "Pipe de descarga a shell (ejecucion remota ciega)" },
  { pattern: /wget\s+.*\|\s*(bash|sh|zsh|python)/, risk: "critical", desc: "Pipe de descarga a shell (ejecucion remota ciega)" },
  { pattern: /curl\s+.*-o\s+.*&&\s*(bash|sh|chmod\s+\+x)/, risk: "high", desc: "Descarga + ejecucion de script" },
  { pattern: /curl\s+.*--data.*@/, risk: "high", desc: "curl enviando archivo como datos (posible exfiltracion)" },
  { pattern: /curl\s+.*-F\s+.*=@/, risk: "high", desc: "curl enviando archivo via form (posible exfiltracion)" },

  // Reverse shells
  { pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp/, risk: "critical", desc: "Reverse shell bash" },
  { pattern: /nc\s+(-e|-c|--exec)\s/, risk: "critical", desc: "Netcat con ejecucion de shell" },
  { pattern: /python.*-c.*socket.*connect/, risk: "critical", desc: "Reverse shell Python" },
  { pattern: /perl.*-e.*socket.*INET/, risk: "critical", desc: "Reverse shell Perl" },
  { pattern: /socat.*EXEC.*TCP/, risk: "critical", desc: "Reverse shell Socat" },

  // Exfiltracion
  { pattern: /cat\s+.*\.(env|pem|key|ssh).*\|\s*curl/, risk: "critical", desc: "Exfiltracion de archivos sensibles via curl" },
  { pattern: /tar\s+.*\|\s*(curl|nc|ncat)/, risk: "critical", desc: "Empaquetado y exfiltracion de datos" },
  { pattern: /base64\s+.*\|\s*curl/, risk: "critical", desc: "Encoding y exfiltracion de datos" },

  // Escalada de privilegios
  { pattern: /chmod\s+(-R\s+)?[47]77/, risk: "high", desc: "Permisos excesivamente abiertos (777)" },
  { pattern: /chmod\s+[+]s/, risk: "high", desc: "Establecimiento de bit SUID" },
  { pattern: /chown\s+.*root/, risk: "high", desc: "Cambio de propiedad a root" },

  // Modificacion de seguridad
  { pattern: /\/etc\/(passwd|shadow|sudoers)/, risk: "high", desc: "Acceso/modificacion de archivos de autenticacion del sistema" },
  { pattern: /visudo|sudoers/, risk: "high", desc: "Modificacion de politicas sudo" },
  { pattern: /iptables\s+.*-F/, risk: "high", desc: "Flush de reglas de firewall" },
  { pattern: /ufw\s+disable/, risk: "high", desc: "Desactivacion de firewall" },
  { pattern: /setenforce\s+0/, risk: "high", desc: "Desactivacion de SELinux" },

  // Variables de entorno sensibles
  { pattern: /export\s+(PATH|LD_PRELOAD|LD_LIBRARY_PATH)\s*=/, risk: "medium", desc: "Modificacion de variables de entorno criticas" },

  // Persistencia
  { pattern: /crontab\s+(-e|-r|-)/, risk: "medium", desc: "Modificacion de tareas programadas" },
  { pattern: /systemctl\s+(enable|start)\s+/, risk: "medium", desc: "Habilitacion de servicio del sistema" },
  { pattern: /\.bashrc|\.bash_profile|\.zshrc|\.profile/, risk: "medium", desc: "Modificacion de archivos de perfil de shell" },

  // Ofuscacion
  { pattern: /\$\(echo\s+.*\|\s*base64\s+-d\)/, risk: "critical", desc: "Decodificacion y ejecucion de base64 inline" },
  { pattern: /echo\s+.*\|\s*base64\s+-d\s*\|\s*(bash|sh)/, risk: "critical", desc: "Decodificacion base64 a shell" },
  { pattern: /eval\s+["']\$\(/, risk: "high", desc: "Evaluacion dinamica de subshell" },
  { pattern: /printf\s+.*\\x[0-9a-f].*\|\s*(bash|sh)/, risk: "critical", desc: "Ejecucion de shellcode hex-encoded" },

  // === Windows-specific patterns ===

  // Destructivos Windows
  { pattern: /del\s+\/[fFsS]\s+.*[/\\][*.]/, risk: "critical", desc: "Eliminacion recursiva forzada (Windows del /F /S)" },
  { pattern: /rd\s+\/[sS]\s+\/[qQ]\s+[A-Z]:\\/i, risk: "critical", desc: "Eliminacion recursiva de directorio raiz (Windows rd /S /Q)" },
  { pattern: /rmdir\s+\/[sS]\s+\/[qQ]\s+[A-Z]:\\/i, risk: "critical", desc: "Eliminacion recursiva de directorio (Windows rmdir /S /Q)" },
  { pattern: /format\s+[A-Z]:\s*/i, risk: "critical", desc: "Formateo de disco (Windows format)" },

  // PowerShell ejecucion remota
  { pattern: /powershell\s+.*-[eE](?:nc(?:odedCommand)?)\s+/i, risk: "critical", desc: "PowerShell con comando codificado en Base64 (-EncodedCommand)" },
  { pattern: /Invoke-WebRequest\s+.*\|\s*(?:Invoke-Expression|iex)/i, risk: "critical", desc: "Descarga y ejecucion remota via PowerShell (IWR | IEX)" },
  { pattern: /iwr\s+.*\|\s*iex/i, risk: "critical", desc: "Descarga y ejecucion remota via PowerShell (IWR | IEX alias)" },
  { pattern: /Invoke-Expression\s*\(\s*\(?\s*New-Object/i, risk: "critical", desc: "Ejecucion remota via WebClient de .NET" },
  { pattern: /DownloadString\s*\(\s*['"]https?:/, risk: "critical", desc: "Descarga de script remoto via WebClient" },

  // PowerShell reverse shells
  { pattern: /New-Object\s+System\.Net\.Sockets\.TCPClient/i, risk: "critical", desc: "Reverse shell PowerShell via TCPClient" },
  { pattern: /\$client\s*=\s*New-Object.*TCPClient/i, risk: "critical", desc: "Reverse shell PowerShell (patron de variable)" },

  // PowerShell persistencia y evasion
  { pattern: /Set-ExecutionPolicy\s+(Bypass|Unrestricted)/i, risk: "high", desc: "Bypass de politica de ejecucion de PowerShell" },
  { pattern: /Add-MpPreference\s+.*-ExclusionPath/i, risk: "high", desc: "Agregar exclusion a Windows Defender" },
  { pattern: /Set-MpPreference\s+.*-DisableRealtimeMonitoring\s+\$true/i, risk: "critical", desc: "Desactivacion de Windows Defender en tiempo real" },
  { pattern: /reg\s+add\s+.*\\CurrentVersion\\Run/i, risk: "high", desc: "Persistencia via registro de Windows (autorun)" },
  { pattern: /schtasks\s+\/create/i, risk: "medium", desc: "Creacion de tarea programada (Windows schtasks)" },

  // Windows exfiltracion
  { pattern: /certutil\s+.*-urlcache/i, risk: "high", desc: "Descarga de archivo via certutil (tecnica LOLBIN)" },
  { pattern: /bitsadmin\s+.*\/transfer/i, risk: "high", desc: "Descarga de archivo via BITS (tecnica LOLBIN)" },
];

// ============================================================
// Patrones de prompt injection (v2 con confidence y category)
// ============================================================

const PROMPT_INJECTION_PATTERNS: PromptInjectionPattern[] = [
  // --- EXISTING v1 PATTERNS (with baseConfidence + category added) ---

  // Override directo
  { pattern: /ignore\s+(all\s+)?previous\s+(instructions|rules|context)/i, risk: "critical", desc: "Intento de override de instrucciones previas", baseConfidence: 0.95, category: "override" },
  { pattern: /disregard\s+(all\s+)?prior\s+(instructions|rules|context)/i, risk: "critical", desc: "Intento de descartar reglas anteriores", baseConfidence: 0.93, category: "override" },
  { pattern: /forget\s+(everything|all)\s+(about|you|that)/i, risk: "high", desc: "Intento de reset de contexto", baseConfidence: 0.88, category: "override" },
  { pattern: /you\s+are\s+now\s+(a|an)\s+/i, risk: "high", desc: "Intento de cambio de identidad", baseConfidence: 0.85, category: "jailbreak" },
  { pattern: /new\s+(system\s+)?instructions?\s*:/i, risk: "critical", desc: "Inyeccion de nuevas instrucciones de sistema", baseConfidence: 0.92, category: "override" },
  { pattern: /\[\s*SYSTEM\s*\]/i, risk: "critical", desc: "Etiqueta falsa de sistema", baseConfidence: 0.90, category: "override" },
  { pattern: /<\s*system\s*>/i, risk: "critical", desc: "Tag XML falso de sistema", baseConfidence: 0.90, category: "override" },
  { pattern: /BEGIN\s+HIDDEN\s+(INSTRUCTIONS?|PROMPT)/i, risk: "critical", desc: "Instrucciones ocultas declaradas", baseConfidence: 0.95, category: "override" },

  // Exfiltracion de prompt
  { pattern: /repeat\s+(back|all)\s+(your|the)\s+(instructions|prompt|system)/i, risk: "high", desc: "Intento de extraer el prompt del sistema", baseConfidence: 0.88, category: "exfiltration" },
  { pattern: /what\s+(are|is|were)\s+your\s+(system\s+)?prompt/i, risk: "medium", desc: "Pregunta sobre el prompt del sistema", baseConfidence: 0.75, category: "exfiltration" },
  { pattern: /print\s+your\s+(system|initial)\s+(message|prompt|instructions)/i, risk: "high", desc: "Intento de imprimir prompt del sistema", baseConfidence: 0.88, category: "exfiltration" },
  { pattern: /output\s+the\s+above\s+text/i, risk: "high", desc: "Intento de extraer texto previo", baseConfidence: 0.85, category: "exfiltration" },

  // Jailbreak
  { pattern: /\bDAN\b\s+mode/i, risk: "high", desc: "Intento de jailbreak DAN", baseConfidence: 0.92, category: "jailbreak" },
  { pattern: /developer\s+mode\s+(enabled|on|activated)/i, risk: "high", desc: "Intento de activar modo desarrollador", baseConfidence: 0.90, category: "jailbreak" },
  { pattern: /act\s+as\s+if\s+you\s+have\s+no\s+(restrictions|limits|rules)/i, risk: "high", desc: "Intento de remocion de restricciones", baseConfidence: 0.90, category: "jailbreak" },
  { pattern: /pretend\s+(you\s+)?(are|have)\s+no\s+(filters|restrictions)/i, risk: "high", desc: "Intento de bypass de filtros", baseConfidence: 0.88, category: "jailbreak" },
  { pattern: /in\s+this\s+hypothetical\s+scenario/i, risk: "medium", desc: "Posible frameo hipotetico para bypass", baseConfidence: 0.65, category: "hypothetical" },
  { pattern: /for\s+(educational|research)\s+purposes\s+only/i, risk: "low", desc: "Disclaimer educativo (usado frecuentemente en jailbreaks)", baseConfidence: 0.45, category: "hypothetical" },

  // Social engineering al agente
  { pattern: /this\s+is\s+(a|an)\s+(authorized|official)\s+(test|request)/i, risk: "high", desc: "Suplantacion de autorizacion", baseConfidence: 0.88, category: "social_engineering" },
  { pattern: /admin\s+(override|access|mode)/i, risk: "critical", desc: "Intento de acceso administrativo falso", baseConfidence: 0.93, category: "social_engineering" },
  { pattern: /authorized\s+(by|from)\s+(anthropic|openai|admin|developer|management)/i, risk: "critical", desc: "Suplantacion de autorizacion empresarial", baseConfidence: 0.95, category: "social_engineering" },

  // Instrucciones ocultas en caracteres invisibles
  { pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF]{3,}/g, risk: "critical", desc: "Caracteres Unicode invisibles (posible texto oculto)", baseConfidence: 0.92, category: "encoding" },
  { pattern: /[\u0400-\u04FF]{5,}/g, risk: "medium", desc: "Texto cirilico extenso (posible homoglyph attack)", baseConfidence: 0.90, category: "encoding" },

  // === NEW v2 PATTERNS ===

  // Override
  { pattern: /do\s+not\s+follow\s+(the\s+)?(previous|above|prior)\s/i, risk: "critical", desc: "Intento de ignorar instrucciones anteriores", baseConfidence: 0.90, category: "override" },
  { pattern: /forget\s+(all\s+)?previous/i, risk: "high", desc: "Intento de reset de instrucciones previas", baseConfidence: 0.85, category: "override" },
  { pattern: /disregard\s+(all\s+)?(previous|above)/i, risk: "critical", desc: "Intento de descartar instrucciones", baseConfidence: 0.88, category: "override" },

  // Jailbreak (expanded)
  { pattern: /bypass\s+(your\s+)?(restrictions|limitations|rules|filters)/i, risk: "critical", desc: "Intento de bypass de restricciones", baseConfidence: 0.93, category: "jailbreak" },
  { pattern: /disable\s+(your\s+)?(safety|content\s+)?filter/i, risk: "critical", desc: "Intento de desactivar filtros de seguridad", baseConfidence: 0.96, category: "jailbreak" },
  { pattern: /without\s+(any\s+)?(restrictions|limitations|rules)/i, risk: "high", desc: "Solicitud sin restricciones", baseConfidence: 0.85, category: "jailbreak" },
  { pattern: /(?:dev(?:eloper)?|debug)\s+mode/i, risk: "high", desc: "Intento de activar modo desarrollador/debug", baseConfidence: 0.85, category: "jailbreak" },
  { pattern: /enable\s+(hidden|secret|special)\s+(features|mode|commands)/i, risk: "high", desc: "Intento de activar features ocultos", baseConfidence: 0.88, category: "jailbreak" },

  // Role switching
  { pattern: /pretend\s+(to\s+be|you\s+are)/i, risk: "medium", desc: "Intento de cambio de rol", baseConfidence: 0.65, category: "jailbreak" },
  { pattern: /reveal\s+(your\s+)?(system\s+)?prompt/i, risk: "high", desc: "Intento de extraer system prompt", baseConfidence: 0.90, category: "exfiltration" },
  { pattern: /what\s+(is|are)\s+your\s+(initial\s+)?instructions/i, risk: "medium", desc: "Consulta sobre instrucciones del sistema", baseConfidence: 0.75, category: "exfiltration" },

  // Delimiter abuse
  { pattern: /```\s*(?:system|instruction|prompt)/i, risk: "high", desc: "Abuso de code block como delimitador de sistema", baseConfidence: 0.85, category: "delimiter" },
  { pattern: /---\s*(?:system|instruction|prompt)/i, risk: "medium", desc: "Abuso de markdown delimiter como sistema", baseConfidence: 0.70, category: "delimiter" },

  // Encoding attacks
  { pattern: /(?:base64|rot13|hex)\s+(?:encode|decode|this)/i, risk: "medium", desc: "Referencia a encoding (posible evasion)", baseConfidence: 0.60, category: "encoding" },

  // Hypothetical framing
  { pattern: /hypothetically|in\s+theory|theoretically|if\s+you\s+could/i, risk: "low", desc: "Frameo hipotetico (posible bypass)", baseConfidence: 0.45, category: "hypothetical" },
];

// ============================================================
// Patrones de codigo malicioso
// ============================================================

const CODE_PATTERNS: CodePattern[] = [
  // Ejecucion de sistema
  // require()/import()/ESM "from" of child_process, with or without the node: prefix
  { pattern: /child_process\s*[.(]|(?:require\s*\(\s*|import\s*\(\s*|from\s+)['"](?:node:)?child_process['"]/, risk: "high", desc: "Acceso a child_process (ejecucion de comandos)" },
  // Bare calls (after destructuring, or Python's exec builtin) and method calls that are
  // unambiguous. A plain ".exec(" is left out: it is almost always RegExp.prototype.exec.
  { pattern: /(?<![\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|\.(?:execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|\b(?:child_process|childProcess|cp)\.exec\s*\(/, risk: "high", desc: "Ejecucion de comandos del sistema" },
  { pattern: /\bos\.(?:system|popen|exec[lv]p?e?)\s*\(|\bshell\s*=\s*True\b/, risk: "high", desc: "Ejecucion de comandos del sistema (Python)" },
  { pattern: /\bsubprocess\b/, risk: "medium", desc: "Uso de subprocess (Python) -- verificar que no use shell=True ni entrada no confiable" },
  // Detection rules, not actual usage. Lookbehinds skip model.eval(), retrieval(), isFunction().
  { pattern: /(?<![\w$.])eval\s*\(/, risk: "high", desc: "eval() -- ejecucion dinamica de codigo" },
  { pattern: /(?<![\w$.])Function\s*\(/, risk: "high", desc: "Constructor Function (ejecucion dinamica)" },
  { pattern: /__import__\s*\(/, risk: "high", desc: "Import dinamico Python" },

  // Acceso a datos sensibles
  { pattern: /document\.cookie/, risk: "high", desc: "Acceso a cookies del navegador" },
  { pattern: /localStorage|sessionStorage/, risk: "medium", desc: "Acceso a almacenamiento del navegador" },
  { pattern: /process\.env\b/, risk: "medium", desc: "Acceso a variables de entorno" },

  // Inyeccion web
  { pattern: /innerHTML\s*=/, risk: "medium", desc: "Asignacion innerHTML (posible XSS)" },
  { pattern: /dangerouslySetInnerHTML\s*[=:{]/, risk: "medium", desc: "dangerouslySetInnerHTML en React (posible XSS) -- sanitizar con DOMPurify" },
  { pattern: /document\.write\s*\(/, risk: "medium", desc: "document.write (posible XSS)" },
  { pattern: /\.outerHTML\s*=/, risk: "medium", desc: "Manipulacion outerHTML" },

  // Red / exfiltracion
  { pattern: /new\s+WebSocket\s*\(/, risk: "medium", desc: "Conexion WebSocket" },
  { pattern: /net\.createServer/, risk: "medium", desc: "Creacion de servidor de red" },
  { pattern: /socket\.socket/, risk: "medium", desc: "Creacion de socket" },
  { pattern: /fetch\s*\(.*process\.env/, risk: "high", desc: "Envio de variables de entorno via fetch" },
  { pattern: /XMLHttpRequest.*process\.env|process\.env.*XMLHttpRequest/, risk: "high", desc: "Envio de env vars via XHR" },

  // Serializacion insegura
  { pattern: /pickle\.loads?\s*\(/, risk: "high", desc: "Deserializacion pickle (ejecucion arbitraria de codigo)" },
  { pattern: /yaml\.load\s*\((?!.*Loader)/, risk: "high", desc: "yaml.load sin Loader seguro" },
  { pattern: /\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)/, risk: "high", desc: "torch.load sin weights_only=True (deserializa pickle)" },

  // Transporte
  { pattern: /\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/, risk: "medium", desc: "Verificacion TLS desactivada (riesgo MITM)" },
  { pattern: /JSON\.parse\s*\(\s*(?!.*try)/, risk: "low", desc: "JSON.parse sin try-catch" },

  // Crypto (contexto de ransomware)
  { pattern: /crypto\.createCipher(?!iv)/, risk: "medium", desc: "createCipher depreciado (sin IV)" },
  { pattern: /fs\.readdir.*crypto.*fs\.writeFile/, risk: "high", desc: "Patron de lectura+cifrado+escritura (posible ransomware)" },
];

// ============================================================
// Patrones de GitHub Actions workflow injection
// ============================================================

const GITHUB_ACTIONS_RISKY_INPUTS: string[] = [
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

// ============================================================
// Helper: normalizeInput
// ============================================================

/**
 * Normalizes input text to defeat encoding-based evasion techniques.
 * - NFKC normalization (canonical decomposition + compatibility composition)
 * - Remove zero-width and invisible Unicode characters
 * - Collapse whitespace
 */
function normalizeInput(text: string): string {
  return text
    .normalize('NFKC')
    .replace(/[\u200B-\u200F\u2028-\u202F\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

// ============================================================
// Helper: calculateConfidence
// ============================================================

/**
 * Calculates a confidence score for a pattern match, factoring in:
 * - baseConfidence of the pattern
 * - Number of co-occurring pattern matches (corroboration bonus)
 * - Short text penalty
 * - Start-of-input bonus
 */
function calculateConfidence(
  text: string,
  match: RegExpExecArray,
  baseConfidence: number,
): number {
  let confidence = baseConfidence;

  // Count other matching patterns for corroboration bonus
  let coMatchCount = 0;
  for (const p of PROMPT_INJECTION_PATTERNS) {
    const testPattern = new RegExp(p.pattern.source, p.pattern.flags.replace('g', ''));
    if (testPattern.test(text)) {
      coMatchCount++;
    }
  }
  // Subtract 1 for the current match itself
  const otherMatches = coMatchCount - 1;
  if (otherMatches > 0) {
    confidence += Math.min(0.05 * otherMatches, 0.25);
  }

  // Short text penalty: texts < 50 chars are less likely to be genuine attacks
  if (text.length < 50) {
    confidence *= 0.9;
  }

  // Start-of-input bonus: injection at position < 20 is more suspicious
  if (match.index < 20) {
    confidence += 0.05;
  }

  // Clamp to [0, 0.99]
  confidence = Math.max(0, Math.min(0.99, confidence));

  // Round to 2 decimal places
  return Math.round(confidence * 100) / 100;
}

// ============================================================
// Helper: adjustSeverity
// ============================================================

/**
 * Downgrades severity when confidence is too low for the declared risk level.
 */
function adjustSeverity(risk: RiskLevel, confidence: number): RiskLevel {
  if (risk === 'critical' && confidence < 0.5) return 'high';
  if (risk === 'high' && confidence < 0.3) return 'medium';
  return risk;
}

// ============================================================
// GitHub Actions injection analysis
// ============================================================

/**
 * Detects GitHub Actions workflow injection vulnerabilities.
 * Unsafe pattern: using ${{ github.event.* }} directly in run: commands
 * Safe pattern: pass through env: variables instead
 */
function analyzeGitHubActionsInjection(code: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // Only analyze if it looks like a GitHub Actions workflow
  const isWorkflow = filePath
    ? /\.github[/\\]workflows[/\\].*\.ya?ml$/i.test(filePath)
    : /on:\s*\n\s+(push|pull_request|issues|issue_comment|workflow_dispatch)/m.test(code);

  if (!isWorkflow) return findings;

  // Check for direct interpolation of risky inputs in run: blocks
  for (const input of GITHUB_ACTIONS_RISKY_INPUTS) {
    const escaped = input.replace(/\./g, "\\.").replace(/\*/g, "[^}]+");
    const pattern = new RegExp(`run:.*\\$\\{\\{\\s*${escaped}\\s*\\}\\}`, "gm");
    if (pattern.test(code)) {
      findings.push({
        category: "code",
        description: `GitHub Actions injection: \${${input}} usado directamente en run: -- usar env: variable en su lugar`,
        risk: "high",
        detail: `Patron inseguro: run: echo "\${${input}}". Patron seguro: env: TITLE: \${${input}} + run: echo "$TITLE"`,
      });
    }
  }

  // Generic check: any ${{ github.event.* }} in run: blocks
  const genericPattern = /run:.*\$\{\{\s*github\.event\.[^}]+\}\}/gm;
  const matches = code.match(genericPattern);
  if (matches && findings.length === 0) {
    findings.push({
      category: "code",
      description: "GitHub Actions injection: interpolacion directa de github.event.* en run: -- riesgo de inyeccion de comandos",
      risk: "high",
      detail: matches[0].slice(0, 200),
    });
  }

  return findings;
}

// ============================================================
// Public API: analyzeBash
// ============================================================

/**
 * Analyzes a bash command for destructive or malicious patterns.
 */
export function analyzeBash(command: string): AnalysisResult {
  const findings: Finding[] = [];
  let maxRisk: RiskLevel = "safe";

  for (const { pattern, risk, desc } of BASH_PATTERNS) {
    if (pattern.test(command)) {
      findings.push({
        category: "bash",
        description: desc,
        risk,
        detail: command.trim().slice(0, 200),
      });
      if (RISK_ORDER[risk] > RISK_ORDER[maxRisk]) maxRisk = risk;
    }
  }

  // Detectar pipes encadenados excesivos
  const pipeCount = (command.match(/\|/g) || []).length;
  if (pipeCount > 6) {
    findings.push({
      category: "bash",
      description: `Cadena de ${pipeCount} pipes (posible ofuscacion)`,
      risk: "medium",
      detail: command.trim().slice(0, 200),
    });
    if (RISK_ORDER["medium"] > RISK_ORDER[maxRisk]) maxRisk = "medium";
  }

  return {
    safe: findings.length === 0,
    risk_level: maxRisk,
    findings,
    summary: findings.length === 0
      ? "Comando parece seguro."
      : `${findings.length} riesgo(s) detectado(s) -- Nivel: ${maxRisk.toUpperCase()}`,
    recommendations: maxRisk === "critical"
      ? ["NO EJECUTAR -- Comando potencialmente destructivo o malicioso"]
      : maxRisk === "high"
        ? ["Revisar cuidadosamente antes de ejecutar"]
        : ["Proceder con precaucion"],
  };
}

// ============================================================
// Public API: analyzePromptInjection
// ============================================================

/**
 * Analyzes text for prompt injection patterns.
 * Enhanced v2: normalizes input, computes per-match confidence, deduplicates
 * by category (keeping highest confidence), and supports quick scan mode.
 */
export function analyzePromptInjection(
  text: string,
  options?: { quickScan?: boolean },
): AnalysisResult {
  const normalized = normalizeInput(text);
  const findings: Finding[] = [];
  let maxRisk: RiskLevel = "safe";

  // Map to track highest-confidence finding per category for deduplication
  const bestPerCategory = new Map<string, Finding & { confidence: number }>();

  for (const { pattern, risk, desc, baseConfidence, category } of PROMPT_INJECTION_PATTERNS) {
    // Reset lastIndex for patterns with global flag
    pattern.lastIndex = 0;
    const match = pattern.exec(normalized);
    if (match) {
      const confidence = calculateConfidence(normalized, match, baseConfidence);
      const adjustedRisk = adjustSeverity(risk, confidence);

      // Quick scan mode: return immediately on first critical match
      if (options?.quickScan && adjustedRisk === 'critical') {
        return {
          safe: false,
          risk_level: 'critical',
          findings: [{
            category: "prompt_injection",
            description: desc,
            risk: adjustedRisk,
            detail: match[0].slice(0, 100),
            confidence,
          }],
          summary: `Prompt injection critico detectado (confidence: ${confidence}) -- Nivel: CRITICAL`,
          recommendations: [
            "No procesar el contenido sin revision manual",
            "El texto podria estar disenado para manipular al agente de IA",
          ],
        };
      }

      const finding: Finding & { confidence: number } = {
        category: "prompt_injection",
        description: desc,
        risk: adjustedRisk,
        detail: match[0].slice(0, 100),
        confidence,
      };

      // Dedup: keep highest confidence per pattern category
      const existing = bestPerCategory.get(category);
      if (!existing || confidence > existing.confidence) {
        bestPerCategory.set(category, finding);
      }
    }
  }

  // Collect deduplicated findings
  for (const finding of bestPerCategory.values()) {
    findings.push(finding);
    if (RISK_ORDER[finding.risk] > RISK_ORDER[maxRisk]) {
      maxRisk = finding.risk;
    }
  }

  return {
    safe: findings.length === 0,
    risk_level: maxRisk,
    findings,
    summary: findings.length === 0
      ? "No se detecto prompt injection."
      : `${findings.length} patron(es) de prompt injection detectado(s) -- Nivel: ${maxRisk.toUpperCase()}`,
    recommendations: findings.length > 0
      ? [
          "No procesar el contenido sin revision manual",
          "El texto podria estar disenado para manipular al agente de IA",
        ]
      : ["Contenido parece limpio"],
  };
}

// ============================================================
// Public API: quickScanPromptInjection
// ============================================================

/**
 * Fast pre-filter: checks only critical patterns and returns on first match.
 * Used for high-throughput scenarios where full analysis is too expensive.
 */
export function quickScanPromptInjection(text: string): { threat: boolean; confidence: number } {
  const normalized = normalizeInput(text);

  for (const { pattern, risk, baseConfidence } of PROMPT_INJECTION_PATTERNS) {
    if (risk !== 'critical') continue;

    pattern.lastIndex = 0;
    const match = pattern.exec(normalized);
    if (match) {
      const confidence = calculateConfidence(normalized, match, baseConfidence);
      return { threat: true, confidence };
    }
  }

  return { threat: false, confidence: 0 };
}

// ============================================================
// Public API: analyzeCode
// ============================================================

/**
 * Analyzes source code for malicious patterns, including GitHub Actions
 * workflow injection detection.
 */
export function analyzeCode(code: string, filePath?: string): AnalysisResult {
  const findings: Finding[] = [];
  let maxRisk: RiskLevel = "safe";

  for (const { pattern, risk, desc } of CODE_PATTERNS) {
    const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
    const matches = [...code.matchAll(new RegExp(pattern.source, flags))];
    if (matches.length > 0) {
      const first = matches[0];
      findings.push({
        category: "code",
        description: `${desc} (${matches.length}x)`,
        risk,
        detail: first[0].slice(0, 100),
        line: code.slice(0, first.index).split("\n").length,
      });
      if (RISK_ORDER[risk] > RISK_ORDER[maxRisk]) maxRisk = risk;
    }
  }

  // GitHub Actions workflow injection detection
  const ghaFindings = analyzeGitHubActionsInjection(code, filePath);
  for (const f of ghaFindings) {
    findings.push(f);
    if (RISK_ORDER[f.risk] > RISK_ORDER[maxRisk]) maxRisk = f.risk;
  }

  // Deteccion de codigo ofuscado
  const lines = code.split("\n").filter((l: string) => l.trim());
  const avgLen = lines.reduce((s: number, l: string) => s + l.length, 0) / (lines.length || 1);
  if (avgLen > 300) {
    findings.push({
      category: "code",
      description: "Codigo con lineas muy largas -- posiblemente ofuscado/minificado",
      risk: "medium",
      detail: `Promedio: ${Math.round(avgLen)} chars/linea`,
    });
    if (RISK_ORDER["medium"] > RISK_ORDER[maxRisk]) maxRisk = "medium";
  }

  return {
    safe: findings.length === 0,
    risk_level: maxRisk,
    findings,
    summary: findings.length === 0
      ? "Codigo parece seguro (analisis estatico)."
      : `${findings.length} patron(es) de riesgo en codigo -- Nivel: ${maxRisk.toUpperCase()}`,
    recommendations: findings.length > 0
      ? [
          "Revisar los patrones detectados antes de ejecutar",
          "Verificar que las operaciones de red/archivos son intencionales",
        ]
      : ["Codigo parece seguro en analisis estatico"],
  };
}
