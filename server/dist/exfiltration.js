/**
 * exfiltration.ts - Módulo Anti-Exfiltración (Capa 4)
 *
 * Protege contra la salida no autorizada de datos:
 * - Monitoreo de datos en tránsito saliente
 * - Protección de archivos sensibles
 * - Detección de técnicas de exfiltración
 * - Audit log de conexiones externas
 */
import { analyzeFilePath } from './privacy.js';
// Extensión de archivo sensible. ".env.example" y similares son plantillas sin secretos.
const SENSITIVE_EXT = String.raw `(?:env(?![\w.-]*\.(?:example|sample|template|dist)\b)|pem|key|crt|pfx|p12|jks)\b`;
const ENV_FILE = String.raw `\.env(?![\w.-]*\.(?:example|sample|template|dist)\b)\b`;
const EXFIL_PATTERNS = [
    // Envío de archivos sensibles por red
    {
        // curl -d @.env URL, --data-binary @~/.ssh/key.pem …
        pattern: new RegExp(String.raw `\bcurl\b[^|;&\n]*\s(?:-d|--data(?:-binary|-raw|-urlencode|-ascii)?)[\s=]+\S*@\S*\.` + SENSITIVE_EXT, 'i'),
        technique: "HTTP POST de archivo sensible",
        desc: "Envío de archivo de credenciales/certificado vía curl",
        risk: "critical",
        data_type: "credentials",
    },
    {
        // curl -T .env URL, wget --post-file=.env URL
        pattern: new RegExp(String.raw `\b(?:curl\b[^|;&\n]*\s(?:-T|--upload-file)|wget\b[^|;&\n]*\s--(?:post|body)-file)[\s=]+\S*\.` + SENSITIVE_EXT, 'i'),
        technique: "HTTP upload de archivo sensible",
        desc: "Subida de archivo de credenciales/certificado vía curl/wget",
        risk: "critical",
        data_type: "credentials",
    },
    {
        // Invoke-RestMethod … -InFile .env
        pattern: new RegExp(String.raw `\b(?:invoke-restmethod|invoke-webrequest|irm|iwr)\b[^|;\n]*-infile\s+\S*\.` + SENSITIVE_EXT, 'i'),
        technique: "PowerShell upload de archivo sensible",
        desc: "Envío de archivo de credenciales vía Invoke-RestMethod/WebRequest -InFile",
        risk: "critical",
        data_type: "credentials",
    },
    {
        // Get-Content .env | Invoke-RestMethod …, type .env | curl …
        pattern: new RegExp(String.raw `\b(?:get-content|gc|cat|type)\s+[^|;\n]*\.` + SENSITIVE_EXT + String.raw `[^|;\n]*\|\s*(?:invoke-restmethod|invoke-webrequest|irm|iwr|curl|wget|nc|ncat)\b`, 'i'),
        technique: "Lectura de archivo sensible + envío por red",
        desc: "Contenido de archivo de credenciales enviado por pipeline a un comando de red",
        risk: "critical",
        data_type: "credentials",
    },
    {
        pattern: /curl\s+.*(-F|--form)\s+.*=@\s*[^\s]+/i,
        technique: "HTTP form upload",
        desc: "Upload de archivo vía formulario HTTP",
        risk: "high",
        data_type: "file",
    },
    {
        pattern: /scp\s+.*\.(env|pem|key|ssh)\s+/i,
        technique: "SCP de archivo sensible",
        desc: "Copia remota de archivo de credenciales vía SCP",
        risk: "critical",
        data_type: "credentials",
    },
    {
        pattern: /rsync\s+.*\.(env|pem|key)\s+.*@/i,
        technique: "Rsync de archivo sensible",
        desc: "Sincronización remota de archivo de credenciales",
        risk: "critical",
        data_type: "credentials",
    },
    // Encoding antes de envío (técnica de evasión)
    {
        pattern: /base64\s+[^\s]+\s*\|\s*(curl|wget|nc|ncat)/i,
        technique: "Base64 + HTTP exfil",
        desc: "Codificación base64 de archivo y envío por red",
        risk: "critical",
        data_type: "encoded_file",
    },
    {
        pattern: /xxd\s+.*\|\s*(curl|wget|nc)/i,
        technique: "Hex dump + exfil",
        desc: "Volcado hex de datos y envío por red",
        risk: "critical",
        data_type: "encoded_file",
    },
    {
        pattern: /gzip\s+.*\|\s*(curl|wget|nc)/i,
        technique: "Compress + exfil",
        desc: "Compresión y envío de datos por red",
        risk: "high",
        data_type: "compressed_data",
    },
    {
        pattern: /tar\s+.*\|\s*(curl|wget|nc)/i,
        technique: "Archive + exfil",
        desc: "Empaquetado tar y envío por red",
        risk: "high",
        data_type: "archive",
    },
    // DNS exfiltration
    {
        pattern: /dig\s+.*\$\(|nslookup\s+.*\$\(/i,
        technique: "DNS exfiltration",
        desc: "Uso de consultas DNS para exfiltrar datos",
        risk: "critical",
        data_type: "dns_tunnel",
    },
    {
        pattern: /\$\(cat\s+[^\)]+\)\.[a-zA-Z0-9]+\.[a-zA-Z]{2,}/i,
        technique: "DNS exfil via subdomain",
        desc: "Contenido de archivo embebido en consulta DNS",
        risk: "critical",
        data_type: "dns_tunnel",
    },
    // Canales encubiertos
    {
        pattern: /nc\s+(-l|-p)\s+\d+.*<\s*[^\s]+\.(env|pem|key)/i,
        technique: "Netcat file serve",
        desc: "Archivo sensible servido via netcat",
        risk: "critical",
        data_type: "credentials",
    },
    {
        pattern: /python.*http\.server/i,
        technique: "Python HTTP server",
        desc: "Servidor HTTP Python (puede exponer archivos)",
        risk: "medium",
        data_type: "file_server",
    },
    {
        pattern: /ngrok\s+(http|tcp)/i,
        technique: "Ngrok tunnel",
        desc: "Tunnel público ngrok (exposición de servicios locales)",
        risk: "high",
        data_type: "tunnel",
    },
    // Lectura y envío de archivos de entorno (cat en Unix, type/Get-Content en Windows)
    {
        pattern: new RegExp(String.raw `\b(?:cat|type|more|get-content|gc)\s+[^\s|;]*` + ENV_FILE, 'i'),
        technique: "Lectura de .env",
        desc: "Lectura de archivo .env (contiene secretos)",
        risk: "high",
        data_type: "env_file",
    },
    {
        pattern: /cat\s+[^\s]*id_rsa|cat\s+[^\s]*\.pem/i,
        technique: "Lectura de clave privada",
        desc: "Lectura de clave privada SSH/PEM",
        risk: "critical",
        data_type: "private_key",
    },
    {
        pattern: /cat\s+[^\s]*\.ssh\/config/i,
        technique: "Lectura de SSH config",
        desc: "Lectura de configuración SSH (hosts, claves)",
        risk: "high",
        data_type: "ssh_config",
    },
    // Código que envía datos sensibles
    {
        pattern: /fetch\s*\(.*process\.env/i,
        technique: "JS env exfil",
        desc: "Envío de variables de entorno vía fetch()",
        risk: "critical",
        data_type: "env_vars",
    },
    {
        pattern: /requests\.(post|put)\s*\(.*os\.environ/i,
        technique: "Python env exfil",
        desc: "Envío de variables de entorno vía requests",
        risk: "critical",
        data_type: "env_vars",
    },
    {
        pattern: /open\s*\(.*\.env.*\).*requests\.|requests\..*open\s*\(.*\.env/i,
        technique: "Python .env exfil",
        desc: "Lectura de .env y envío por HTTP",
        risk: "critical",
        data_type: "env_file",
    },
];
// ============================================================
// Archivos protegidos
// ============================================================
const PROTECTED_FILE_PATTERNS = [
    { pattern: /\.env($|\.\w+)/i, reason: "Variables de entorno (secretos)" },
    { pattern: /id_(rsa|ed25519|ecdsa|dsa)$/i, reason: "Clave SSH privada" },
    { pattern: /\.pem$/i, reason: "Certificado/Clave PEM" },
    { pattern: /\.key$/i, reason: "Clave privada" },
    { pattern: /\.p12$/i, reason: "Almacén de claves PKCS#12" },
    { pattern: /\.pfx$/i, reason: "Certificado PFX" },
    { pattern: /known_hosts$/i, reason: "Hosts SSH conocidos" },
    { pattern: /\.netrc$/i, reason: "Credenciales de red" },
    { pattern: /\.npmrc$/i, reason: "Config npm (tokens)" },
    { pattern: /\.pypirc$/i, reason: "Credenciales PyPI" },
    { pattern: /credentials$/i, reason: "Archivo de credenciales" },
    { pattern: /secrets?\.\w+$/i, reason: "Archivo de secretos" },
    { pattern: /\.kube\/config$/i, reason: "Config Kubernetes" },
    { pattern: /\.docker\/config\.json$/i, reason: "Credenciales Docker" },
    { pattern: /\.aws\/credentials$/i, reason: "Credenciales AWS" },
    { pattern: /\.password-store\//i, reason: "Almacén de contraseñas" },
    { pattern: /wallet\.dat$/i, reason: "Billetera crypto" },
    { pattern: /\.gnupg\/.*\.key$/i, reason: "Clave GPG privada" },
    { pattern: /\.config\/gh\/hosts\.yml$/i, reason: "Tokens GitHub CLI" },
];
// ============================================================
// Funciones de análisis
// ============================================================
export function analyzeExfiltration(text) {
    const findings = [];
    const filesAtRisk = [];
    let maxRisk = "safe";
    const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    // Buscar patrones de exfiltración
    for (const ep of EXFIL_PATTERNS) {
        ep.pattern.lastIndex = 0;
        if (ep.pattern.test(text)) {
            findings.push({
                technique: ep.technique,
                description: ep.desc,
                risk: ep.risk,
                data_type: ep.data_type,
            });
            if (riskOrder[ep.risk] > riskOrder[maxRisk])
                maxRisk = ep.risk;
        }
    }
    // Buscar archivos sensibles mencionados (Unix + Windows paths, y nombres sueltos como
    // ".env", "@.env" o ".\.env" que aparecen como argumentos de comandos)
    const filePathRegex = /(?:\/[\w.-]+)+|~\/[\w./-]+|\.\/[\w./-]+|[A-Za-z]:\\[\w.\\ -]+|\\\\[\w.\\ -]+/g;
    const bareFileRegex = /(?:^|[\s@='"(<])((?:[\w~.-]*[\\/])*(?:\.env(?:\.[\w-]+)*|id_(?:rsa|ed25519|ecdsa|dsa)|[\w-]+\.(?:pem|key|p12|pfx)))(?=$|[\s'")|;,>])/gi;
    const isEnvTemplate = (p) => /\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist)$/i.test(p);
    const filePaths = [...new Set([
            ...(text.match(filePathRegex) || []),
            ...[...text.matchAll(bareFileRegex)].map(m => m[1]),
        ])].filter(fp => !isEnvTemplate(fp));
    // Comandos de red como palabras completas: "nc" dentro de "include" no es netcat.
    const hasNetworkCmd = /\b(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ftp|fetch|requests|invoke-restmethod|invoke-webrequest|irm|iwr)\b|https?:\/\//i.test(text);
    for (const fp of filePaths) {
        const analysis = analyzeFilePath(fp.replace(/\\/g, "/"));
        if (analysis.is_sensitive) {
            filesAtRisk.push({ path: fp, reason: analysis.reason });
            // Si el archivo sensible aparece junto con comandos de red, es exfiltración
            if (hasNetworkCmd) {
                findings.push({
                    technique: "Archivo sensible + comando de red",
                    description: `${analysis.reason}: "${fp}" mencionado con operación de red`,
                    risk: "critical",
                    data_type: "sensitive_file",
                    destination: "red externa",
                });
                if (riskOrder["critical"] > riskOrder[maxRisk])
                    maxRisk = "critical";
            }
        }
    }
    const recommendations = [];
    if (findings.some(f => f.risk === "critical")) {
        recommendations.push("🚫 BLOQUEAR — Posible exfiltración de datos detectada");
        recommendations.push("Verificar por qué se están enviando datos sensibles a la red");
    }
    if (filesAtRisk.length > 0) {
        recommendations.push(`📁 ${filesAtRisk.length} archivo(s) sensible(s) en riesgo`);
        recommendations.push("Nunca compartir estos archivos por canales no seguros");
    }
    return {
        safe: findings.length === 0 && filesAtRisk.length === 0,
        risk_level: maxRisk,
        findings,
        files_at_risk: filesAtRisk,
        summary: findings.length === 0 && filesAtRisk.length === 0
            ? "✅ No se detectaron intentos de exfiltración."
            : `🛡️ ${findings.length} técnica(s) de exfiltración, ${filesAtRisk.length} archivo(s) en riesgo — Nivel: ${maxRisk.toUpperCase()}`,
        recommendations: recommendations.length > 0 ? recommendations : ["Sin riesgos de exfiltración detectados"],
    };
}
/**
 * Verifica si una operación de archivo es segura
 */
export function checkFileOperation(operation, filepath) {
    // Normalize Windows backslashes to forward slashes for matching
    const normalizedPath = filepath.replace(/\\/g, "/");
    for (const { pattern, reason } of PROTECTED_FILE_PATTERNS) {
        if (pattern.test(normalizedPath)) {
            if (operation === "send") {
                return { allowed: false, risk: "critical", reason: `🚫 BLOQUEADO: No se permite enviar ${reason}: ${filepath}` };
            }
            if (operation === "delete") {
                return { allowed: false, risk: "critical", reason: `🚫 BLOQUEADO: No se permite eliminar ${reason}: ${filepath}` };
            }
            if (operation === "write") {
                return { allowed: false, risk: "high", reason: `⚠️ PRECAUCIÓN: Escritura en ${reason}: ${filepath}` };
            }
            // Read es warning
            return { allowed: true, risk: "medium", reason: `📖 Lectura de ${reason}: ${filepath} — verificar que es intencional` };
        }
    }
    return { allowed: true, risk: "safe", reason: "Operación permitida" };
}
//# sourceMappingURL=exfiltration.js.map