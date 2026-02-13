#!/usr/bin/env node
/**
 * Privacy Shield MCP - Servidor MCP de Protección de Privacidad y Seguridad
 *
 * 5 capas de protección:
 * 1. Privacidad: Detecta PII, secretos, datos sensibles
 * 2. Red: Valida URLs, dominios, conexiones externas
 * 3. Ejecución: Analiza comandos bash, prompt injection, código
 * 4. Anti-Exfiltración: Previene salida no autorizada de datos
 * 5. Auditoría: Log persistente de sesión con estadísticas
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import { analyzePrivacy, analyzeFilePath } from "./privacy.js";
import { analyzeNetwork, isDomainSafeForDataSending } from "./network.js";
import { analyzeBash, analyzePromptInjection, analyzeCode } from "./execution.js";
import { analyzeExfiltration, checkFileOperation } from "./exfiltration.js";
import { logEntry, getSessionSummary, getRecentLogs, getLogPath, setSessionId } from "./audit.js";
// ============================================================
// Configuración del servidor MCP
// ============================================================
const server = new Server({ name: "privacy-shield", version: "1.0.0" }, { capabilities: { tools: {} } });
// ============================================================
// Registro de herramientas
// ============================================================
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        // === ANÁLISIS COMPLETO ===
        {
            name: "full_security_scan",
            description: "🛡️ Análisis de seguridad completo (4 capas): privacidad, red, ejecución y anti-exfiltración. Usa esta herramienta para verificar cualquier contenido sospechoso antes de procesarlo.",
            inputSchema: {
                type: "object",
                properties: {
                    content: {
                        type: "string",
                        description: "Texto, código, comando, o URL a analizar",
                    },
                },
                required: ["content"],
            },
        },
        // === CAPA 1: PRIVACIDAD ===
        {
            name: "scan_privacy",
            description: "👤 Detecta datos personales sensibles: emails, teléfonos, SSN, tarjetas de crédito, API keys, tokens, claves SSH, contraseñas en texto plano. Devuelve una versión redactada del texto.",
            inputSchema: {
                type: "object",
                properties: {
                    text: { type: "string", description: "Texto a escanear por datos sensibles" },
                },
                required: ["text"],
            },
        },
        {
            name: "check_file_sensitivity",
            description: "📁 Verifica si un archivo es sensible (por ruta/nombre). Detecta .env, claves SSH, certificados, credenciales, wallets, etc.",
            inputSchema: {
                type: "object",
                properties: {
                    filepath: { type: "string", description: "Ruta del archivo a verificar" },
                },
                required: ["filepath"],
            },
        },
        {
            name: "redact_text",
            description: "🔒 Redacta/anonimiza datos sensibles en texto. Devuelve el texto con datos personales y secretos reemplazados por placeholders seguros.",
            inputSchema: {
                type: "object",
                properties: {
                    text: { type: "string", description: "Texto a redactar" },
                },
                required: ["text"],
            },
        },
        // === CAPA 2: RED ===
        {
            name: "validate_urls",
            description: "🔗 Valida URLs/links: detecta acortadores, dominios maliciosos, phishing, typosquatting, TLDs de alto riesgo, conexiones HTTP sin cifrar, y patrones sospechosos.",
            inputSchema: {
                type: "object",
                properties: {
                    text: { type: "string", description: "Texto que contiene URLs a validar" },
                },
                required: ["text"],
            },
        },
        {
            name: "check_domain",
            description: "🌐 Verifica si un dominio específico es seguro para enviar datos.",
            inputSchema: {
                type: "object",
                properties: {
                    domain: { type: "string", description: "Dominio a verificar (e.g., 'example.com')" },
                },
                required: ["domain"],
            },
        },
        // === CAPA 3: EJECUCIÓN ===
        {
            name: "analyze_command",
            description: "💻 Analiza un comando bash/shell por patrones peligrosos: rm -rf, fork bombs, reverse shells, escalada de privilegios, modificación de seguridad del sistema.",
            inputSchema: {
                type: "object",
                properties: {
                    command: { type: "string", description: "Comando bash a analizar" },
                },
                required: ["command"],
            },
        },
        {
            name: "detect_prompt_injection",
            description: "🛡️ Detecta intentos de prompt injection, jailbreak, o instrucciones maliciosas ocultas. Analiza texto de archivos, inputs de usuario, o contenido web.",
            inputSchema: {
                type: "object",
                properties: {
                    text: { type: "string", description: "Texto a analizar por prompt injection" },
                },
                required: ["text"],
            },
        },
        {
            name: "scan_code",
            description: "🔍 Escanea código fuente por patrones de riesgo: ejecución de sistema, exfiltración de datos, deserialización insegura, XSS, eval dinámica, GitHub Actions workflow injection.",
            inputSchema: {
                type: "object",
                properties: {
                    code: { type: "string", description: "Código fuente a escanear" },
                    language: { type: "string", description: "Ruta del archivo o lenguaje (opcional — ayuda a detectar GitHub Actions workflow injection en .github/workflows/*.yml)" },
                },
                required: ["code"],
            },
        },
        // === CAPA 4: ANTI-EXFILTRACIÓN ===
        {
            name: "check_exfiltration",
            description: "🚫 Detecta técnicas de exfiltración de datos: envío de archivos sensibles por red, encoding para evasión, DNS tunneling, canales encubiertos.",
            inputSchema: {
                type: "object",
                properties: {
                    content: { type: "string", description: "Contenido (comando, código, etc.) a analizar por exfiltración" },
                },
                required: ["content"],
            },
        },
        {
            name: "check_file_operation",
            description: "📂 Verifica si una operación sobre un archivo es segura (leer, escribir, eliminar, enviar).",
            inputSchema: {
                type: "object",
                properties: {
                    operation: {
                        type: "string",
                        enum: ["read", "write", "delete", "send"],
                        description: "Tipo de operación",
                    },
                    filepath: { type: "string", description: "Ruta del archivo" },
                },
                required: ["operation", "filepath"],
            },
        },
        // === CAPA 5: AUDITORÍA Y SESIÓN ===
        {
            name: "session_summary",
            description: "📊 Muestra resumen de seguridad de la sesión actual: total de escaneos, riesgos detectados, herramientas usadas, y hallazgos principales.",
            inputSchema: {
                type: "object",
                properties: {},
            },
        },
        {
            name: "audit_log",
            description: "📋 Muestra las últimas entradas del audit log de seguridad. Persiste entre sesiones.",
            inputSchema: {
                type: "object",
                properties: {
                    count: { type: "number", description: "Número de entradas a mostrar (default: 20)" },
                },
            },
        },
        {
            name: "set_session",
            description: "🔖 Establece un ID de sesión personalizado para agrupar análisis relacionados en el audit log.",
            inputSchema: {
                type: "object",
                properties: {
                    session_id: { type: "string", description: "ID de sesión personalizado" },
                },
                required: ["session_id"],
            },
        },
    ],
}));
// ============================================================
// Handler de llamadas a herramientas
// ============================================================
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
        switch (name) {
            // === ANÁLISIS COMPLETO ===
            case "full_security_scan": {
                const content = args?.content;
                if (!content)
                    throw new Error("Se requiere el parámetro 'content'");
                const privacy = analyzePrivacy(content);
                const network = analyzeNetwork(content);
                const bash = analyzeBash(content);
                const injection = analyzePromptInjection(content);
                const code = analyzeCode(content);
                const exfil = analyzeExfiltration(content);
                const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
                const allRisks = [privacy.risk_level, network.risk_level, bash.risk_level, injection.risk_level, code.risk_level, exfil.risk_level];
                const overallRisk = allRisks.reduce((max, r) => riskOrder[r] > riskOrder[max] ? r : max, "safe");
                const overallSafe = privacy.safe && network.safe && bash.safe && injection.safe && code.safe && exfil.safe;
                const result = {
                    overall_safe: overallSafe,
                    overall_risk: overallRisk,
                    layers: {
                        "1_privacy": { safe: privacy.safe, risk: privacy.risk_level, summary: privacy.summary, findings_count: privacy.findings.length },
                        "2_network": { safe: network.safe, risk: network.risk_level, summary: network.summary, urls_count: network.urls_analyzed.length },
                        "3_execution": {
                            bash: { safe: bash.safe, risk: bash.risk_level, summary: bash.summary },
                            prompt_injection: { safe: injection.safe, risk: injection.risk_level, summary: injection.summary },
                            code: { safe: code.safe, risk: code.risk_level, summary: code.summary },
                        },
                        "4_anti_exfiltration": { safe: exfil.safe, risk: exfil.risk_level, summary: exfil.summary, files_at_risk: exfil.files_at_risk.length },
                    },
                    redacted_text: privacy.redacted_text,
                };
                const emoji = overallRisk === "safe" ? "✅" : overallRisk === "critical" ? "🚨" : overallRisk === "high" ? "🔴" : "⚠️";
                await logEntry({ event: "full_security_scan", tool_name: name, risk_level: overallRisk, safe: overallSafe, summary: `${emoji} Riesgo: ${overallRisk}`, details: { content_length: content.length, layers_triggered: allRisks.filter(r => r !== "safe").length } });
                return {
                    content: [{
                            type: "text",
                            text: `${emoji} ANÁLISIS COMPLETO — Riesgo: ${overallRisk.toUpperCase()}\n\n${JSON.stringify(result, null, 2)}`,
                        }],
                };
            }
            // === CAPA 1: PRIVACIDAD ===
            case "scan_privacy": {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parámetro 'text'");
                const result = analyzePrivacy(text);
                await logEntry({ event: "scan_privacy", tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "check_file_sensitivity": {
                const filepath = args?.filepath;
                if (!filepath)
                    throw new Error("Se requiere el parámetro 'filepath'");
                const result = analyzeFilePath(filepath);
                await logEntry({ event: "check_file_sensitivity", tool_name: name, risk_level: result.is_sensitive ? "high" : "safe", safe: !result.is_sensitive, summary: `${filepath}: ${result.reason}` });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "redact_text": {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parámetro 'text'");
                const result = analyzePrivacy(text);
                await logEntry({ event: "redact_text", tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: `Redactados ${result.findings.length} elementos` });
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({
                                original_had_sensitive_data: !result.safe,
                                findings_count: result.findings.length,
                                redacted_text: result.redacted_text,
                            }, null, 2),
                        }],
                };
            }
            // === CAPA 2: RED ===
            case "validate_urls": {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parámetro 'text'");
                const result = analyzeNetwork(text);
                await logEntry({ event: "validate_urls", tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "check_domain": {
                const domain = args?.domain;
                if (!domain)
                    throw new Error("Se requiere el parámetro 'domain'");
                const result = isDomainSafeForDataSending(domain);
                await logEntry({ event: "check_domain", tool_name: name, risk_level: result.safe ? "safe" : "high", safe: result.safe, summary: `${domain}: ${result.reason}` });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            // === CAPA 3: EJECUCIÓN ===
            case "analyze_command": {
                const command = args?.command;
                if (!command)
                    throw new Error("Se requiere el parámetro 'command'");
                const result = analyzeBash(command);
                await logEntry({ event: "analyze_command", tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary, details: { command: command.slice(0, 200) } });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "detect_prompt_injection": {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parámetro 'text'");
                const result = analyzePromptInjection(text);
                await logEntry({ event: "detect_prompt_injection", tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "scan_code": {
                const code = args?.code;
                if (!code)
                    throw new Error("Se requiere el parámetro 'code'");
                const filePath = args?.language;
                const result = analyzeCode(code, filePath);
                await logEntry({ event: "scan_code", tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            // === CAPA 4: ANTI-EXFILTRACIÓN ===
            case "check_exfiltration": {
                const content = args?.content;
                if (!content)
                    throw new Error("Se requiere el parámetro 'content'");
                const result = analyzeExfiltration(content);
                await logEntry({ event: "check_exfiltration", tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "check_file_operation": {
                const operation = args?.operation;
                const filepath = args?.filepath;
                if (!operation || !filepath)
                    throw new Error("Se requieren 'operation' y 'filepath'");
                const result = checkFileOperation(operation, filepath);
                await logEntry({ event: "check_file_operation", tool_name: name, risk_level: result.risk, safe: result.allowed, summary: result.reason, details: { operation, filepath } });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            // === CAPA 5: AUDITORÍA Y SESIÓN ===
            case "session_summary": {
                const summary = getSessionSummary();
                return {
                    content: [{
                            type: "text",
                            text: `📊 RESUMEN DE SESIÓN\n\n${JSON.stringify(summary, null, 2)}`,
                        }],
                };
            }
            case "audit_log": {
                const count = args?.count || 20;
                const logs = await getRecentLogs(count);
                return {
                    content: [{
                            type: "text",
                            text: `📋 AUDIT LOG (últimas ${logs.length} entradas)\nArchivo: ${getLogPath()}\n\n${JSON.stringify(logs, null, 2)}`,
                        }],
                };
            }
            case "set_session": {
                const sessionId = args?.session_id;
                if (!sessionId)
                    throw new Error("Se requiere 'session_id'");
                setSessionId(sessionId);
                return {
                    content: [{
                            type: "text",
                            text: `🔖 Sesión establecida: ${sessionId}`,
                        }],
                };
            }
            default:
                throw new Error(`Herramienta desconocida: ${name}`);
        }
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
            content: [{ type: "text", text: `Error: ${message}` }],
            isError: true,
        };
    }
});
// ============================================================
// Inicio del servidor
// ============================================================
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("🛡️ Privacy Shield MCP Server iniciado");
}
main().catch((error) => {
    console.error("Error fatal:", error);
    process.exit(1);
});
//# sourceMappingURL=index.js.map