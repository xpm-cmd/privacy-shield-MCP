#!/usr/bin/env node
/**
 * Privacy Shield MCP v2 - Servidor MCP de Proteccion de Privacidad y Seguridad
 *
 * 7 capas de proteccion:
 * 1. Privacidad: Detecta PII, secretos, datos sensibles
 * 2. Red: Valida URLs, dominios, conexiones externas
 * 3. Ejecucion: Analiza comandos bash, prompt injection, codigo
 * 4. Anti-Exfiltracion: Previene salida no autorizada de datos
 * 5. Auditoria: Log persistente de sesion con estadisticas
 * 6. Adversarial: Deteccion multi-agente (threats, collusion, quorum)
 * 7. Supply Chain: Escaneo de paquetes y repos antes de instalar
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
// Layer 1: Privacy
import { analyzePrivacy, analyzeFilePath } from './privacy.js';
// Layer 2: Network
import { analyzeNetwork, isDomainSafeForDataSending } from './network.js';
// Layer 3: Execution
import { analyzeBash, analyzePromptInjection, analyzeCode } from './execution.js';
// Layer 4: Anti-Exfiltration
import { analyzeExfiltration, checkFileOperation } from './exfiltration.js';
// Layer 5: Audit
import { logEntry, getSessionSummary, getRecentLogs, getLogPath, setSessionId } from './audit.js';
// Layer 6: Adversarial
import { ThreatDetector, CollusionDetector, MemoryQuorum } from './adversarial.js';
// Layer 7: Supply Chain
import { analyzeSupplyChain, analyzePackageJson, analyzeRepoFiles } from './supply-chain.js';
// Stats
import { recordScan, getStats, getStatsSummary, flushStats } from './stats.js';
// Gates
import { runAllGates } from './gates.js';
// Types
import { RISK_ORDER } from './types.js';
// ============================================================
// Singleton instances for stateful modules
// ============================================================
const threatDetector = new ThreatDetector();
const collusionDetector = new CollusionDetector();
const memoryQuorum = new MemoryQuorum();
// ============================================================
// Server configuration
// ============================================================
const server = new Server({ name: 'privacy-shield', version: '2.0.0' }, { capabilities: { tools: {} } });
// ============================================================
// Tool definitions
// ============================================================
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        // === FULL SCAN ===
        {
            name: 'full_security_scan',
            description: 'Analisis de seguridad completo (7 capas): privacidad, red, ejecucion, anti-exfiltracion, adversarial y supply chain.',
            inputSchema: {
                type: 'object',
                properties: {
                    content: { type: 'string', description: 'Texto, codigo, comando, o URL a analizar' },
                },
                required: ['content'],
            },
        },
        // === LAYER 1: PRIVACY ===
        {
            name: 'scan_privacy',
            description: 'Detecta datos personales sensibles: emails, telefonos, SSN, tarjetas de credito, API keys, tokens, claves SSH, contrasenas en texto plano.',
            inputSchema: {
                type: 'object',
                properties: {
                    text: { type: 'string', description: 'Texto a escanear por datos sensibles' },
                },
                required: ['text'],
            },
        },
        {
            name: 'check_file_sensitivity',
            description: 'Verifica si un archivo es sensible por su ruta/nombre (.env, claves SSH, certificados, credenciales, wallets).',
            inputSchema: {
                type: 'object',
                properties: {
                    filepath: { type: 'string', description: 'Ruta del archivo a verificar' },
                },
                required: ['filepath'],
            },
        },
        {
            name: 'redact_text',
            description: 'Redacta/anonimiza datos sensibles en texto. Devuelve version con datos personales y secretos reemplazados.',
            inputSchema: {
                type: 'object',
                properties: {
                    text: { type: 'string', description: 'Texto a redactar' },
                },
                required: ['text'],
            },
        },
        // === LAYER 2: NETWORK ===
        {
            name: 'validate_urls',
            description: 'Valida URLs: detecta acortadores, dominios maliciosos, phishing, typosquatting, TLDs de alto riesgo.',
            inputSchema: {
                type: 'object',
                properties: {
                    text: { type: 'string', description: 'Texto que contiene URLs a validar' },
                },
                required: ['text'],
            },
        },
        {
            name: 'check_domain',
            description: 'Verifica si un dominio especifico es seguro para enviar datos.',
            inputSchema: {
                type: 'object',
                properties: {
                    domain: { type: 'string', description: "Dominio a verificar (e.g., 'example.com')" },
                },
                required: ['domain'],
            },
        },
        // === LAYER 3: EXECUTION ===
        {
            name: 'analyze_command',
            description: 'Analiza un comando bash por patrones peligrosos: rm -rf, fork bombs, reverse shells, escalada de privilegios.',
            inputSchema: {
                type: 'object',
                properties: {
                    command: { type: 'string', description: 'Comando bash a analizar' },
                },
                required: ['command'],
            },
        },
        {
            name: 'detect_prompt_injection',
            description: 'Detecta prompt injection, jailbreak, o instrucciones maliciosas ocultas. Incluye confidence scoring.',
            inputSchema: {
                type: 'object',
                properties: {
                    text: { type: 'string', description: 'Texto a analizar por prompt injection' },
                },
                required: ['text'],
            },
        },
        {
            name: 'scan_code',
            description: 'Escanea codigo fuente por patrones de riesgo: ejecucion de sistema, exfiltracion, XSS, GitHub Actions injection.',
            inputSchema: {
                type: 'object',
                properties: {
                    code: { type: 'string', description: 'Codigo fuente a escanear' },
                    language: { type: 'string', description: 'Ruta del archivo o lenguaje (opcional)' },
                },
                required: ['code'],
            },
        },
        // === LAYER 4: ANTI-EXFILTRATION ===
        {
            name: 'check_exfiltration',
            description: 'Detecta tecnicas de exfiltracion: envio de archivos sensibles, encoding para evasion, DNS tunneling.',
            inputSchema: {
                type: 'object',
                properties: {
                    content: { type: 'string', description: 'Contenido a analizar por exfiltracion' },
                },
                required: ['content'],
            },
        },
        {
            name: 'check_file_operation',
            description: 'Verifica si una operacion sobre un archivo es segura (leer, escribir, eliminar, enviar).',
            inputSchema: {
                type: 'object',
                properties: {
                    operation: {
                        type: 'string',
                        enum: ['read', 'write', 'delete', 'send'],
                        description: 'Tipo de operacion',
                    },
                    filepath: { type: 'string', description: 'Ruta del archivo' },
                },
                required: ['operation', 'filepath'],
            },
        },
        // === LAYER 5: AUDIT ===
        {
            name: 'session_summary',
            description: 'Resumen de seguridad de la sesion actual: total de escaneos, riesgos detectados, hallazgos.',
            inputSchema: { type: 'object', properties: {} },
        },
        {
            name: 'audit_log',
            description: 'Muestra las ultimas entradas del audit log de seguridad.',
            inputSchema: {
                type: 'object',
                properties: {
                    count: { type: 'number', description: 'Numero de entradas a mostrar (default: 20)' },
                },
            },
        },
        {
            name: 'set_session',
            description: 'Establece un ID de sesion personalizado para agrupar analisis.',
            inputSchema: {
                type: 'object',
                properties: {
                    session_id: { type: 'string', description: 'ID de sesion' },
                },
                required: ['session_id'],
            },
        },
        // === LAYER 6: ADVERSARIAL (new in v2) ===
        {
            name: 'detect_adversarial',
            description: 'Analiza una secuencia de acciones de agentes para detectar patrones adversariales: prompt injection, escalada de privilegios, exfiltracion.',
            inputSchema: {
                type: 'object',
                properties: {
                    actions: {
                        type: 'array',
                        description: 'Array de acciones de agentes [{agentId, action, target, timestamp, metadata?}]',
                        items: {
                            type: 'object',
                            properties: {
                                agentId: { type: 'string' },
                                action: { type: 'string' },
                                target: { type: 'string' },
                                timestamp: { type: 'number' },
                                metadata: { type: 'object' },
                            },
                            required: ['agentId', 'action', 'target', 'timestamp'],
                        },
                    },
                },
                required: ['actions'],
            },
        },
        {
            name: 'check_collusion',
            description: 'Verifica un grafo de interacciones entre agentes para detectar collusion: anillos, frecuencia sospechosa, timing coordinado.',
            inputSchema: {
                type: 'object',
                properties: {
                    interactions: {
                        type: 'array',
                        description: 'Array de interacciones [{from, to, timestamp, action}]',
                        items: {
                            type: 'object',
                            properties: {
                                from: { type: 'string' },
                                to: { type: 'string' },
                                timestamp: { type: 'number' },
                                action: { type: 'string' },
                            },
                            required: ['from', 'to', 'timestamp'],
                        },
                    },
                },
                required: ['interactions'],
            },
        },
        {
            name: 'quorum_vote',
            description: 'Valida una escritura de memoria via votacion Byzantine (requiere 2/3 mayoria). Propone, vota y resuelve.',
            inputSchema: {
                type: 'object',
                properties: {
                    operation: {
                        type: 'string',
                        enum: ['propose', 'vote', 'resolve'],
                        description: 'Operacion: propose (crear propuesta), vote (votar), resolve (resolver)',
                    },
                    proposal_id: { type: 'string', description: 'ID de la propuesta (para vote/resolve)' },
                    content: { type: 'string', description: 'Contenido de la escritura (para propose)' },
                    agent_id: { type: 'string', description: 'ID del agente que propone o vota' },
                    approve: { type: 'boolean', description: 'Voto: true=aprobar, false=rechazar (para vote)' },
                },
                required: ['operation'],
            },
        },
        // === LAYER 7: SUPPLY CHAIN (new in v2) ===
        {
            name: 'scan_supply_chain',
            description: 'Escaneo completo de supply chain: analiza comando de instalacion + package.json + archivos del repo.',
            inputSchema: {
                type: 'object',
                properties: {
                    command: { type: 'string', description: 'Comando de instalacion (npm install, pip install, git clone, etc.)' },
                    package_json: { type: 'string', description: 'Contenido del package.json (opcional)' },
                    repo_files: {
                        type: 'array',
                        items: { type: 'string' },
                        description: 'Lista de archivos del repo (opcional, para detectar binarios/scripts sospechosos)',
                    },
                },
                required: ['command'],
            },
        },
        {
            name: 'scan_package_json',
            description: 'Escanea un package.json por riesgos de supply chain: scripts de instalacion peligrosos, dependencias de URL, typosquatting.',
            inputSchema: {
                type: 'object',
                properties: {
                    content: { type: 'string', description: 'Contenido del package.json como string' },
                },
                required: ['content'],
            },
        },
        {
            name: 'scan_repo_files',
            description: 'Escanea una lista de archivos de un repo por archivos sospechosos (binarios, scripts, modelos inseguros).',
            inputSchema: {
                type: 'object',
                properties: {
                    files: {
                        type: 'array',
                        items: { type: 'string' },
                        description: 'Lista de rutas de archivos del repo',
                    },
                },
                required: ['files'],
            },
        },
        // === STATS (new in v2) ===
        {
            name: 'detection_stats',
            description: 'Muestra estadisticas de deteccion: total de escaneos, detecciones por categoria, latencia promedio.',
            inputSchema: { type: 'object', properties: {} },
        },
        // === GATES (new in v2) ===
        {
            name: 'run_gates',
            description: 'Ejecuta todos los gates de enforcement y retorna la decision agregada (allow/warn/require-confirmation/block).',
            inputSchema: {
                type: 'object',
                properties: {
                    content: { type: 'string', description: 'Contenido a evaluar' },
                    tool_name: { type: 'string', description: 'Nombre del tool MCP que se quiere ejecutar (para tool allowlist gate)' },
                    diff_lines: { type: 'number', description: 'Numero de lineas del diff (para diff size gate)' },
                    allowed_tools: {
                        type: 'array',
                        items: { type: 'string' },
                        description: 'Lista de tools permitidos con wildcards (e.g., ["mcp__privacy-shield__*", "Read", "Grep"])',
                    },
                },
                required: ['content'],
            },
        },
    ],
}));
// ============================================================
// Tool call handler
// ============================================================
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const startTime = Date.now();
    try {
        switch (name) {
            // === FULL SCAN ===
            case 'full_security_scan': {
                const content = args?.content;
                if (!content)
                    throw new Error("Se requiere el parametro 'content'");
                const privacy = analyzePrivacy(content);
                const network = analyzeNetwork(content);
                const bash = analyzeBash(content);
                const injection = analyzePromptInjection(content);
                const code = analyzeCode(content);
                const exfil = analyzeExfiltration(content);
                const allRisks = [
                    privacy.risk_level, network.risk_level, bash.risk_level,
                    injection.risk_level, code.risk_level, exfil.risk_level,
                ];
                const overallRisk = allRisks.reduce((max, r) => (RISK_ORDER[r] > RISK_ORDER[max] ? r : max), 'safe');
                const overallSafe = privacy.safe && network.safe && bash.safe &&
                    injection.safe && code.safe && exfil.safe;
                const result = {
                    overall_safe: overallSafe,
                    overall_risk: overallRisk,
                    layers: {
                        '1_privacy': { safe: privacy.safe, risk: privacy.risk_level, summary: privacy.summary, findings_count: privacy.findings.length },
                        '2_network': { safe: network.safe, risk: network.risk_level, summary: network.summary },
                        '3_execution': {
                            bash: { safe: bash.safe, risk: bash.risk_level, summary: bash.summary },
                            prompt_injection: { safe: injection.safe, risk: injection.risk_level, summary: injection.summary },
                            code: { safe: code.safe, risk: code.risk_level, summary: code.summary },
                        },
                        '4_anti_exfiltration': { safe: exfil.safe, risk: exfil.risk_level, summary: exfil.summary },
                    },
                    redacted_text: privacy.redacted_text,
                };
                const emoji = overallRisk === 'safe' ? 'OK' : overallRisk === 'critical' ? 'CRITICAL' : overallRisk === 'high' ? 'HIGH' : 'WARNING';
                recordScan('full_scan', !overallSafe, Date.now() - startTime);
                await logEntry({ event: 'full_security_scan', tool_name: name, risk_level: overallRisk, safe: overallSafe, summary: `${emoji} Riesgo: ${overallRisk}` });
                return { content: [{ type: 'text', text: `[${emoji}] ANALISIS COMPLETO — Riesgo: ${overallRisk.toUpperCase()}\n\n${JSON.stringify(result, null, 2)}` }] };
            }
            // === LAYER 1: PRIVACY ===
            case 'scan_privacy': {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parametro 'text'");
                const result = analyzePrivacy(text);
                recordScan('privacy', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'scan_privacy', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'check_file_sensitivity': {
                const filepath = args?.filepath;
                if (!filepath)
                    throw new Error("Se requiere el parametro 'filepath'");
                const result = analyzeFilePath(filepath);
                recordScan('file_sensitivity', result.is_sensitive, Date.now() - startTime);
                await logEntry({ event: 'check_file_sensitivity', tool_name: name, risk_level: result.is_sensitive ? 'high' : 'safe', safe: !result.is_sensitive, summary: `${filepath}: ${result.reason}` });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'redact_text': {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parametro 'text'");
                const result = analyzePrivacy(text);
                recordScan('redact', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'redact_text', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: `Redactados ${result.findings.length} elementos` });
                return { content: [{ type: 'text', text: JSON.stringify({ original_had_sensitive_data: !result.safe, findings_count: result.findings.length, redacted_text: result.redacted_text }, null, 2) }] };
            }
            // === LAYER 2: NETWORK ===
            case 'validate_urls': {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parametro 'text'");
                const result = analyzeNetwork(text);
                recordScan('network', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'validate_urls', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'check_domain': {
                const domain = args?.domain;
                if (!domain)
                    throw new Error("Se requiere el parametro 'domain'");
                const result = isDomainSafeForDataSending(domain);
                recordScan('domain', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'check_domain', tool_name: name, risk_level: result.safe ? 'safe' : 'high', safe: result.safe, summary: `${domain}: ${result.reason}` });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            // === LAYER 3: EXECUTION ===
            case 'analyze_command': {
                const command = args?.command;
                if (!command)
                    throw new Error("Se requiere el parametro 'command'");
                const result = analyzeBash(command);
                recordScan('bash', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'analyze_command', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary, details: { command: command.slice(0, 200) } });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'detect_prompt_injection': {
                const text = args?.text;
                if (!text)
                    throw new Error("Se requiere el parametro 'text'");
                const result = analyzePromptInjection(text);
                recordScan('injection', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'detect_prompt_injection', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'scan_code': {
                const code = args?.code;
                if (!code)
                    throw new Error("Se requiere el parametro 'code'");
                const filePath = args?.language;
                const result = analyzeCode(code, filePath);
                recordScan('code', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'scan_code', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            // === LAYER 4: ANTI-EXFILTRATION ===
            case 'check_exfiltration': {
                const content = args?.content;
                if (!content)
                    throw new Error("Se requiere el parametro 'content'");
                const result = analyzeExfiltration(content);
                recordScan('exfiltration', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'check_exfiltration', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'check_file_operation': {
                const operation = args?.operation;
                const filepath = args?.filepath;
                if (!operation || !filepath)
                    throw new Error("Se requieren 'operation' y 'filepath'");
                const result = checkFileOperation(operation, filepath);
                recordScan('file_operation', !result.allowed, Date.now() - startTime);
                await logEntry({ event: 'check_file_operation', tool_name: name, risk_level: result.risk, safe: result.allowed, summary: result.reason, details: { operation, filepath } });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            // === LAYER 5: AUDIT ===
            case 'session_summary': {
                const summary = getSessionSummary();
                return { content: [{ type: 'text', text: `RESUMEN DE SESION\n\n${JSON.stringify(summary, null, 2)}` }] };
            }
            case 'audit_log': {
                const count = args?.count || 20;
                const logs = await getRecentLogs(count);
                return { content: [{ type: 'text', text: `AUDIT LOG (ultimas ${logs.length} entradas)\nArchivo: ${getLogPath()}\n\n${JSON.stringify(logs, null, 2)}` }] };
            }
            case 'set_session': {
                const sessionId = args?.session_id;
                if (!sessionId)
                    throw new Error("Se requiere 'session_id'");
                setSessionId(sessionId);
                return { content: [{ type: 'text', text: `Sesion establecida: ${sessionId}` }] };
            }
            // === LAYER 6: ADVERSARIAL (new in v2) ===
            case 'detect_adversarial': {
                const actions = args?.actions;
                if (!actions || !Array.isArray(actions))
                    throw new Error("Se requiere 'actions' como array");
                const threats = [];
                for (const action of actions) {
                    const inputThreats = threatDetector.analyzeInput(action.agentId, action.target);
                    threats.push(...inputThreats);
                }
                // Get score for the first agent (or 'unknown')
                const primaryAgent = actions[0]?.agentId || 'unknown';
                const scoreResult = threatDetector.getThreatScore(primaryAgent);
                const safe = threats.length === 0;
                recordScan('adversarial', !safe, Date.now() - startTime);
                await logEntry({ event: 'detect_adversarial', tool_name: name, risk_level: safe ? 'safe' : 'high', safe, summary: `${threats.length} amenaza(s) detectada(s), score: ${scoreResult.decayedScore.toFixed(2)}` });
                return { content: [{ type: 'text', text: JSON.stringify({ safe, threat_count: threats.length, threat_score: scoreResult, threats }, null, 2) }] };
            }
            case 'check_collusion': {
                const interactions = args?.interactions;
                if (!interactions || !Array.isArray(interactions))
                    throw new Error("Se requiere 'interactions' como array");
                for (const i of interactions) {
                    collusionDetector.recordInteraction(i.from, i.to, i.action || 'interact');
                }
                const collusionResult = collusionDetector.detectCollusion();
                const hasCollusion = collusionResult.rings.length > 0 || collusionResult.unusualFrequency.length > 0 || collusionResult.coordinatedTiming.length > 0;
                const safe = !hasCollusion;
                recordScan('collusion', !safe, Date.now() - startTime);
                const collusionSummary = hasCollusion
                    ? `Collusion detectada: ${collusionResult.rings.length} anillo(s), ${collusionResult.unusualFrequency.length} par(es) frecuentes, ${collusionResult.coordinatedTiming.length} timing(s) coordinado(s)`
                    : 'No se detecto collusion';
                await logEntry({ event: 'check_collusion', tool_name: name, risk_level: safe ? 'safe' : 'high', safe, summary: collusionSummary });
                return { content: [{ type: 'text', text: JSON.stringify({ detected: hasCollusion, ...collusionResult }, null, 2) }] };
            }
            case 'quorum_vote': {
                const operation = args?.operation;
                if (!operation)
                    throw new Error("Se requiere 'operation'");
                if (operation === 'propose') {
                    const content = args?.content;
                    const agentId = args?.agent_id;
                    if (!content || !agentId)
                        throw new Error("Se requieren 'content' y 'agent_id' para propose");
                    const proposalId = memoryQuorum.propose('key', content, agentId);
                    return { content: [{ type: 'text', text: JSON.stringify({ proposal_id: proposalId, status: 'proposed' }, null, 2) }] };
                }
                if (operation === 'vote') {
                    const proposalId = args?.proposal_id;
                    const agentId = args?.agent_id;
                    const approve = args?.approve;
                    if (!proposalId || !agentId || approve === undefined)
                        throw new Error("Se requieren 'proposal_id', 'agent_id', y 'approve' para vote");
                    memoryQuorum.vote(proposalId, agentId, approve);
                    return { content: [{ type: 'text', text: JSON.stringify({ proposal_id: proposalId, status: 'voted' }, null, 2) }] };
                }
                if (operation === 'resolve') {
                    const proposalId = args?.proposal_id;
                    if (!proposalId)
                        throw new Error("Se requiere 'proposal_id' para resolve");
                    const resolution = memoryQuorum.resolve(proposalId);
                    return { content: [{ type: 'text', text: JSON.stringify(resolution, null, 2) }] };
                }
                throw new Error(`Operacion desconocida: ${operation}. Usar 'propose', 'vote', o 'resolve'`);
            }
            // === LAYER 7: SUPPLY CHAIN (new in v2) ===
            case 'scan_supply_chain': {
                const command = args?.command;
                if (!command)
                    throw new Error("Se requiere el parametro 'command'");
                const packageJson = args?.package_json;
                const repoFiles = args?.repo_files;
                const result = analyzeSupplyChain(command, packageJson, repoFiles);
                recordScan('supply_chain', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'scan_supply_chain', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'scan_package_json': {
                const content = args?.content;
                if (!content)
                    throw new Error("Se requiere el parametro 'content'");
                const result = analyzePackageJson(content);
                recordScan('package_json', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'scan_package_json', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            case 'scan_repo_files': {
                const files = args?.files;
                if (!files || !Array.isArray(files))
                    throw new Error("Se requiere 'files' como array");
                const result = analyzeRepoFiles(files);
                recordScan('repo_files', !result.safe, Date.now() - startTime);
                await logEntry({ event: 'scan_repo_files', tool_name: name, risk_level: result.risk_level, safe: result.safe, summary: result.summary });
                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            }
            // === STATS (new in v2) ===
            case 'detection_stats': {
                const stats = getStats();
                const summary = getStatsSummary();
                return { content: [{ type: 'text', text: `ESTADISTICAS DE DETECCION\n\n${summary}\n\n${JSON.stringify(stats, null, 2)}` }] };
            }
            // === GATES (new in v2) ===
            case 'run_gates': {
                const content = args?.content;
                if (!content)
                    throw new Error("Se requiere el parametro 'content'");
                const diffSizeThreshold = args?.diff_lines;
                const allowedTools = args?.allowed_tools;
                const result = runAllGates(content, { diffSizeThreshold, allowedTools });
                if (result) {
                    recordScan('gates', result.decision !== 'allow', Date.now() - startTime);
                    await logEntry({ event: 'run_gates', tool_name: name, risk_level: result.risk, safe: result.decision === 'allow', summary: `${result.gate}: ${result.decision} — ${result.reason}` });
                    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                }
                // All gates passed
                recordScan('gates', false, Date.now() - startTime);
                return { content: [{ type: 'text', text: JSON.stringify({ gate: 'all', decision: 'allow', risk: 'safe', reason: 'All gates passed', remediation: [] }, null, 2) }] };
            }
            default:
                throw new Error(`Herramienta desconocida: ${name}`);
        }
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
    }
});
// ============================================================
// Server start
// ============================================================
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('Privacy Shield MCP v2 Server iniciado (7 capas, 21 tools)');
    // Flush stats on exit
    process.on('SIGINT', () => { flushStats(); process.exit(0); });
    process.on('SIGTERM', () => { flushStats(); process.exit(0); });
}
main().catch((error) => {
    console.error('Error fatal:', error);
    process.exit(1);
});
//# sourceMappingURL=index.js.map