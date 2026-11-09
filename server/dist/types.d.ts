/**
 * types.ts - Tipos compartidos para Privacy Shield v2
 */
export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export declare const RISK_ORDER: Record<RiskLevel, number>;
export interface Finding {
    category: string;
    description: string;
    risk: RiskLevel;
    detail?: string;
    confidence?: number;
    /** 1-based line of the first match, when the finding comes from scanning source text */
    line?: number;
}
export interface AnalysisResult {
    safe: boolean;
    risk_level: RiskLevel;
    findings: Finding[];
    summary: string;
    recommendations?: string[];
}
export interface InjectionThreat {
    pattern_id: string;
    description: string;
    risk: RiskLevel;
    confidence: number;
    matched_text: string;
    category: 'override' | 'exfiltration' | 'jailbreak' | 'social_engineering' | 'encoding' | 'delimiter' | 'hypothetical';
}
export interface GateDecision {
    gate: string;
    decision: 'allow' | 'warn' | 'require-confirmation' | 'block';
    risk: RiskLevel;
    reason: string;
    remediation: string[];
    metadata?: Record<string, unknown>;
}
export interface AgentAction {
    agentId: string;
    action: string;
    target: string;
    timestamp: number;
    metadata?: Record<string, unknown>;
}
export interface ThreatSignal {
    id: string;
    category: string;
    source: string;
    description: string;
    evidence: string[];
    severity: number;
    timestamp: number;
}
export interface DetectionStats {
    totalScans: number;
    totalDetections: number;
    avgLatencyMs: number;
    detectionsByCategory: Record<string, number>;
    lastUpdated: string;
}
