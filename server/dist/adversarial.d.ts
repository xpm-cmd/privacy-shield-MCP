/**
 * adversarial.ts - Multi-agent adversarial detection module
 *
 * Detects prompt injection, privilege escalation, data exfiltration,
 * inter-agent collusion, and enforces quorum-based memory writes.
 */
import type { ThreatSignal } from './types.js';
export declare class ThreatDetector {
    private signals;
    private maxSignals;
    private memoryWriteTimestamps;
    private memoryWriteRateLimit;
    /**
     * Analyze an agent's text input for known adversarial patterns.
     * Returns an array of ThreatSignals (empty if nothing detected).
     */
    analyzeInput(agentId: string, input: string): ThreatSignal[];
    /**
     * Analyze a memory write operation for rate abuse and adversarial content.
     */
    analyzeMemoryWrite(agentId: string, key: string, value: string): ThreatSignal[];
    /**
     * Compute a threat score for a specific agent.
     *
     * `score` is the raw average severity across all signals.
     * `decayedScore` applies an exponential decay where signals fully
     * lose weight after 1 hour (3 600 000 ms).
     */
    getThreatScore(agentId: string): {
        score: number;
        decayedScore: number;
    };
}
export declare class CollusionDetector {
    private interactions;
    private maxInteractions;
    /**
     * Record an inter-agent interaction.
     */
    recordInteraction(from: string, to: string, contentHash: string): void;
    /**
     * Run all collusion heuristics and return aggregated results.
     */
    detectCollusion(): {
        rings: string[][];
        unusualFrequency: Array<{
            pair: string[];
            count: number;
        }>;
        coordinatedTiming: Array<{
            agents: string[];
            window: number;
        }>;
    };
    private detectRings;
    private detectUnusualFrequency;
    private detectCoordinatedTiming;
}
interface MemoryProposal {
    id: string;
    key: string;
    value: string;
    proposerId: string;
    timestamp: number;
    votes: Map<string, boolean>;
    resolved: boolean;
    result?: {
        approved: boolean;
        votes: {
            for: number;
            against: number;
            total: number;
        };
        threshold: number;
    };
}
export declare class MemoryQuorum {
    private proposals;
    private threshold;
    private maxProposals;
    constructor(threshold?: number);
    /**
     * Create a new memory-write proposal. The proposer automatically votes yes.
     * Returns the proposal id.
     */
    propose(key: string, value: string, proposerId: string): string;
    /**
     * Cast a vote on an existing proposal.
     *
     * @throws If the proposal does not exist or is already resolved.
     */
    vote(proposalId: string, agentId: string, approve: boolean): void;
    /**
     * Resolve a proposal by tallying votes against the quorum threshold.
     *
     * @throws If the proposal does not exist.
     */
    resolve(proposalId: string): {
        approved: boolean;
        votes: {
            for: number;
            against: number;
            total: number;
        };
        threshold: number;
    };
    /**
     * Retrieve a deep copy of a proposal (or null if not found).
     */
    getProposal(proposalId: string): MemoryProposal | null;
}
export {};
