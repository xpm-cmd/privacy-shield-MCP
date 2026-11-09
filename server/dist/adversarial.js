/**
 * adversarial.ts - Multi-agent adversarial detection module
 *
 * Detects prompt injection, privilege escalation, data exfiltration,
 * inter-agent collusion, and enforces quorum-based memory writes.
 */
import { randomUUID } from 'node:crypto';
const DETECTION_PATTERNS = [
    {
        id: 'prompt-injection',
        pattern: /ignore\s+previous|system\s+prompt|disregard/i,
        severity: 0.9,
        category: 'prompt-injection',
        description: 'Prompt injection attempt detected',
    },
    {
        id: 'role-manipulation',
        pattern: /you\s+are\s+a\s+hacker|act\s+as\s+root/i,
        severity: 0.85,
        category: 'role-manipulation',
        description: 'Role manipulation attempt detected',
    },
    {
        id: 'privilege-injection',
        pattern: /admin\s*=\s*true|role\s*[:=]\s*['"]?admin/i,
        severity: 0.95,
        category: 'privilege-injection',
        description: 'Privilege injection attempt detected',
    },
    {
        id: 'privilege-escalation',
        pattern: /chmod|chown|sudo/i,
        severity: 0.9,
        category: 'privilege-escalation',
        description: 'Privilege escalation attempt detected',
    },
    {
        id: 'data-exfiltration-network',
        pattern: /curl|wget|http\.get.*\bhttps?:\/\//i,
        severity: 0.85,
        category: 'data-exfiltration',
        description: 'Network data exfiltration attempt detected',
    },
    {
        id: 'data-exfiltration-encoded',
        pattern: /base64\s+[^\s]+\s*\|/i,
        severity: 0.6,
        category: 'data-exfiltration',
        description: 'Encoded data exfiltration attempt detected',
    },
];
// ---------------------------------------------------------------------------
// ThreatDetector
// ---------------------------------------------------------------------------
export class ThreatDetector {
    signals = [];
    maxSignals = 10_000;
    memoryWriteTimestamps = new Map();
    memoryWriteRateLimit = 10; // per minute
    /**
     * Analyze an agent's text input for known adversarial patterns.
     * Returns an array of ThreatSignals (empty if nothing detected).
     */
    analyzeInput(agentId, input) {
        const detected = [];
        for (const dp of DETECTION_PATTERNS) {
            // Reset stateful regex
            dp.pattern.lastIndex = 0;
            if (dp.pattern.test(input)) {
                const signal = {
                    id: randomUUID(),
                    category: dp.category,
                    source: agentId,
                    description: dp.description,
                    evidence: [input.slice(0, 200)],
                    severity: dp.severity,
                    timestamp: Date.now(),
                };
                detected.push(signal);
                this.signals.push(signal);
            }
        }
        // Batch eviction: trim oldest 10% when over capacity
        if (this.signals.length > this.maxSignals) {
            const trimCount = Math.ceil(this.maxSignals * 0.1);
            this.signals.splice(0, trimCount);
        }
        return detected;
    }
    /**
     * Analyze a memory write operation for rate abuse and adversarial content.
     */
    analyzeMemoryWrite(agentId, key, value) {
        const detected = [];
        const now = Date.now();
        // --- Rate-limit check (sliding window: 60 s) ---
        if (!this.memoryWriteTimestamps.has(agentId)) {
            this.memoryWriteTimestamps.set(agentId, []);
        }
        const timestamps = this.memoryWriteTimestamps.get(agentId);
        // Evict entries older than the sliding window
        const windowStart = now - 60_000;
        while (timestamps.length > 0 && timestamps[0] < windowStart) {
            timestamps.shift();
        }
        timestamps.push(now);
        if (timestamps.length > this.memoryWriteRateLimit) {
            const signal = {
                id: randomUUID(),
                category: 'memory-poisoning',
                source: agentId,
                description: `Memory write rate exceeded: ${timestamps.length} writes in 60 s (limit ${this.memoryWriteRateLimit})`,
                evidence: [`key=${key}`],
                severity: 0.8,
                timestamp: now,
            };
            detected.push(signal);
            this.signals.push(signal);
        }
        // --- Pattern check on key + value ---
        const combined = `${key} ${value}`;
        const patternSignals = this.analyzeInput(agentId, combined);
        detected.push(...patternSignals);
        return detected;
    }
    /**
     * Compute a threat score for a specific agent.
     *
     * `score` is the raw average severity across all signals.
     * `decayedScore` applies an exponential decay where signals fully
     * lose weight after 1 hour (3 600 000 ms).
     */
    getThreatScore(agentId) {
        const agentSignals = this.signals.filter((s) => s.source === agentId);
        if (agentSignals.length === 0) {
            return { score: 0, decayedScore: 0 };
        }
        const now = Date.now();
        let rawSum = 0;
        let decayedSum = 0;
        for (const signal of agentSignals) {
            const age = now - signal.timestamp;
            const decay = Math.max(0, 1 - age / 3_600_000);
            rawSum += signal.severity;
            decayedSum += signal.severity * decay;
        }
        return {
            score: rawSum / agentSignals.length,
            decayedScore: decayedSum / agentSignals.length,
        };
    }
}
export class CollusionDetector {
    interactions = [];
    maxInteractions = 10_000;
    /**
     * Record an inter-agent interaction.
     */
    recordInteraction(from, to, contentHash) {
        this.interactions.push({
            from,
            to,
            contentHash,
            timestamp: Date.now(),
        });
        // Batch evict oldest 1000 if over capacity
        if (this.interactions.length > this.maxInteractions) {
            this.interactions.splice(0, 1000);
        }
    }
    /**
     * Run all collusion heuristics and return aggregated results.
     */
    detectCollusion() {
        const { rings, truncated } = this.detectRings();
        return {
            rings,
            ringsTruncated: truncated,
            unusualFrequency: this.detectUnusualFrequency(),
            coordinatedTiming: this.detectCoordinatedTiming(),
        };
    }
    // --- Ring detection via bounded DFS cycle finding ---
    /** Longest ring reported (number of agents). */
    static MAX_RING_LENGTH = 10;
    /** Rings reported at most; a dense graph has exponentially many. */
    static MAX_RINGS = 100;
    /** Edge visits allowed per detection, so search time stays bounded on any graph. */
    static MAX_SEARCH_STEPS = 50_000;
    detectRings() {
        // Build adjacency list (sorted for deterministic output)
        const adjSets = new Map();
        for (const { from, to } of this.interactions) {
            if (!adjSets.has(from))
                adjSets.set(from, new Set());
            adjSets.get(from).add(to);
        }
        const adj = new Map();
        for (const [node, next] of adjSets)
            adj.set(node, [...next].sort());
        const rings = [];
        let steps = 0;
        let truncated = false;
        // Each simple cycle is reported once, rotated to start at its smallest agent: the search
        // from `start` only walks through agents that sort after `start`, so no ring is found
        // twice and no dedup set is needed.
        for (const start of [...adj.keys()].sort()) {
            const path = [start];
            const onPath = new Set(path);
            const dfs = (node) => {
                for (const next of adj.get(node) ?? []) {
                    if (++steps > CollusionDetector.MAX_SEARCH_STEPS) {
                        truncated = true;
                        return;
                    }
                    if (next === start) {
                        if (path.length >= 3) {
                            rings.push([...path]);
                            if (rings.length >= CollusionDetector.MAX_RINGS) {
                                truncated = true;
                                return;
                            }
                        }
                        continue;
                    }
                    if (next < start || onPath.has(next) || path.length >= CollusionDetector.MAX_RING_LENGTH)
                        continue;
                    path.push(next);
                    onPath.add(next);
                    dfs(next);
                    onPath.delete(next);
                    path.pop();
                    if (truncated)
                        return;
                }
            };
            dfs(start);
            if (truncated)
                break;
        }
        return { rings, truncated };
    }
    // --- Unusual frequency detection ---
    detectUnusualFrequency() {
        const pairCounts = new Map();
        for (const { from, to } of this.interactions) {
            const key = [from, to].sort().join('<->');
            pairCounts.set(key, (pairCounts.get(key) ?? 0) + 1);
        }
        const flagged = [];
        for (const [key, count] of pairCounts) {
            if (count > 10) {
                flagged.push({ pair: key.split('<->'), count });
            }
        }
        return flagged;
    }
    // --- Coordinated timing detection ---
    detectCoordinatedTiming() {
        const windowSize = 5000; // 5 seconds
        const flagged = [];
        if (this.interactions.length === 0)
            return flagged;
        // Sort by timestamp
        const sorted = [...this.interactions].sort((a, b) => a.timestamp - b.timestamp);
        // Sliding window
        let windowStart = 0;
        for (let i = 0; i < sorted.length; i++) {
            // Advance window start
            while (sorted[windowStart].timestamp <
                sorted[i].timestamp - windowSize) {
                windowStart++;
            }
            const windowInteractions = sorted.slice(windowStart, i + 1);
            if (windowInteractions.length >= 5) {
                const agents = new Set();
                for (const inter of windowInteractions) {
                    agents.add(inter.from);
                    agents.add(inter.to);
                }
                if (agents.size >= 3) {
                    flagged.push({
                        agents: [...agents],
                        window: sorted[i].timestamp,
                    });
                }
            }
        }
        return flagged;
    }
}
export class MemoryQuorum {
    proposals = new Map();
    threshold;
    minVoters;
    maxProposals = 1000;
    /**
     * @param threshold  Share of "for" votes needed (default 2/3).
     * @param minVoters  Votes needed before a proposal can pass, the proposer's included
     *                   (default 3). Without it a proposer approves its own write 1/1.
     */
    constructor(threshold = 0.67, minVoters = 3) {
        this.threshold = threshold;
        this.minVoters = Math.max(1, Math.floor(minVoters));
    }
    /**
     * Create a new memory-write proposal. The proposer automatically votes yes.
     * Returns the proposal id.
     */
    propose(key, value, proposerId) {
        const id = randomUUID();
        const votes = new Map();
        votes.set(proposerId, true);
        const proposal = {
            id,
            key,
            value,
            proposerId,
            timestamp: Date.now(),
            votes,
            resolved: false,
        };
        // Evict oldest if at capacity
        if (this.proposals.size >= this.maxProposals) {
            let oldestId = null;
            let oldestTs = Infinity;
            for (const [pid, p] of this.proposals) {
                if (p.timestamp < oldestTs) {
                    oldestTs = p.timestamp;
                    oldestId = pid;
                }
            }
            if (oldestId) {
                this.proposals.delete(oldestId);
            }
        }
        this.proposals.set(id, proposal);
        return id;
    }
    /**
     * Cast a vote on an existing proposal.
     *
     * @throws If the proposal does not exist or is already resolved.
     */
    vote(proposalId, agentId, approve) {
        const proposal = this.proposals.get(proposalId);
        if (!proposal) {
            throw new Error(`Proposal '${proposalId}' not found`);
        }
        if (proposal.resolved) {
            throw new Error(`Proposal '${proposalId}' is already resolved`);
        }
        proposal.votes.set(agentId, approve);
    }
    /**
     * Resolve a proposal by tallying votes against the quorum threshold.
     *
     * @throws If the proposal does not exist.
     */
    resolve(proposalId) {
        const proposal = this.proposals.get(proposalId);
        if (!proposal) {
            throw new Error(`Proposal '${proposalId}' not found`);
        }
        let forCount = 0;
        let againstCount = 0;
        for (const approved of proposal.votes.values()) {
            if (approved) {
                forCount++;
            }
            else {
                againstCount++;
            }
        }
        const total = forCount + againstCount;
        const approved = total >= this.minVoters && forCount / total >= this.threshold;
        const result = {
            approved,
            votes: { for: forCount, against: againstCount, total },
            threshold: this.threshold,
            minVoters: this.minVoters,
        };
        proposal.resolved = true;
        proposal.result = result;
        return result;
    }
    /**
     * Retrieve a deep copy of a proposal (or null if not found).
     */
    getProposal(proposalId) {
        const proposal = this.proposals.get(proposalId);
        if (!proposal)
            return null;
        // Deep copy - Map requires manual cloning
        return {
            ...proposal,
            votes: new Map(proposal.votes),
            result: proposal.result
                ? {
                    ...proposal.result,
                    votes: { ...proposal.result.votes },
                }
                : undefined,
        };
    }
}
//# sourceMappingURL=adversarial.js.map