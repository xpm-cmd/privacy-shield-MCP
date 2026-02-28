/**
 * adversarial.ts - Multi-agent adversarial detection module
 *
 * Detects prompt injection, privilege escalation, data exfiltration,
 * inter-agent collusion, and enforces quorum-based memory writes.
 */

import { randomUUID } from 'node:crypto';
import type { AgentAction, ThreatSignal } from './types.js';

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

interface DetectionPattern {
  id: string;
  pattern: RegExp;
  severity: number;
  category: string;
  description: string;
}

const DETECTION_PATTERNS: DetectionPattern[] = [
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
  private signals: ThreatSignal[] = [];
  private maxSignals = 10_000;
  private memoryWriteTimestamps: Map<string, number[]> = new Map();
  private memoryWriteRateLimit = 10; // per minute

  /**
   * Analyze an agent's text input for known adversarial patterns.
   * Returns an array of ThreatSignals (empty if nothing detected).
   */
  analyzeInput(agentId: string, input: string): ThreatSignal[] {
    const detected: ThreatSignal[] = [];

    for (const dp of DETECTION_PATTERNS) {
      // Reset stateful regex
      dp.pattern.lastIndex = 0;

      if (dp.pattern.test(input)) {
        const signal: ThreatSignal = {
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
  analyzeMemoryWrite(
    agentId: string,
    key: string,
    value: string,
  ): ThreatSignal[] {
    const detected: ThreatSignal[] = [];
    const now = Date.now();

    // --- Rate-limit check (sliding window: 60 s) ---
    if (!this.memoryWriteTimestamps.has(agentId)) {
      this.memoryWriteTimestamps.set(agentId, []);
    }

    const timestamps = this.memoryWriteTimestamps.get(agentId)!;

    // Evict entries older than the sliding window
    const windowStart = now - 60_000;
    while (timestamps.length > 0 && timestamps[0] < windowStart) {
      timestamps.shift();
    }

    timestamps.push(now);

    if (timestamps.length > this.memoryWriteRateLimit) {
      const signal: ThreatSignal = {
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
  getThreatScore(agentId: string): { score: number; decayedScore: number } {
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

// ---------------------------------------------------------------------------
// CollusionDetector
// ---------------------------------------------------------------------------

interface Interaction {
  from: string;
  to: string;
  contentHash: string;
  timestamp: number;
}

export class CollusionDetector {
  private interactions: Interaction[] = [];
  private maxInteractions = 10_000;

  /**
   * Record an inter-agent interaction.
   */
  recordInteraction(from: string, to: string, contentHash: string): void {
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
  detectCollusion(): {
    rings: string[][];
    unusualFrequency: Array<{ pair: string[]; count: number }>;
    coordinatedTiming: Array<{ agents: string[]; window: number }>;
  } {
    return {
      rings: this.detectRings(),
      unusualFrequency: this.detectUnusualFrequency(),
      coordinatedTiming: this.detectCoordinatedTiming(),
    };
  }

  // --- Ring detection via DFS cycle finding ---

  private detectRings(): string[][] {
    // Build adjacency list
    const adj = new Map<string, Set<string>>();
    for (const { from, to } of this.interactions) {
      if (!adj.has(from)) adj.set(from, new Set());
      adj.get(from)!.add(to);
    }

    const rings: string[][] = [];
    const visited = new Set<string>();
    const ringSet = new Set<string>(); // dedup serialised rings

    const dfs = (node: string, path: string[]): void => {
      if (path.length > 10) return; // max depth

      const neighbours = adj.get(node);
      if (!neighbours) return;

      for (const next of neighbours) {
        const cycleStart = path.indexOf(next);
        if (cycleStart !== -1) {
          const cycle = path.slice(cycleStart);
          if (cycle.length >= 3) {
            // Normalise: rotate so smallest element comes first
            const minIdx = cycle.indexOf(
              cycle.reduce((a, b) => (a < b ? a : b)),
            );
            const normalised = [
              ...cycle.slice(minIdx),
              ...cycle.slice(0, minIdx),
            ];
            const key = normalised.join('->');
            if (!ringSet.has(key)) {
              ringSet.add(key);
              rings.push(normalised);
            }
          }
          continue;
        }

        if (!visited.has(next)) {
          dfs(next, [...path, next]);
        }
      }
    };

    for (const node of adj.keys()) {
      visited.clear();
      dfs(node, [node]);
      visited.add(node);
    }

    return rings;
  }

  // --- Unusual frequency detection ---

  private detectUnusualFrequency(): Array<{ pair: string[]; count: number }> {
    const pairCounts = new Map<string, number>();

    for (const { from, to } of this.interactions) {
      const key = [from, to].sort().join('<->');
      pairCounts.set(key, (pairCounts.get(key) ?? 0) + 1);
    }

    const flagged: Array<{ pair: string[]; count: number }> = [];

    for (const [key, count] of pairCounts) {
      if (count > 10) {
        flagged.push({ pair: key.split('<->'), count });
      }
    }

    return flagged;
  }

  // --- Coordinated timing detection ---

  private detectCoordinatedTiming(): Array<{
    agents: string[];
    window: number;
  }> {
    const windowSize = 5000; // 5 seconds
    const flagged: Array<{ agents: string[]; window: number }> = [];

    if (this.interactions.length === 0) return flagged;

    // Sort by timestamp
    const sorted = [...this.interactions].sort(
      (a, b) => a.timestamp - b.timestamp,
    );

    // Sliding window
    let windowStart = 0;

    for (let i = 0; i < sorted.length; i++) {
      // Advance window start
      while (
        sorted[windowStart].timestamp <
        sorted[i].timestamp - windowSize
      ) {
        windowStart++;
      }

      const windowInteractions = sorted.slice(windowStart, i + 1);

      if (windowInteractions.length >= 5) {
        const agents = new Set<string>();
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

// ---------------------------------------------------------------------------
// MemoryQuorum
// ---------------------------------------------------------------------------

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
    votes: { for: number; against: number; total: number };
    threshold: number;
  };
}

export class MemoryQuorum {
  private proposals: Map<string, MemoryProposal> = new Map();
  private threshold: number;
  private maxProposals = 1000;

  constructor(threshold: number = 0.67) {
    this.threshold = threshold;
  }

  /**
   * Create a new memory-write proposal. The proposer automatically votes yes.
   * Returns the proposal id.
   */
  propose(key: string, value: string, proposerId: string): string {
    const id = randomUUID();

    const votes = new Map<string, boolean>();
    votes.set(proposerId, true);

    const proposal: MemoryProposal = {
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
      let oldestId: string | null = null;
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
  vote(proposalId: string, agentId: string, approve: boolean): void {
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
  resolve(proposalId: string): {
    approved: boolean;
    votes: { for: number; against: number; total: number };
    threshold: number;
  } {
    const proposal = this.proposals.get(proposalId);

    if (!proposal) {
      throw new Error(`Proposal '${proposalId}' not found`);
    }

    let forCount = 0;
    let againstCount = 0;

    for (const approved of proposal.votes.values()) {
      if (approved) {
        forCount++;
      } else {
        againstCount++;
      }
    }

    const total = forCount + againstCount;
    const approved = total > 0 && forCount / total >= this.threshold;

    const result = {
      approved,
      votes: { for: forCount, against: againstCount, total },
      threshold: this.threshold,
    };

    proposal.resolved = true;
    proposal.result = result;

    return result;
  }

  /**
   * Retrieve a deep copy of a proposal (or null if not found).
   */
  getProposal(proposalId: string): MemoryProposal | null {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) return null;

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
