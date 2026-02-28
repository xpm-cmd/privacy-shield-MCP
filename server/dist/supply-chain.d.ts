/**
 * supply-chain.ts - Supply Chain Security (Layer 7)
 *
 * Scans packages and repositories before installation:
 * - Detects suspicious install scripts (preinstall, postinstall)
 * - Identifies risky dependency patterns (GitHub URLs, "latest" versions)
 * - Checks for known malicious package name patterns (typosquatting)
 * - Validates Hugging Face model repos for suspicious files
 * - Functional approach: alert on real signals, no overreaction
 */
import type { RiskLevel, Finding, AnalysisResult } from './types.js';
interface PackageJsonScanResult {
    safe: boolean;
    risk_level: RiskLevel;
    findings: Finding[];
    summary: string;
    recommendations: string[];
}
interface RepoScanResult {
    safe: boolean;
    risk_level: RiskLevel;
    findings: Finding[];
    summary: string;
    suspicious_files: string[];
    recommendations: string[];
}
/**
 * Scan a package.json content for supply chain risks.
 * Designed to be practical: flags real dangers, not every dependency.
 */
export declare function analyzePackageJson(packageJsonContent: string): PackageJsonScanResult;
/**
 * Scan a list of file paths from a repository for suspicious files.
 * Used when cloning/downloading from GitHub or Hugging Face.
 */
export declare function analyzeRepoFiles(filePaths: string[]): RepoScanResult;
/**
 * Quick scan an install command to check if it needs deeper inspection.
 * Returns whether the install target should be fetched and scanned.
 */
export declare function analyzeInstallCommand(command: string): {
    should_scan: boolean;
    package_manager: string;
    targets: string[];
    risk_signals: string[];
};
/**
 * Comprehensive supply chain scan: combines install command analysis
 * with package.json content scanning.
 */
export declare function analyzeSupplyChain(command: string, packageJsonContent?: string, repoFiles?: string[]): AnalysisResult;
export {};
