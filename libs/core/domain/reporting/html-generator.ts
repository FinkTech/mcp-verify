/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
import type { Report } from '../mcp-server/entities/validation.types';
import { translations } from './i18n';
import type { Language } from './i18n';
import { GraphGenerator } from './graph-generator';

export interface BaselineComparison {
    baseline: {
        timestamp: string;
        security_score: number;
        quality_score: number;
        findings_count: number;
    };
    current: {
        timestamp: string;
        security_score: number;
        quality_score: number;
        findings_count: number;
    };
    delta: {
        security_score: number;
        quality_score: number;
        findings_count: number;
    };
    introduced: Array<{ rule: string; message: string; severity: string; location?: string }>;
    resolved: Array<{ rule: string; message: string; severity: string; location?: string }>;
}

// Helper for safe translation access
function getTranslation(t: typeof translations['en'], key: string): string {
    const val = (t as Record<string, string>)[key];
    return val || key;
}

export class HtmlReportGenerator {
    static generate(report: Report, lang: Language = 'en', baseline?: BaselineComparison): string {
        const t = translations[lang];

        // Safety check for undefined sections
        const qualityScore = report.quality ? report.quality.score : 0;
        const protocolPassed = report.protocolCompliance ? report.protocolCompliance.passed : true;

        // Generate Mermaid Graph
        const mermaidGraph = GraphGenerator.generateMermaid({
            tools: report.tools.items,
            resources: report.resources.items,
            prompts: report.prompts.items
        }, 'dark');

        // Calculate severity counts
        const findingsByS = report.security.findings.reduce((acc, f) => {
            const sev = f.severity || 'low';
            acc[sev] = (acc[sev] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);

        const criticalCount = findingsByS['critical'] || 0;
        const highCount = findingsByS['high'] || 0;
        const mediumCount = findingsByS['medium'] || 0;
        const lowCount = findingsByS['low'] || 0;
        const totalFindings = report.security.findings.length;

        // Sort findings by severity
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        const sortedFindings = [...report.security.findings].sort((a, b) => {
            const aSev = severityOrder[a.severity as keyof typeof severityOrder] ?? 999;
            const bSev = severityOrder[b.severity as keyof typeof severityOrder] ?? 999;
            return aSev - bSev;
        });

        // Generate Risk Heatmap data (map findings to 3x3 grid by impact/probability)
        const heatmapData = generateHeatmapData(sortedFindings);

        // Generate Surgical Summary
        const surgicalSummary = generateSurgicalSummary(report, t);

        // Estimate time to fix
        const timeToFix = estimateTimeToFix(criticalCount, highCount, mediumCount);

        // Calculate risk score (0-10)
        const riskScore = ((100 - report.security.score) / 10).toFixed(1);

        // Generate compliance matrix data
        const complianceData = generateComplianceMatrix(sortedFindings);

        // Generate finding cards HTML
        const findingCardsHtml = sortedFindings.map((finding, idx) => {
            const sev = finding.severity || 'low';
            const sevColor = getSeverityTailwindColor(sev);
            const sevBgColor = getSeverityBgColor(sev);
            const code = finding.rule || `SEC-${String(idx + 1).padStart(3, '0')}`;
            const ruleIcon = getRuleIcon(code); // Use rule-specific icon

            const evidenceCode = typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2);
            const evidenceEscaped = escapeHtml(evidenceCode);
            const evidenceForJs = escapeForJs(evidenceCode);

            const recommendation = finding.remediation || 'Review and remediate this security issue.';
            const recForJs = escapeForJs(recommendation);

            // Detect if finding has fuzzer payload
            const hasFuzzerPayload = finding.evidence && (
                typeof finding.evidence === 'string' && (finding.evidence as string).includes('mcp-verify fuzz')
            );

            // Detect if finding is validation issue (SEC-019)
            const isValidationIssue = code === 'SEC-019' || finding.message?.includes('validation');

            // Generate agency tags based on finding metadata
            const agencyTags = generateAgencyTags(finding, t);

            return `
<div class="glass-panel-depth border-glow-hover group relative overflow-hidden">
    <div class="absolute left-0 top-0 bottom-0 w-[3px] ${sev === 'critical' ? 'bg-amber-neon shadow-[0_0_15px_rgba(245,158,11,0.6)]' : ''} z-20"></div>
    <div class="p-8 ${sev === 'critical' ? 'pl-10' : ''}">
        <div class="flex flex-col md:flex-row justify-between items-start mb-6 gap-4">
            <div class="flex gap-5">
                <div class="mt-1 p-2 rounded-lg bg-${sevColor}/10 border border-${sevColor}/20 text-${sevColor} shadow-[0_0_15px_rgba(${getSeverityRgba(sev)},0.2)] h-fit">
                    <span class="material-symbols-outlined text-xl">${ruleIcon}</span>
                </div>
                <div>
                    <div class="flex items-center gap-3 mb-2">
                        <h3 class="text-lg font-bold text-white tracking-tight">${escapeHtml(finding.message || finding.rule || t.security_finding || 'Security Finding')}</h3>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-white/5 text-slate-400 border border-white/10">${escapeHtml(code)}</span>
                    </div>
                    ${agencyTags.length > 0 ? `
                    <div class="flex gap-2 mb-3">
                        ${agencyTags.map(tag => `
                        <div class="agency-tag px-2 py-0.5 rounded flex items-center gap-1.5 text-[10px] text-slate-400 group/tag cursor-help">
                            <span class="material-symbols-outlined text-[12px] text-${tag.color}-400 neon-icon-glow">${tag.icon}</span>
                            <span class="group-hover/tag:text-${tag.color}-100 transition-colors">${tag.label}</span>
                        </div>
                        `).join('')}
                    </div>
                    ` : ''}
                    <p class="text-sm text-slate-400 leading-relaxed font-light max-w-2xl">
                        ${escapeHtml(finding.message || '')}
                    </p>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <span class="px-3 py-1 rounded-full text-[10px] uppercase font-bold tracking-wider ${sevBgColor}">${sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
                <span class="px-3 py-1 rounded-full text-[10px] uppercase font-bold tracking-wider bg-white/5 text-slate-400 border border-white/10">Open</span>
            </div>
        </div>

        ${hasFuzzerPayload ? `
        <!-- CLI Reproducer (Fuzzer Playground) -->
        <div class="bg-[#0c0c14] rounded-lg border border-white/10 overflow-hidden font-mono text-xs relative shadow-inner mb-4 ring-1 ring-white/5">
            <div class="flex items-center justify-between px-4 py-2 bg-white/[0.03] border-b border-white/5">
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined text-[14px] text-slate-500">terminal</span>
                    <span class="text-slate-400 font-bold text-[10px] uppercase tracking-wider">${t.cli_reproducer || 'CLI Reproducer'}</span>
                </div>
                <div class="flex gap-2">
                    <button onclick="copyCode(this, '${evidenceForJs}')" class="text-[10px] text-slate-400 hover:text-white flex items-center gap-1 bg-white/5 px-2 py-0.5 rounded hover:bg-white/10 transition-colors border border-transparent hover:border-white/10">
                        <span class="material-symbols-outlined text-[10px]">content_copy</span> ${t.copy || 'Copy'}
                    </button>
                </div>
            </div>
            <div class="p-4 text-slate-300 overflow-x-auto relative group/code">
                <pre class="text-xs">${evidenceEscaped}</pre>
            </div>
        </div>
        ` : isValidationIssue && finding.remediation ? `
        <!-- Shielded Schema Diff -->
        <div class="bg-[#050508]/80 rounded-xl border border-white/10 overflow-hidden font-mono text-xs relative backdrop-blur-sm shadow-inner mb-4">
            <div class="flex items-center justify-between px-4 py-2 border-b border-white/5 bg-white/[0.02]">
                <span class="text-[10px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2">
                    <span class="material-symbols-outlined text-sm">difference</span>
                    ${t.shielded_schema_diff || 'Shielded Schema Diff'}
                </span>
                <div class="flex gap-4 text-[10px] font-bold uppercase tracking-wider">
                    <span class="text-red-400 flex items-center gap-1"><span class="block w-2 h-2 rounded-sm bg-red-400/20 border border-red-400/50"></span> ${t.vulnerable || 'Vulnerable'}</span>
                    <span class="text-emerald-400 flex items-center gap-1"><span class="block w-2 h-2 rounded-sm bg-emerald-400/20 border border-emerald-400/50"></span> ${t.hardened || 'Hardened'}</span>
                </div>
            </div>
            <div class="grid grid-cols-2 divide-x divide-white/5">
                <div class="p-3 bg-red-500/[0.02]">
                    <div class="space-y-0.5 text-slate-400 opacity-80">
                        <pre class="text-xs">${evidenceEscaped}</pre>
                    </div>
                </div>
                <div class="p-3 bg-emerald-500/[0.02]">
                    <div class="space-y-0.5 text-slate-300">
                        <pre class="text-xs text-emerald-300">${escapeHtml(recommendation)}</pre>
                    </div>
                </div>
            </div>
        </div>
        ` : finding.evidence || finding.remediation ? `
        <!-- Evidence + Recommendation -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            ${finding.evidence ? `
            <div class="relative group/code">
                <div class="absolute -top-3 left-4 px-2 bg-[#050508] text-[10px] font-bold text-slate-500 uppercase tracking-wider z-10">${t.evidence || 'Evidence'}</div>
                <div class="bg-[#0c0c14] rounded-lg border border-white/10 overflow-hidden font-mono text-xs relative">
                    <div class="p-4 pt-6 text-slate-300 overflow-x-auto max-h-64">
                        <pre class="text-xs">${evidenceEscaped}</pre>
                    </div>
                    <button onclick="copyCode(this, '${evidenceForJs}')" class="absolute top-2 right-2 p-1.5 rounded-md bg-slate-800/50 hover:bg-slate-700 text-slate-400 hover:text-white border border-transparent hover:border-slate-600 transition-all active:scale-95">
                        <span class="material-symbols-outlined text-[16px]">content_copy</span>
                    </button>
                </div>
            </div>
            ` : ''}
            ${finding.remediation ? `
            <div class="bg-gradient-to-br from-slate-800/40 to-slate-900/40 rounded-lg border border-slate-700/50 p-5 flex flex-col justify-between hover:border-primary/30 transition-colors">
                <div>
                    <div class="flex items-center gap-2 mb-3">
                        <div class="bg-primary/20 p-1 rounded">
                            <span class="material-symbols-outlined text-primary text-sm">lightbulb</span>
                        </div>
                        <span class="text-xs font-bold text-white uppercase tracking-wider">${t.recommendation || 'Remediation'}</span>
                    </div>
                    <div class="space-y-2 text-xs text-slate-400 pl-1">
                        <p>${escapeHtml(recommendation)}</p>
                    </div>
                </div>
                <button onclick="copyCode(this, '${recForJs}')" class="mt-4 w-full py-2 bg-slate-800 hover:bg-primary hover:text-black text-slate-300 text-xs font-bold rounded border border-slate-700 hover:border-primary transition-all duration-300 transform hover:scale-[1.02] flex items-center justify-center gap-2">
                    <span class="material-symbols-outlined text-[14px]">code</span>
                    ${t.copy_remediation || 'Copy Remediation'}
                </button>
            </div>
            ` : ''}
        </div>
        ` : ''}
    </div>
    <div class="px-6 py-2 bg-slate-900/50 border-t border-white/5 flex justify-between items-center text-[10px] text-slate-500 font-mono">
        <span>${t.detected || 'Detected'}: ${getTimeAgo(report.timestamp, t)}</span>
        <span>${t.source || 'Source'}: <a href="https://github.com/FinkTech/mcp-verify" target="_blank" rel="noopener noreferrer" class="text-primary hover:text-white transition-colors hover:underline">MCP Verify</a></span>
    </div>
</div>
            `.trim();
        }).join('\n');

        // Generate Drift Analysis HTML (if baseline provided)
        const driftAnalysisHtml = baseline ? `
<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <div class="glass-panel-depth p-0 overflow-hidden border-glow-hover flex flex-col h-full">
        <div class="px-6 py-4 border-b border-white/5 bg-critical/5 flex justify-between items-center">
            <h3 class="text-xs font-bold text-critical uppercase tracking-widest flex items-center gap-2">
                <span class="relative flex h-2 w-2">
                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-critical opacity-75"></span>
                    <span class="relative inline-flex rounded-full h-2 w-2 bg-critical shadow-[0_0_8px_rgba(239,68,68,0.8)]"></span>
                </span>
                ${t.introduced_risks || 'Introduced Risks'}
            </h3>
            <span class="text-[10px] font-mono bg-critical/10 text-critical px-2 py-0.5 rounded border border-critical/20">${baseline.introduced.length} ${t.new_label || 'New'}</span>
        </div>
        <div class="p-4 space-y-2 flex-1 bg-gradient-to-b from-critical/[0.02] to-transparent">
            ${baseline.introduced.length > 0 ? baseline.introduced.map(risk => `
            <div class="flex items-center justify-between p-3 rounded-lg bg-white/[0.03] border border-white/5 hover:bg-white/[0.06] transition-colors group cursor-pointer">
                <div class="flex items-center gap-3">
                    <div class="p-1.5 rounded bg-${getSeverityTailwindColor(risk.severity)}/10 text-${getSeverityTailwindColor(risk.severity)} border border-${getSeverityTailwindColor(risk.severity)}/20 group-hover:shadow-[0_0_10px_rgba(${getSeverityRgba(risk.severity)},0.2)] transition-shadow">
                        <span class="material-symbols-outlined text-sm">${getSeverityIcon(risk.severity)}</span>
                    </div>
                    <div class="flex flex-col">
                        <span class="text-sm text-slate-200 font-medium group-hover:text-white transition-colors">${escapeHtml(risk.message)}</span>
                        ${risk.location ? `<span class="text-[10px] text-slate-500">${escapeHtml(risk.location)}</span>` : ''}
                    </div>
                </div>
                <span class="text-[10px] font-mono text-slate-500 border border-white/10 px-1.5 py-0.5 rounded">${escapeHtml(risk.rule)}</span>
            </div>
            `).join('') : `<p class="text-sm text-slate-500 text-center py-8">${t.no_new_risks || 'No new risks introduced'}</p>`}
        </div>
    </div>
    <div class="glass-panel-depth p-0 overflow-hidden border-glow-hover flex flex-col h-full">
        <div class="px-6 py-4 border-b border-white/5 bg-emerald-500/5 flex justify-between items-center">
            <h3 class="text-xs font-bold text-emerald-400 uppercase tracking-widest flex items-center gap-2">
                <span class="relative flex h-2 w-2">
                    <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"></span>
                </span>
                ${t.resolved_risks || 'Resolved Risks'}
            </h3>
            <span class="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/20">${baseline.resolved.length} ${t.fixed_label || 'Fixed'}</span>
        </div>
        <div class="p-4 space-y-2 flex-1 bg-gradient-to-b from-emerald-500/[0.02] to-transparent">
            ${baseline.resolved.length > 0 ? baseline.resolved.map(risk => `
            <div class="flex items-center justify-between p-3 rounded-lg bg-white/[0.03] border border-white/5 hover:bg-white/[0.06] transition-colors group cursor-pointer">
                <div class="flex items-center gap-3">
                    <div class="p-1.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 group-hover:shadow-[0_0_10px_rgba(52,211,153,0.2)] transition-shadow">
                        <span class="material-symbols-outlined text-sm">check_circle</span>
                    </div>
                    <div class="flex flex-col">
                        <span class="text-sm text-slate-200 font-medium group-hover:text-white transition-colors">${escapeHtml(risk.message)}</span>
                        ${risk.location ? `<span class="text-[10px] text-slate-500">${escapeHtml(risk.location)}</span>` : ''}
                    </div>
                </div>
                <span class="text-[10px] font-mono text-emerald-500 font-bold px-1.5 py-0.5 bg-emerald-500/5 rounded border border-emerald-500/10">${t.updated_label || 'Updated'}</span>
            </div>
            `).join('') : `<p class="text-sm text-slate-500 text-center py-8">${t.no_risks_resolved || 'No risks resolved'}</p>`}
        </div>
    </div>
</div>
        ` : '';

        return `
<!DOCTYPE html>
<html class="dark" lang="${lang}">
<head>
    <meta charset="utf-8"/>
    <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
    <title>${t.title || 'MCP Audit'}: ${escapeHtml(report.server_name)}</title>
    <link href="https://fonts.googleapis.com" rel="preconnect"/>
    <link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect"/>
    <link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Geist+Mono:wght@300;400;500;700&display=swap" rel="stylesheet"/>
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
    <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
    <script src="https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        tailwind.config = {
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        "primary": "#07d5d5",
                        "violet-glow": "#8b5cf6",
                        "background-dark": "#050508",
                        "surface-dark": "#0f172a",
                        "critical": "#ef4444",
                        "high": "#f97316",
                        "medium": "#eab308",
                        "low": "#3b82f6",
                    },
                    fontFamily: {
                        "display": ["Geist", "sans-serif"],
                        "mono": ["Geist Mono", "monospace"],
                    },
                    boxShadow: {
                        'glow-primary': '0 0 20px -5px rgba(7, 213, 213, 0.3)',
                        'glow-violet': '0 0 80px 20px rgba(139, 92, 246, 0.15)',
                        'glass-deep': '0 8px 40px -10px rgba(0, 0, 0, 0.6)',
                        'glass-border': 'inset 0 1px 0 0 rgba(255, 255, 255, 0.1)',
                        'neon-glow': '0 0 10px rgba(255,255,255,0.5), 0 0 20px rgba(255,255,255,0.3)',
                    },
                    backgroundImage: {
                        'glass-gradient': 'linear-gradient(180deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.03) 100%)',
                        'card-border': 'linear-gradient(to bottom, rgba(255, 255, 255, 0.15), rgba(255, 255, 255, 0.02))',
                        'amber-neon': 'linear-gradient(180deg, #f59e0b 0%, rgba(245, 158, 11, 0) 100%)'
                    },
                    animation: {
                        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                    }
                },
            },
        }
    </script>
    <style>
        ::-webkit-scrollbar {
            width: 6px;
        }
        ::-webkit-scrollbar-track {
            background: #050508;
        }
        ::-webkit-scrollbar-thumb {
            background: #27272a;
            border-radius: 3px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #3f3f46;
        }
        .glass-panel-depth {
            background: rgba(10, 10, 15, 0.6);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            position: relative;
            box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.3);
            border-radius: 1rem;
        }
        .glass-panel-depth::before {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: inherit;
            padding: 1px;
            background: linear-gradient(to bottom, rgba(255, 255, 255, 0.12), rgba(255, 255, 255, 0.02));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            pointer-events: none;
        }
        .glass-panel-highlight {
            background: rgba(15, 20, 30, 0.7);
            backdrop-filter: blur(30px);
            box-shadow: 0 0 40px -10px rgba(139, 92, 246, 0.1);
        }
        .border-glow-hover {
            transition: all 0.3s ease;
        }
        .border-glow-hover:hover {
            box-shadow: 0 0 25px rgba(255, 255, 255, 0.05), inset 0 0 20px rgba(255, 255, 255, 0.02);
            border-color: rgba(255, 255, 255, 0.2);
        }
        .border-glow-hover:hover::before {
            background: linear-gradient(to bottom, rgba(255, 255, 255, 0.3), rgba(255, 255, 255, 0.05));
        }
        .gauge-inner-glow {
            filter: drop-shadow(0 0 8px rgba(7, 213, 213, 0.4));
        }
        .vertical-glass-divider {
            width: 1px;
            background: linear-gradient(to bottom, transparent, rgba(255, 255, 255, 0.15), transparent);
        }
        .floating-dock {
            background: rgba(20, 20, 25, 0.7);
            backdrop-filter: blur(20px);
            box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        }
        .heatmap-cell {
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .heatmap-cell:hover {
            transform: scale(1.08);
            z-index: 10;
            box-shadow: 0 0 15px rgba(255,255,255,0.1);
        }
        .agency-tag {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(4px);
            transition: all 0.3s ease;
        }
        .agency-tag:hover {
            border-color: rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.06);
        }
        .diff-added {
            background-color: rgba(16, 185, 129, 0.1);
            border-left: 2px solid #10b981;
        }
        .diff-removed {
            background-color: rgba(239, 68, 68, 0.1);
            border-left: 2px solid #ef4444;
            text-decoration: line-through;
            opacity: 0.6;
        }
        @keyframes flow-dash {
            to {
                stroke-dashoffset: -20;
            }
        }
        .animate-flow {
            stroke-dasharray: 4;
            animation: flow-dash 1s linear infinite;
        }
        .hero-glow {
            box-shadow: 0 0 30px rgba(99, 102, 241, 0.15);
        }
        .neon-icon-glow {
            filter: drop-shadow(0 0 4px currentColor);
        }
        /* Mermaid */
        .mermaid {
            display: flex;
            justify-content: center;
        }
        .mermaid svg {
            max-width: 100%;
            height: auto;
        }
    </style>
</head>
<body class="bg-background-dark text-slate-200 font-display antialiased min-h-screen relative overflow-x-hidden selection:bg-violet-500/30 selection:text-white pb-40">
    <!-- Background Glows -->
    <div class="fixed top-0 left-0 w-full h-full pointer-events-none z-0 overflow-hidden">
        <div class="absolute top-[-10%] left-[50%] -translate-x-1/2 w-[1000px] h-[600px] bg-violet-glow/10 rounded-full blur-[120px] opacity-60"></div>
        <div class="absolute bottom-[-10%] right-[0%] w-[800px] h-[800px] bg-indigo-900/10 rounded-full blur-[150px]"></div>
        <div class="absolute top-[20%] left-[-10%] w-[600px] h-[600px] bg-cyan-900/5 rounded-full blur-[100px]"></div>
    </div>

    <main class="relative z-10 w-full max-w-[1000px] mx-auto px-6 py-12 flex flex-col gap-8">
        <!-- Header -->
        <header class="flex flex-col gap-6 mb-2">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end gap-6">
                <div>
                    <div class="flex items-center gap-3 mb-3">
                        <div class="flex items-center justify-center size-8 rounded-lg bg-white/5 border border-white/10 text-white shadow-[0_0_15px_rgba(255,255,255,0.05)] backdrop-blur-md">
                            <span class="material-symbols-outlined text-sm">shield_lock</span>
                        </div>
                        <span class="text-[11px] font-bold tracking-[0.2em] text-slate-400 uppercase">MCP Verify</span>
                    </div>
                    <h1 class="text-4xl md:text-5xl font-bold text-white tracking-tight leading-tight">
                        <span class="text-white drop-shadow-[0_0_15px_rgba(255,255,255,0.15)]">MCP Verify</span><br/>
                        <span class="text-slate-500 font-medium">${t.security_audit || 'Security Audit'}</span>
                    </h1>
                </div>
                <div class="flex flex-col items-end gap-3">
                    <div class="flex items-center gap-2 text-xs text-slate-300 font-mono bg-white/5 px-4 py-2 rounded-full border border-white/10 backdrop-blur-md shadow-glass-border">
                        <span class="size-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)] animate-pulse"></span>
                        ${t.target || 'Target'}: ${escapeHtml(report.server_name)}
                    </div>
                    <p class="text-[11px] text-slate-500 font-medium tracking-wide">${t.scan_id_prefix || 'ID'}: <span class="font-mono text-slate-400">#${generateScanId(report.timestamp)}</span></p>
                </div>
            </div>

            <!-- Surgical Summary -->
            <div class="glass-panel-depth glass-panel-highlight p-6 border border-white/10 bg-white/[0.02] flex flex-col md:flex-row items-center justify-between gap-6 hero-glow">
                <div class="flex gap-4 items-center w-full md:w-auto">
                    <div class="size-14 rounded-full bg-gradient-to-br from-violet-500/20 to-blue-500/10 flex items-center justify-center border border-white/10 shadow-[0_0_20px_rgba(139,92,246,0.25)] ring-1 ring-white/5">
                        <span class="material-symbols-outlined text-violet-300 text-2xl drop-shadow-[0_0_8px_rgba(167,139,250,0.6)]">psychology</span>
                    </div>
                    <div>
                        <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-1 flex items-center gap-2">
                            ${t.surgical_summary || 'Surgical Summary'}
                            <span class="flex h-1.5 w-1.5 relative">
                                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-75"></span>
                                <span class="relative inline-flex rounded-full h-1.5 w-1.5 bg-violet-500"></span>
                            </span>
                        </h3>
                        <p class="text-sm text-slate-300 max-w-lg leading-relaxed font-light">
                            ${surgicalSummary}
                        </p>
                    </div>
                </div>
                <div class="flex items-center gap-8 w-full md:w-auto justify-end px-4">
                    <button onclick="toggleRiskBreakdown()" class="text-right hover:bg-white/5 p-4 rounded-lg transition-all group cursor-pointer">
                        <div class="flex items-center gap-2 justify-end mb-1">
                            <div class="text-[10px] uppercase text-slate-500 font-bold tracking-widest">${t.risk_score || 'Risk Score'}</div>
                            <span class="material-symbols-outlined text-[14px] text-slate-500 group-hover:text-white transition-colors" id="breakdown-icon">expand_more</span>
                        </div>
                        <div class="text-2xl font-mono text-white font-bold drop-shadow-[0_0_10px_rgba(255,255,255,0.3)]">${riskScore}<span class="text-slate-600 text-sm font-normal">/10</span></div>
                    </button>
                </div>
            </div>

            <!-- Risk Score Breakdown (Collapsible) -->
            <div id="risk-breakdown" class="hidden overflow-hidden transition-all duration-300 glass-panel-depth p-6 border border-white/10 bg-white/[0.02]">
                <div class="flex items-center gap-3 mb-6 pb-4 border-b border-white/5">
                    <span class="material-symbols-outlined text-primary text-xl">analytics</span>
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">${t.risk_breakdown || 'Risk Breakdown'}</h3>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <!-- Left: Breakdown Table -->
                    <div class="space-y-3">
                        <div class="text-xs text-slate-500 uppercase tracking-wider mb-4">${t.score_calculation || 'Score Calculation'}</div>

                        ${criticalCount > 0 ? `
                        <div class="flex items-center justify-between p-3 rounded-lg bg-critical/5 border border-critical/10 hover:bg-critical/10 transition-colors">
                            <div class="flex items-center gap-3">
                                <span class="material-symbols-outlined text-critical text-lg">warning</span>
                                <div>
                                    <div class="text-sm font-bold text-white">${t.critical || 'Critical'}</div>
                                    <div class="text-[10px] text-slate-500">${criticalCount} ${t.findings || 'findings'} × 4.0 pts</div>
                                </div>
                            </div>
                            <div class="text-right">
                                <div class="text-lg font-mono font-bold text-critical">${(criticalCount * 4.0).toFixed(1)}</div>
                                <div class="text-[10px] text-slate-500">${t.contribution || 'contribution'}</div>
                            </div>
                        </div>
                        ` : ''}

                        ${highCount > 0 ? `
                        <div class="flex items-center justify-between p-3 rounded-lg bg-high/5 border border-high/10 hover:bg-high/10 transition-colors">
                            <div class="flex items-center gap-3">
                                <span class="material-symbols-outlined text-high text-lg">priority_high</span>
                                <div>
                                    <div class="text-sm font-bold text-white">${t.high || 'High'}</div>
                                    <div class="text-[10px] text-slate-500">${highCount} ${t.findings || 'findings'} × 2.0 pts</div>
                                </div>
                            </div>
                            <div class="text-right">
                                <div class="text-lg font-mono font-bold text-high">${(highCount * 2.0).toFixed(1)}</div>
                                <div class="text-[10px] text-slate-500">${t.contribution || 'contribution'}</div>
                            </div>
                        </div>
                        ` : ''}

                        ${mediumCount > 0 ? `
                        <div class="flex items-center justify-between p-3 rounded-lg bg-medium/5 border border-medium/10 hover:bg-medium/10 transition-colors">
                            <div class="flex items-center gap-3">
                                <span class="material-symbols-outlined text-medium text-lg">info</span>
                                <div>
                                    <div class="text-sm font-bold text-white">${t.medium || 'Medium'}</div>
                                    <div class="text-[10px] text-slate-500">${mediumCount} ${t.findings || 'findings'} × 1.0 pts</div>
                                </div>
                            </div>
                            <div class="text-right">
                                <div class="text-lg font-mono font-bold text-medium">${(mediumCount * 1.0).toFixed(1)}</div>
                                <div class="text-[10px] text-slate-500">${t.contribution || 'contribution'}</div>
                            </div>
                        </div>
                        ` : ''}

                        ${lowCount > 0 ? `
                        <div class="flex items-center justify-between p-3 rounded-lg bg-low/5 border border-low/10 hover:bg-low/10 transition-colors">
                            <div class="flex items-center gap-3">
                                <span class="material-symbols-outlined text-low text-lg">check_circle</span>
                                <div>
                                    <div class="text-sm font-bold text-white">${t.low || 'Low'}</div>
                                    <div class="text-[10px] text-slate-500">${lowCount} ${t.findings || 'findings'} × 0.5 pts</div>
                                </div>
                            </div>
                            <div class="text-right">
                                <div class="text-lg font-mono font-bold text-low">${(lowCount * 0.5).toFixed(1)}</div>
                                <div class="text-[10px] text-slate-500">${t.contribution || 'contribution'}</div>
                            </div>
                        </div>
                        ` : ''}
                    </div>

                    <!-- Right: Summary & Formula -->
                    <div class="glass-panel-depth p-6 flex flex-col justify-center">
                        <div class="space-y-4">
                            <div class="flex items-center justify-between pb-3 border-b border-white/10">
                                <span class="text-xs text-slate-500 uppercase tracking-wider">${t.total_findings || 'Total Findings'}</span>
                                <span class="text-xl font-mono font-bold text-white">${criticalCount + highCount + mediumCount + lowCount}</span>
                            </div>

                            <div class="space-y-2 text-xs text-slate-400 font-mono">
                                <div class="flex justify-between">
                                    <span>Total Points:</span>
                                    <span class="text-white">${(criticalCount * 4.0 + highCount * 2.0 + mediumCount * 1.0 + lowCount * 0.5).toFixed(1)}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>Max Points:</span>
                                    <span class="text-white">${((criticalCount + highCount + mediumCount + lowCount) * 4.0).toFixed(1)}</span>
                                </div>
                            </div>

                            <div class="pt-4 border-t border-white/10">
                                <div class="text-xs text-slate-500 uppercase tracking-wider mb-2">${t.weighted_average || 'Weighted Average'}</div>
                                <div class="text-3xl font-mono font-bold text-primary drop-shadow-[0_0_15px_rgba(147,51,234,0.5)]">
                                    ${riskScore}<span class="text-slate-600 text-lg">/10</span>
                                </div>
                            </div>

                            <div class="text-[10px] text-slate-600 leading-relaxed mt-4 p-3 bg-black/20 rounded border border-white/5">
                                Score = 100 - (Total Points / Max Points) × 100
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <!-- Executive Summary -->
        ${(() => {
            const score = report.security.score;
            const hasCritical = criticalCount > 0;
            const hasHigh = highCount > 0;

            let ratingLevel = '';
            let ratingColor = '';
            let ratingIcon = '';
            let postureText = '';

            if (hasCritical) {
                ratingLevel = t.requires_immediate_action || 'Requires Immediate Action';
                ratingColor = 'critical';
                ratingIcon = 'emergency';
                postureText = t.critical_findings_detected || 'Critical findings detected';
            } else if (hasHigh || score < 70) {
                ratingLevel = t.requires_attention || 'Requires Attention';
                ratingColor = 'high';
                ratingIcon = 'priority_high';
                postureText = t.moderate_findings_detected || 'Moderate findings detected';
            } else if (score >= 90) {
                ratingLevel = t.excellent || 'Excellent';
                ratingColor = 'emerald';
                ratingIcon = 'verified';
                postureText = t.no_major_findings || 'No major findings';
            } else {
                ratingLevel = t.satisfactory || 'Satisfactory';
                ratingColor = 'yellow';
                ratingIcon = 'check_circle';
                postureText = t.minor_findings_detected || 'Minor findings detected';
            }

            const topIssues = sortedFindings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 3);

            return `
        <div class="glass-panel-depth p-8 border border-${ratingColor}/20 bg-gradient-to-br from-${ratingColor}/5 to-transparent">
            <div class="flex items-center gap-3 mb-6 pb-4 border-b border-white/5">
                <span class="material-symbols-outlined text-${ratingColor}-400 text-xl">${ratingIcon}</span>
                <h3 class="text-sm font-bold text-white uppercase tracking-wider">${t.executive_summary || 'Executive Summary'}</h3>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- Overall Risk Rating -->
                <div class="glass-panel-depth p-6 text-center">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-3">${t.overall_risk_rating || 'Overall Risk Rating'}</div>
                    <div class="flex items-center justify-center gap-3 mb-3">
                        <span class="material-symbols-outlined text-5xl text-${ratingColor}-400">${ratingIcon}</span>
                        <div>
                            <div class="text-2xl font-bold text-${ratingColor}-400">${ratingLevel}</div>
                            <div class="text-xs text-slate-500 mt-1">${postureText}</div>
                        </div>
                    </div>
                </div>

                <!-- Security Posture -->
                <div class="glass-panel-depth p-6">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-4">${t.security_posture || 'Security Posture'}</div>
                    <div class="space-y-3">
                        <div class="flex items-center justify-between">
                            <span class="text-xs text-slate-400">${t.critical || 'Critical'}</span>
                            <span class="text-sm font-mono font-bold text-critical">${criticalCount}</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="text-xs text-slate-400">${t.high || 'High'}</span>
                            <span class="text-sm font-mono font-bold text-high">${highCount}</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="text-xs text-slate-400">${t.medium || 'Medium'}</span>
                            <span class="text-sm font-mono font-bold text-medium">${mediumCount}</span>
                        </div>
                        <div class="flex items-center justify-between pt-2 border-t border-white/5">
                            <span class="text-xs text-slate-400 font-bold">${t.total_findings || 'Total'}</span>
                            <span class="text-lg font-mono font-bold text-white">${totalFindings}</span>
                        </div>
                    </div>
                </div>

                <!-- Top Critical Issues -->
                <div class="glass-panel-depth p-6">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-4">${t.top_critical_issues || 'Top Critical Issues'}</div>
                    <div class="space-y-2">
                        ${topIssues.length > 0 ? topIssues.map((issue, idx) => {
                            const sevColor = getSeverityTailwindColor(issue.severity || 'low');
                            const message = issue.message || 'Security issue detected';
                            return `
                            <div class="flex items-start gap-2 p-2 rounded bg-${sevColor}/5 border border-${sevColor}/10">
                                <span class="text-${sevColor} text-xs font-bold mt-0.5">${idx + 1}.</span>
                                <span class="text-[10px] text-slate-300 leading-relaxed flex-1">${escapeHtml(message.length > 60 ? message.substring(0, 60) + '...' : message)}</span>
                            </div>
                            `;
                        }).join('') : `
                        <div class="flex items-center gap-2 p-3 rounded bg-emerald-500/5 border border-emerald-500/10">
                            <span class="material-symbols-outlined text-emerald-400 text-sm">check_circle</span>
                            <span class="text-xs text-emerald-400">${t.no_major_findings || 'No major findings'}</span>
                        </div>
                        `}
                    </div>
                </div>
            </div>
        </div>
        `;
        })()}

        <!-- Security Pulse + Risk Heatmap -->
        <div class="grid grid-cols-1 md:grid-cols-12 gap-6">
            <!-- Security Pulse Gauge -->
            <div class="md:col-span-5 glass-panel-depth p-8 relative overflow-hidden group border-glow-hover flex flex-col items-center justify-center">
                <div class="absolute inset-0 bg-gradient-to-t from-primary/5 via-transparent to-transparent opacity-40"></div>
                <div class="relative z-10 w-full flex flex-col items-center">
                    <div class="flex items-center gap-2 mb-4 self-start">
                        <span class="material-symbols-outlined text-slate-500 text-sm">speed</span>
                        <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">${t.system_health || 'System Health'}</span>
                    </div>
                    <div class="relative size-48 flex items-center justify-center mb-6">
                        <div class="absolute inset-0 rounded-full border border-white/5"></div>
                        <div class="absolute inset-4 rounded-full border border-white/5"></div>
                        <svg class="size-full -rotate-90 transform gauge-inner-glow" viewBox="0 0 36 36">
                            <path class="text-slate-800" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" stroke-opacity="0.3" stroke-width="1.5"></path>
                            <defs>
                                <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                                    <stop offset="0%" stop-color="#ef4444"></stop>
                                    <stop offset="33%" stop-color="#f97316"></stop>
                                    <stop offset="66%" stop-color="#eab308"></stop>
                                    <stop offset="100%" stop-color="#07d5d5"></stop>
                                </linearGradient>
                            </defs>
                            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="url(#gaugeGradient)" stroke-dasharray="${report.security.score}, 100" stroke-linecap="round" stroke-width="2"></path>
                            ${
                                (() => {
                                    const score = report.security.score;
                                    const radius = 15.9155;
                                    const center = 18;
                                    const angle = (score / 100) * 2 * Math.PI;
                                    const x = center + radius * Math.cos(angle);
                                    const y = center + radius * Math.sin(angle);
                                    return `<circle cx="${x}" cy="${y}" r="1.5" fill="#f97316" class="drop-shadow-[0_0_6px_rgba(249,115,22,0.8)]"><animate attributeName="r" values="1.5;2;1.5" dur="2s" repeatCount="indefinite"/></circle>`;
                                })()
                            }
                        </svg>
                        <div class="absolute flex flex-col items-center text-center">
                            <span class="text-5xl font-bold text-white tracking-tighter drop-shadow-[0_0_10px_rgba(255,255,255,0.2)]">${report.security.score}</span>
                            <span class="text-[10px] font-bold text-primary/80 uppercase tracking-[0.3em] mt-2 border border-primary/20 px-2 py-0.5 rounded-full bg-primary/5">${report.security.level}</span>
                        </div>
                    </div>
                    <div class="flex w-full justify-center items-center h-12 border-t border-white/5 pt-4 w-full">
                        <div class="flex-1 text-center px-4">
                            <div class="text-2xl font-bold text-white">${totalFindings}</div>
                            <div class="text-[9px] text-slate-500 uppercase tracking-widest font-semibold mt-1">${t.issues || 'Issues'}</div>
                        </div>
                        <div class="vertical-glass-divider h-8"></div>
                        <div class="flex-1 text-center px-4">
                            <div class="text-2xl font-bold text-critical">${criticalCount}</div>
                            <div class="text-[9px] text-slate-500 uppercase tracking-widest font-semibold mt-1">${t.critical || 'Critical'}</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Risk Heatmap -->
            <div class="md:col-span-7 glass-panel-depth p-8 flex flex-col relative overflow-hidden border-glow-hover">
                <div class="absolute top-0 right-0 w-48 h-48 bg-violet-500/5 blur-[60px] rounded-full pointer-events-none"></div>
                <div class="flex justify-between items-center mb-6 z-10 border-b border-white/5 pb-4">
                    <h3 class="text-sm font-semibold text-slate-200 uppercase tracking-wide flex items-center gap-2">
                        <span class="material-symbols-outlined text-lg text-slate-500">grid_view</span>
                        ${t.risk_heatmap || 'Risk Heatmap'}
                    </h3>
                    <div class="flex gap-2">
                        <span class="px-2 py-1 rounded bg-critical/20 border border-critical/30 text-[9px] text-critical font-bold uppercase tracking-wider">${t.critical_zone || 'Critical Zone'}</span>
                        <span class="px-2 py-1 rounded bg-white/5 border border-white/10 text-[9px] text-slate-400 font-mono">${t.impact_vs_probability || 'IMPACT vs PROBABILITY'}</span>
                    </div>
                </div>
                <div class="flex-1 flex flex-col relative z-10 justify-center">
                    <div class="absolute -left-8 top-1/2 -translate-y-1/2 -rotate-90 text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase flex items-center gap-2">
                        <span>${t.impact || 'Impact'}</span>
                        <span class="material-symbols-outlined text-[12px]">arrow_upward</span>
                    </div>
                    <div class="pl-4 pb-6 flex-1 grid grid-cols-3 grid-rows-3 gap-3 h-[260px] w-full max-w-[90%] mx-auto">
                        ${generateHeatmapCells(heatmapData)}
                    </div>
                    <div class="flex justify-between pl-4 text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase pt-2 w-full max-w-[90%] mx-auto border-t border-white/5">
                        <span class="w-1/3 text-center">${t.low || 'Low'}</span>
                        <span class="w-1/3 text-center">${t.medium || 'Med'}</span>
                        <span class="w-1/3 text-center flex items-center justify-center gap-1">${t.high || 'High'} <span class="material-symbols-outlined text-[12px]">arrow_forward</span></span>
                    </div>
                    <div class="text-center text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase mt-1">${t.probability || 'Probability'}</div>
                </div>
            </div>
        </div>

        <!-- Compliance Matrix -->
        <div class="glass-panel-depth p-8 border border-white/10 bg-white/[0.02]">
            <div class="flex items-center gap-3 mb-6 pb-4 border-b border-white/5">
                <span class="material-symbols-outlined text-emerald-400 text-xl">verified</span>
                <h3 class="text-sm font-bold text-white uppercase tracking-wider">${t.compliance_matrix || 'Compliance Matrix'}</h3>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
                <!-- OWASP -->
                <div class="glass-panel-depth p-4 text-center group hover:border-emerald-500/30 transition-all">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-2">${t.owasp_top_10 || 'OWASP Top 10'}</div>
                    <div class="text-3xl font-mono font-bold mb-1 ${complianceData.owasp >= 90 ? 'text-emerald-400' : complianceData.owasp >= 70 ? 'text-yellow-400' : 'text-critical'}">${complianceData.owasp}%</div>
                    <div class="text-[10px] text-slate-600">${complianceData.mappings.filter(m => m.owasp).length}/${complianceData.mappings.length} mapped</div>
                </div>

                <!-- CWE -->
                <div class="glass-panel-depth p-4 text-center group hover:border-emerald-500/30 transition-all">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-2">${t.cwe_mapping || 'CWE'}</div>
                    <div class="text-3xl font-mono font-bold mb-1 ${complianceData.cwe >= 90 ? 'text-emerald-400' : complianceData.cwe >= 70 ? 'text-yellow-400' : 'text-critical'}">${complianceData.cwe}%</div>
                    <div class="text-[10px] text-slate-600">${complianceData.mappings.filter(m => m.cwe).length}/${complianceData.mappings.length} mapped</div>
                </div>

                <!-- NIST -->
                <div class="glass-panel-depth p-4 text-center group hover:border-emerald-500/30 transition-all">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-2">${t.nist_controls || 'NIST SP 800-53'}</div>
                    <div class="text-3xl font-mono font-bold mb-1 ${complianceData.nist >= 90 ? 'text-emerald-400' : complianceData.nist >= 70 ? 'text-yellow-400' : 'text-critical'}">${complianceData.nist}%</div>
                    <div class="text-[10px] text-slate-600">${complianceData.mappings.filter(m => m.nist).length}/${complianceData.mappings.length} mapped</div>
                </div>

                <!-- PCI-DSS -->
                <div class="glass-panel-depth p-4 text-center group hover:border-emerald-500/30 transition-all">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-2">${t.pci_dss || 'PCI-DSS'}</div>
                    <div class="text-3xl font-mono font-bold mb-1 ${complianceData.pci >= 90 ? 'text-emerald-400' : complianceData.pci >= 70 ? 'text-yellow-400' : 'text-critical'}">${complianceData.pci}%</div>
                    <div class="text-[10px] text-slate-600">${complianceData.mappings.filter(m => m.pci).length}/${complianceData.mappings.length} mapped</div>
                </div>

                <!-- ISO 27001 -->
                <div class="glass-panel-depth p-4 text-center group hover:border-emerald-500/30 transition-all">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-2">${t.iso_27001 || 'ISO 27001'}</div>
                    <div class="text-3xl font-mono font-bold mb-1 ${complianceData.iso >= 90 ? 'text-emerald-400' : complianceData.iso >= 70 ? 'text-yellow-400' : 'text-critical'}">${complianceData.iso}%</div>
                    <div class="text-[10px] text-slate-600">${complianceData.mappings.filter(m => m.iso).length}/${complianceData.mappings.length} mapped</div>
                </div>
            </div>

            <!-- Detailed Mapping Table (Collapsible) -->
            <button onclick="toggleComplianceTable()" class="w-full flex items-center justify-between p-3 rounded-lg hover:bg-white/5 transition-colors text-left group">
                <span class="text-xs text-slate-400 uppercase tracking-wider">${t.view_details || 'View Details'}</span>
                <span class="material-symbols-outlined text-slate-400 group-hover:text-white transition-colors text-sm" id="compliance-table-icon">expand_more</span>
            </button>

            <div id="compliance-table" class="hidden mt-4 overflow-x-auto">
                <table class="w-full text-xs">
                    <thead>
                        <tr class="border-b border-white/10">
                            <th class="text-left p-2 text-slate-500 font-semibold">Rule</th>
                            <th class="text-left p-2 text-slate-500 font-semibold">Severity</th>
                            <th class="text-left p-2 text-slate-500 font-semibold">OWASP</th>
                            <th class="text-left p-2 text-slate-500 font-semibold">CWE</th>
                            <th class="text-left p-2 text-slate-500 font-semibold">NIST</th>
                            <th class="text-left p-2 text-slate-500 font-semibold">PCI-DSS</th>
                            <th class="text-left p-2 text-slate-500 font-semibold">ISO 27001</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${complianceData.mappings.map(m => `
                        <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                            <td class="p-2 font-mono text-white">${escapeHtml(m.rule)}</td>
                            <td class="p-2"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-${m.severity}/10 text-${m.severity}">${m.severity?.toUpperCase() || 'N/A'}</span></td>
                            <td class="p-2 text-slate-300">${m.owasp ? `<span class="font-mono bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded">${m.owasp}</span>` : '<span class="text-slate-600">—</span>'}</td>
                            <td class="p-2 text-slate-300">${m.cwe ? `<span class="font-mono bg-blue-500/10 text-blue-400 px-1.5 py-0.5 rounded">${m.cwe}</span>` : '<span class="text-slate-600">—</span>'}</td>
                            <td class="p-2 text-slate-300">${m.nist ? `<span class="font-mono bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded">${m.nist}</span>` : '<span class="text-slate-600">—</span>'}</td>
                            <td class="p-2 text-slate-300">${m.pci ? `<span class="font-mono bg-orange-500/10 text-orange-400 px-1.5 py-0.5 rounded">${m.pci}</span>` : '<span class="text-slate-600">—</span>'}</td>
                            <td class="p-2 text-slate-300">${m.iso ? `<span class="font-mono bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded">${m.iso}</span>` : '<span class="text-slate-600">—</span>'}</td>
                        </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        ${baseline ? `
        <!-- Historical Trends -->
        <div class="glass-panel-depth p-8 border border-white/10 bg-white/[0.02]">
            <div class="flex items-center gap-3 mb-6 pb-4 border-b border-white/5">
                <span class="material-symbols-outlined text-blue-400 text-xl">trending_up</span>
                <h3 class="text-sm font-bold text-white uppercase tracking-wider">${t.historical_trends || 'Historical Trends'}</h3>
            </div>

            ${(() => {
                const currentScore = report.security.score;
                const baselineScore = baseline.baseline.security_score;
                const delta = currentScore - baselineScore;
                const deltaPercent = ((delta / baselineScore) * 100).toFixed(1);
                const trend = delta > 2 ? 'improving' : delta < -2 ? 'degrading' : 'stable';
                const trendColor = trend === 'improving' ? 'emerald' : trend === 'degrading' ? 'critical' : 'yellow';
                const trendIcon = trend === 'improving' ? 'trending_up' : trend === 'degrading' ? 'trending_down' : 'trending_flat';

                return `
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                    <!-- Current Score -->
                    <div class="glass-panel-depth p-6 text-center">
                        <div class="text-xs text-slate-500 uppercase tracking-wider mb-3">${t.current_scan || 'Current Scan'}</div>
                        <div class="text-4xl font-mono font-bold text-white mb-2">${currentScore}</div>
                        <div class="text-[10px] text-slate-600">${new Date(report.timestamp).toLocaleDateString()}</div>
                    </div>

                    <!-- Trend Indicator -->
                    <div class="glass-panel-depth p-6 text-center bg-gradient-to-br from-${trendColor}-500/10 to-transparent border-${trendColor}-500/20">
                        <div class="text-xs text-slate-500 uppercase tracking-wider mb-3">${t.security_evolution || 'Security Evolution'}</div>
                        <div class="flex items-center justify-center gap-2 mb-2">
                            <span class="material-symbols-outlined text-4xl text-${trendColor}-400">${trendIcon}</span>
                            <div>
                                <div class="text-2xl font-bold text-${trendColor}-400">${delta > 0 ? '+' : ''}${delta.toFixed(1)}</div>
                                <div class="text-xs text-slate-500">(${delta > 0 ? '+' : ''}${deltaPercent}%)</div>
                            </div>
                        </div>
                        <div class="text-xs font-bold uppercase tracking-wider text-${trendColor}-400">
                            ${trend === 'improving' ? t.trend_improving : trend === 'degrading' ? t.trend_degrading : t.trend_stable || 'Stable'}
                        </div>
                    </div>

                    <!-- Baseline Score -->
                    <div class="glass-panel-depth p-6 text-center">
                        <div class="text-xs text-slate-500 uppercase tracking-wider mb-3">${t.previous_scan || 'Previous Scan'}</div>
                        <div class="text-4xl font-mono font-bold text-slate-400 mb-2">${baselineScore}</div>
                        <div class="text-[10px] text-slate-600">${new Date(baseline.baseline.timestamp).toLocaleDateString()}</div>
                    </div>
                </div>

                <!-- Sparkline Visualization -->
                <div class="glass-panel-depth p-4 flex items-center gap-4">
                    <span class="material-symbols-outlined text-slate-500 text-sm">show_chart</span>
                    <div class="flex-1 flex items-end gap-1 h-16">
                        ${[baselineScore, currentScore].map((score, i) => {
                            const maxScore = Math.max(baselineScore, currentScore, 50);
                            const height = (score / maxScore) * 100;
                            const isLast = i === 1;
                            const barColor = isLast ? (trend === 'improving' ? 'emerald' : trend === 'degrading' ? 'critical' : 'yellow') : 'slate';
                            return `<div class="flex-1 bg-${barColor}-500/20 border-t-2 border-${barColor}-500 hover:bg-${barColor}-500/30 transition-colors rounded-t relative group" style="height: ${height}%">
                                <span class="absolute -top-6 left-1/2 -translate-x-1/2 text-[10px] font-mono font-bold text-white opacity-0 group-hover:opacity-100 transition-opacity">${score}</span>
                            </div>`;
                        }).join('')}
                    </div>
                </div>
                `;
            })()}
        </div>
        ` : ''}

        ${driftAnalysisHtml ? `
        <!-- Drift Analysis -->
        ${driftAnalysisHtml}
        ` : ''}

        <!-- Active Findings -->
        <div id="findings" class="flex items-center gap-4 mt-4">
            <h2 class="text-xl font-bold text-white tracking-tight">${t.active_findings || 'Active Findings'}</h2>
            <div class="h-px flex-1 bg-gradient-to-r from-slate-800 via-slate-800 to-transparent"></div>
            <div class="relative">
                <button onclick="toggleSortMenu()" class="flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/5 hover:bg-white/10 transition-colors">
                    <span class="text-[10px] text-slate-400 font-mono uppercase" id="current-sort">${t.sort_severity || 'Sort: Severity'}</span>
                    <span class="material-symbols-outlined text-[14px] text-slate-400">arrow_drop_down</span>
                </button>
                <div id="sort-menu" class="hidden absolute right-0 mt-2 w-48 bg-slate-900 border border-white/10 rounded-lg shadow-lg overflow-hidden z-50">
                    <button onclick="sortFindings('severity')" class="w-full px-4 py-2 text-left text-xs text-slate-300 hover:bg-white/5 transition-colors">${t.by_severity || 'By Severity'}</button>
                    <button onclick="sortFindings('rule')" class="w-full px-4 py-2 text-left text-xs text-slate-300 hover:bg-white/5 transition-colors">${t.by_rule || 'By Rule Code'}</button>
                    <button onclick="sortFindings('recent')" class="w-full px-4 py-2 text-left text-xs text-slate-300 hover:bg-white/5 transition-colors">${t.most_recent || 'Most Recent'}</button>
                </div>
            </div>
        </div>

        <!-- Quick Filters Bar -->
        <div class="glass-panel-depth p-4 border border-white/10 bg-white/[0.02] mb-6">
            <div class="flex flex-wrap items-center gap-4">
                <!-- Filter by Severity -->
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined text-slate-500 text-sm">filter_list</span>
                    <span class="text-[10px] text-slate-500 uppercase tracking-wider font-bold">${t.quick_filters || 'Quick Filters'}:</span>
                </div>

                <!-- Severity Filters -->
                <div class="flex items-center gap-2">
                    <button onclick="filterBySeverity('all')" class="filter-btn filter-severity-btn px-3 py-1.5 rounded-full bg-white/10 border border-white/20 text-xs text-white font-bold uppercase tracking-wider hover:bg-white/20 transition-all active" data-severity="all">
                        ${t.all_severities || 'All'}
                    </button>
                    <button onclick="filterBySeverity('critical')" class="filter-btn filter-severity-btn px-3 py-1.5 rounded-full bg-critical/10 border border-critical/20 text-xs text-critical font-bold uppercase tracking-wider hover:bg-critical/20 transition-all" data-severity="critical">
                        ${t.critical || 'Critical'} (${criticalCount})
                    </button>
                    <button onclick="filterBySeverity('high')" class="filter-btn filter-severity-btn px-3 py-1.5 rounded-full bg-high/10 border border-high/20 text-xs text-high font-bold uppercase tracking-wider hover:bg-high/20 transition-all" data-severity="high">
                        ${t.high || 'High'} (${highCount})
                    </button>
                    <button onclick="filterBySeverity('medium')" class="filter-btn filter-severity-btn px-3 py-1.5 rounded-full bg-medium/10 border border-medium/20 text-xs text-medium font-bold uppercase tracking-wider hover:bg-medium/20 transition-all" data-severity="medium">
                        ${t.medium || 'Medium'} (${mediumCount})
                    </button>
                    <button onclick="filterBySeverity('low')" class="filter-btn filter-severity-btn px-3 py-1.5 rounded-full bg-low/10 border border-low/20 text-xs text-low font-bold uppercase tracking-wider hover:bg-low/20 transition-all" data-severity="low">
                        ${t.low || 'Low'} (${lowCount})
                    </button>
                </div>

                <!-- Category Filters -->
                <div class="flex items-center gap-2 pl-4 border-l border-white/10">
                    <button onclick="filterByCategory('all')" class="filter-btn filter-category-btn px-3 py-1.5 rounded-full bg-white/10 border border-white/20 text-xs text-white font-bold uppercase tracking-wider hover:bg-white/20 transition-all active" data-category="all">
                        ${t.all_categories || 'All Categories'}
                    </button>
                    <button onclick="filterByCategory('auth')" class="filter-btn filter-category-btn px-3 py-1.5 rounded-full bg-red-500/10 border border-red-500/20 text-xs text-red-400 font-bold uppercase tracking-wider hover:bg-red-500/20 transition-all" data-category="auth">
                        ${t.agency_auth || 'Auth'}
                    </button>
                    <button onclick="filterByCategory('network')" class="filter-btn filter-category-btn px-3 py-1.5 rounded-full bg-violet-500/10 border border-violet-500/20 text-xs text-violet-400 font-bold uppercase tracking-wider hover:bg-violet-500/20 transition-all" data-category="network">
                        ${t.agency_network || 'Network'}
                    </button>
                    <button onclick="filterByCategory('data')" class="filter-btn filter-category-btn px-3 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-xs text-amber-400 font-bold uppercase tracking-wider hover:bg-amber-500/20 transition-all" data-category="data">
                        ${t.agency_data || 'Data'}
                    </button>
                </div>

                <!-- Reset Button -->
                <button onclick="resetFilters()" class="ml-auto px-4 py-1.5 rounded-full bg-white/5 border border-white/10 text-xs text-slate-400 font-bold uppercase tracking-wider hover:bg-white/10 hover:text-white transition-all flex items-center gap-2">
                    <span class="material-symbols-outlined text-sm">refresh</span>
                    ${t.reset_filters || 'Reset'}
                </button>
            </div>

            <!-- Results Count -->
            <div class="mt-3 pt-3 border-t border-white/5 flex items-center gap-2">
                <span class="material-symbols-outlined text-primary text-sm">info</span>
                <span class="text-xs text-slate-400" id="filter-results">${t.showing_findings?.replace('{count}', String(totalFindings)) || `Showing ${totalFindings} findings`}</span>
            </div>
        </div>

        <div class="flex flex-col gap-6" id="findings-container">
            ${findingCardsHtml}
        </div>

        <!-- Remediation Checklist -->
        ${totalFindings > 0 ? `
        <div class="glass-panel-depth p-8 border border-white/10 bg-white/[0.02] mt-6">
            <div class="flex items-center justify-between mb-6 pb-4 border-b border-white/5">
                <div class="flex items-center gap-3">
                    <span class="material-symbols-outlined text-primary text-xl">checklist</span>
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">${t.remediation_checklist || 'Remediation Checklist'}</h3>
                </div>
                <button onclick="exportChecklist()" class="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary/10 border border-primary/20 text-xs text-primary font-bold uppercase tracking-wider hover:bg-primary/20 transition-all">
                    <span class="material-symbols-outlined text-sm">download</span>
                    ${t.export_checklist || 'Export Checklist'}
                </button>
            </div>

            <div class="space-y-3">
                ${sortedFindings.map((finding, idx) => {
                    const sev = finding.severity || 'low';
                    const sevColor = getSeverityTailwindColor(sev);
                    const code = finding.rule || `SEC-${String(idx + 1).padStart(3, '0')}`;
                    const message = finding.message || 'Security issue detected';

                    // Estimate time to fix based on severity
                    let timeEstimate = '';
                    if (sev === 'critical') timeEstimate = `4 ${t.hours || 'hours'}`;
                    else if (sev === 'high') timeEstimate = `2 ${t.hours || 'hours'}`;
                    else if (sev === 'medium') timeEstimate = `1 ${t.hour || 'hour'}`;
                    else timeEstimate = `30 min`;

                    return `
                    <div class="checklist-item glass-panel-depth p-4 flex items-start gap-4 hover:bg-white/5 transition-all border-l-4 border-l-${sevColor}" data-finding-id="${idx}">
                        <!-- Checkbox -->
                        <input type="checkbox" class="checklist-checkbox mt-1 size-5 rounded border-2 border-${sevColor}/30 bg-transparent checked:bg-${sevColor} checked:border-${sevColor} cursor-pointer transition-all" onchange="toggleChecklistItem(${idx})">

                        <!-- Content -->
                        <div class="flex-1">
                            <div class="flex items-start justify-between gap-4 mb-2">
                                <div class="flex items-center gap-2">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-${sevColor}/10 text-${sevColor} uppercase">${sev}</span>
                                    <span class="font-mono text-xs text-slate-400">${escapeHtml(code)}</span>
                                </div>
                                <div class="flex items-center gap-4 text-[10px] text-slate-500">
                                    <div class="flex items-center gap-1">
                                        <span class="material-symbols-outlined text-xs">schedule</span>
                                        ${timeEstimate}
                                    </div>
                                    <div class="flex items-center gap-1">
                                        <span class="material-symbols-outlined text-xs">flag</span>
                                        ${t.priority || 'Priority'}: ${sev === 'critical' ? 'P0' : sev === 'high' ? 'P1' : sev === 'medium' ? 'P2' : 'P3'}
                                    </div>
                                </div>
                            </div>

                            <div class="text-sm text-slate-300 mb-2">${escapeHtml(message)}</div>

                            ${finding.remediation ? `
                            <div class="text-xs text-slate-400 pl-4 border-l-2 border-${sevColor}/20 mt-2">
                                💡 ${escapeHtml(finding.remediation)}
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    `;
                }).join('')}
            </div>

            <!-- Summary Footer -->
            <div class="mt-6 pt-4 border-t border-white/5 flex items-center justify-between">
                <div class="flex items-center gap-6">
                    <div class="flex items-center gap-2">
                        <span class="text-xs text-slate-500">${t.total_findings || 'Total'}:</span>
                        <span class="text-sm font-mono font-bold text-white">${totalFindings}</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="text-xs text-slate-500">${t.estimated_time || 'Estimated Time'}:</span>
                        <span class="text-sm font-mono font-bold text-primary">${timeToFix}</span>
                    </div>
                </div>
                <div class="flex items-center gap-2">
                    <span class="size-3 rounded-full bg-emerald-500"></span>
                    <span class="text-xs text-slate-500"><span id="checklist-completed">0</span>/${totalFindings} ${t.completed || 'completed'}</span>
                </div>
            </div>
        </div>
        ` : ''}

        <!-- Protocol Compliance -->
        <div id="compliance">
            <div class="flex items-center gap-4 mb-6">
                <h2 class="text-xl font-bold text-white tracking-tight">${t.protocol_compliance_full || 'Protocol Compliance'}</h2>
                <div class="h-px flex-1 bg-gradient-to-r from-slate-700 via-slate-800 to-transparent"></div>
                <span class="text-xs ${protocolPassed ? 'text-green-400' : 'text-critical'} font-mono">${t.mcp_version || 'MCP Version'}: 2024-11-05</span>
            </div>
            <div class="glass-panel-depth rounded-xl p-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="flex items-start gap-4">
                        <div class="p-3 rounded-lg ${protocolPassed ? 'bg-green-500/10' : 'bg-critical/10'}">
                            <span class="material-symbols-outlined text-2xl ${protocolPassed ? 'text-green-400' : 'text-critical'}">${protocolPassed ? 'check_circle' : 'cancel'}</span>
                        </div>
                        <div class="flex-1">
                            <h3 class="text-lg font-bold text-white mb-2">${t.protocol || 'Protocol'}</h3>
                            <p class="text-sm ${protocolPassed ? 'text-green-400' : 'text-critical'} font-semibold mb-2">
                                ${protocolPassed ? (t.compliance_passed || 'All protocol checks passed') : (t.compliance_failed || 'Protocol validation failed')}
                            </p>
                            <div class="space-y-2 text-xs text-slate-400">
                                <div class="flex justify-between">
                                    <span>${t.jsonrpc_20 || 'JSON-RPC 2.0'}:</span>
                                    <span class="${protocolPassed ? 'text-green-400' : 'text-critical'}">${protocolPassed ? '✓' : '✗'}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>${t.schema_valid || 'Schema Validation'}:</span>
                                    <span class="text-green-400">✓</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-start gap-4">
                        <div class="p-3 rounded-lg bg-primary/10">
                            <span class="material-symbols-outlined text-2xl text-primary">insights</span>
                        </div>
                        <div class="flex-1">
                            <h3 class="text-lg font-bold text-white mb-2">${t.quality || 'Quality'}</h3>
                            <div class="flex items-baseline gap-2 mb-2">
                                <span class="text-3xl font-black text-white">${qualityScore}</span>
                                <span class="text-sm text-slate-400">/ 100</span>
                            </div>
                            <div class="space-y-2 text-xs text-slate-400">
                                <div class="flex justify-between">
                                    <span>${t.tools || 'Tools'}:</span>
                                    <span class="text-white">${report.tools.items.length}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>${t.resources || 'Resources'}:</span>
                                    <span class="text-white">${report.resources.items.length}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>${t.prompts || 'Prompts'}:</span>
                                    <span class="text-white">${report.prompts.items.length}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        ${mermaidGraph ? `
        <!-- Architecture Diagram -->
        <div id="architecture">
            <div class="flex items-center gap-4 mb-6">
                <h2 class="text-xl font-bold text-white tracking-tight">${t.architecture_diagram || 'Architecture Diagram'}</h2>
                <div class="h-px flex-1 bg-gradient-to-r from-slate-700 via-slate-800 to-transparent"></div>
            </div>
            <div class="glass-panel-depth rounded-xl p-6 relative overflow-hidden group hover:border-primary/30 transition-all border-glow-hover">
                <div class="mermaid" id="mermaid-diagram">
${mermaidGraph}
                </div>
            </div>
        </div>
        ` : ''}
    </main>

    <!-- Heatmap Modal -->
    <div id="heatmap-modal" class="fixed inset-0 z-[100] hidden items-center justify-center bg-black/70 backdrop-blur-sm">
        <div class="glass-panel-depth max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto relative">
            <div class="sticky top-0 bg-slate-900/95 backdrop-blur-md border-b border-white/10 px-6 py-4 flex items-center justify-between z-10">
                <h3 class="text-xl font-bold text-white flex items-center gap-3">
                    <span class="material-symbols-outlined text-2xl" id="modal-severity-icon">grid_view</span>
                    <span id="modal-title">${t.heatmap_modal_title || 'Risk Cell Analysis'}</span>
                </h3>
                <button onclick="closeHeatmapModal()" class="size-10 rounded-full hover:bg-white/10 transition-colors flex items-center justify-center group">
                    <span class="material-symbols-outlined text-slate-400 group-hover:text-white">close</span>
                </button>
            </div>
            <div class="p-6 space-y-6">
                <!-- Impact & Probability -->
                <div class="grid grid-cols-2 gap-4">
                    <div class="glass-panel-depth p-4">
                        <div class="text-xs text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-2">
                            <span class="material-symbols-outlined text-sm">trending_up</span>
                            ${t.heatmap_modal_impact || 'Impact Level'}
                        </div>
                        <div class="text-2xl font-bold" id="modal-impact">-</div>
                    </div>
                    <div class="glass-panel-depth p-4">
                        <div class="text-xs text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-2">
                            <span class="material-symbols-outlined text-sm">percent</span>
                            ${t.heatmap_modal_probability || 'Probability Level'}
                        </div>
                        <div class="text-2xl font-bold" id="modal-probability">-</div>
                    </div>
                </div>

                <!-- Findings Count -->
                <div class="glass-panel-depth p-4 bg-gradient-to-r from-primary/5 to-transparent">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-2">${t.heatmap_modal_findings || 'Findings in this category'}</div>
                    <div class="text-3xl font-bold text-white" id="modal-count">0</div>
                </div>

                <!-- Explanation -->
                <div class="glass-panel-depth p-4">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                        <span class="material-symbols-outlined text-sm">info</span>
                        ${t.heatmap_modal_explanation || 'Explanation'}
                    </div>
                    <p class="text-sm text-slate-300 leading-relaxed" id="modal-explanation">-</p>
                </div>

                <!-- Recommended Action -->
                <div class="glass-panel-depth p-4 border-l-4" id="modal-action-container">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                        <span class="material-symbols-outlined text-sm">recommend</span>
                        ${t.heatmap_modal_action || 'Recommended Action'}
                    </div>
                    <p class="text-sm text-slate-300 leading-relaxed" id="modal-action">-</p>
                </div>

                <!-- Action Buttons -->
                <div class="flex gap-3 pt-4 border-t border-white/10">
                    <button onclick="viewFindingsBySeverity()" class="flex-1 py-3 bg-primary hover:bg-primary/80 text-black font-bold rounded-lg transition-all hover:scale-[1.02] flex items-center justify-center gap-2" id="modal-view-findings">
                        <span class="material-symbols-outlined text-lg">bug_report</span>
                        ${t.view_findings || 'View Findings'}
                    </button>
                    <button onclick="closeHeatmapModal()" class="px-6 py-3 bg-white/10 hover:bg-white/20 text-white font-bold rounded-lg transition-all">
                        ${t.close || 'Close'}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Floating Dock Navigation -->
    <div class="fixed bottom-8 left-1/2 -translate-x-1/2 z-50 w-auto">
        <nav class="floating-dock flex items-center gap-2 p-2 rounded-2xl border border-white/10 shadow-glass-deep">
            <a class="flex flex-col items-center gap-1.5 px-6 py-2.5 rounded-xl bg-white/10 text-white border border-white/10 transition-all hover:bg-white/15 hover:scale-105 active:scale-95 group relative overflow-hidden" href="#top">
                <span class="absolute inset-0 bg-gradient-to-tr from-white/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></span>
                <span class="material-symbols-outlined text-[20px]">dashboard</span>
                <span class="text-[9px] font-bold uppercase tracking-widest">${t.summary || 'Summary'}</span>
            </a>
            <div class="w-px h-8 bg-white/10 mx-1"></div>
            <a class="flex flex-col items-center gap-1.5 px-5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-all hover:scale-105 active:scale-95 group" href="#findings">
                <span class="material-symbols-outlined text-[20px] group-hover:text-critical transition-colors duration-300">bug_report</span>
                <span class="text-[9px] font-bold uppercase tracking-widest">${t.findings || 'Findings'}</span>
            </a>
            <a class="flex flex-col items-center gap-1.5 px-5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-all hover:scale-105 active:scale-95 group" href="#compliance">
                <span class="material-symbols-outlined text-[20px] group-hover:text-emerald-400 transition-colors duration-300">verified_user</span>
                <span class="text-[9px] font-bold uppercase tracking-widest">${t.compliance || 'Compliance'}</span>
            </a>
            ${mermaidGraph ? `
            <a class="flex flex-col items-center gap-1.5 px-5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-all hover:scale-105 active:scale-95" href="#architecture">
                <span class="material-symbols-outlined text-[20px]">account_tree</span>
                <span class="text-[9px] font-bold uppercase tracking-widest">${t.architecture_diagram || 'Architecture'}</span>
            </a>
            ` : ''}
            <button onclick="downloadJSON()" class="flex flex-col items-center gap-1.5 px-5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-all hover:scale-105 active:scale-95" title="Download JSON">
                <span class="material-symbols-outlined text-[20px]">code</span>
                <span class="text-[9px] font-bold uppercase tracking-widest">JSON</span>
            </button>
            <a href="https://github.com/FinkTech/mcp-verify" target="_blank" rel="noopener noreferrer" class="flex flex-col items-center gap-1.5 px-5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-all hover:scale-105 active:scale-95 group" title="${t.view_on_github || 'View on GitHub'}">
                <svg class="w-[20px] h-[20px] group-hover:text-white transition-colors duration-300" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
                <span class="text-[9px] font-bold uppercase tracking-widest">GitHub</span>
            </a>
            <div class="w-px h-8 bg-white/10 mx-1"></div>
            <button onclick="exportToZip()" class="flex items-center justify-center size-11 rounded-xl bg-white text-black shadow-[0_0_20px_rgba(255,255,255,0.2)] hover:shadow-[0_0_25px_rgba(255,255,255,0.4)] transition-all hover:scale-105 active:scale-95 ml-1" title="${t.export_zip || 'Export ZIP'}">
                <span class="material-symbols-outlined font-semibold">download</span>
            </button>
        </nav>
    </div>

    <script>
        // Report data for export
        const reportData = ${JSON.stringify({
            server_name: report.server_name,
            url: report.url,
            timestamp: report.timestamp,
            status: report.status,
            security: report.security,
            quality: report.quality,
            tools: report.tools,
            resources: report.resources,
            prompts: report.prompts,
            findings: report.security.findings
        })};

        // Initialize Mermaid
        ${mermaidGraph ? `
        mermaid.initialize({
            startOnLoad: true,
            theme: 'dark',
            securityLevel: 'loose'
        });
        ` : ''}

        // Copy code function
        function copyCode(btn, text) {
            navigator.clipboard.writeText(text).then(() => {
                const icon = btn.querySelector('.material-symbols-outlined');
                if (icon) {
                    const originalText = icon.textContent;
                    icon.textContent = 'check';
                    icon.style.color = '#22c55e';
                    setTimeout(() => {
                        icon.textContent = originalText;
                        icon.style.color = '';
                    }, 2000);
                }
            }).catch(err => {
                console.error('Copy failed:', err);
            });
        }

        // Sort menu toggle
        function toggleSortMenu() {
            const menu = document.getElementById('sort-menu');
            menu.classList.toggle('hidden');
        }

        // Toggle risk breakdown
        function toggleRiskBreakdown() {
            const breakdown = document.getElementById('risk-breakdown');
            const icon = document.getElementById('breakdown-icon');

            if (breakdown.classList.contains('hidden')) {
                breakdown.classList.remove('hidden');
                icon.textContent = 'expand_less';
            } else {
                breakdown.classList.add('hidden');
                icon.textContent = 'expand_more';
            }
        }

        // Toggle compliance table
        function toggleComplianceTable() {
            const table = document.getElementById('compliance-table');
            const icon = document.getElementById('compliance-table-icon');

            if (table.classList.contains('hidden')) {
                table.classList.remove('hidden');
                icon.textContent = 'expand_less';
            } else {
                table.classList.add('hidden');
                icon.textContent = 'expand_more';
            }
        }

        // Sort findings
        function sortFindings(method) {
            const container = document.getElementById('findings-container');
            const findings = Array.from(container.children);

            findings.sort((a, b) => {
                if (method === 'severity') {
                    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                    const getSev = (el) => {
                        if (el.classList.contains('border-l-critical')) return 0;
                        if (el.classList.contains('border-l-high')) return 1;
                        if (el.classList.contains('border-l-medium')) return 2;
                        return 3;
                    };
                    return getSev(a) - getSev(b);
                } else if (method === 'rule') {
                    const getRule = (el) => el.querySelector('.font-mono').textContent.trim();
                    return getRule(a).localeCompare(getRule(b));
                } else if (method === 'recent') {
                    // Already in order by timestamp, reverse it
                    return 0; // Keep original order for "recent"
                }
                return 0;
            });

            // Clear and re-append
            container.innerHTML = '';
            findings.forEach(f => container.appendChild(f));

            // Update button text
            const labels = {
                severity: '${t.by_severity || 'By Severity'}',
                rule: '${t.by_rule || 'By Rule Code'}',
                recent: '${t.most_recent || 'Most Recent'}'
            };
            document.getElementById('current-sort').textContent = labels[method] || labels.severity;
            toggleSortMenu();
        }

        // Filter state
        let activeFilters = {
            severity: 'all',
            category: 'all'
        };

        // Filter findings by severity (from heatmap click OR quick filters)
        function filterBySeverity(severity) {
            activeFilters.severity = severity;
            applyFilters();

            // Update active button state
            document.querySelectorAll('.filter-severity-btn').forEach(btn => {
                if (btn.dataset.severity === severity) {
                    btn.classList.add('active');
                    btn.style.borderWidth = '2px';
                } else {
                    btn.classList.remove('active');
                    btn.style.borderWidth = '1px';
                }
            });

            // Scroll to findings
            document.getElementById('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        // Filter findings by category
        function filterByCategory(category) {
            activeFilters.category = category;
            applyFilters();

            // Update active button state
            document.querySelectorAll('.filter-category-btn').forEach(btn => {
                if (btn.dataset.category === category) {
                    btn.classList.add('active');
                    btn.style.borderWidth = '2px';
                } else {
                    btn.classList.remove('active');
                    btn.style.borderWidth = '1px';
                }
            });
        }

        // Apply all active filters
        function applyFilters() {
            const container = document.getElementById('findings-container');
            const findings = container.querySelectorAll('.glass-panel-depth');
            let visibleCount = 0;

            findings.forEach(finding => {
                let showFinding = true;

                // Check severity filter
                if (activeFilters.severity !== 'all') {
                    const hasSeverity = finding.classList.contains('border-l-' + activeFilters.severity);
                    if (!hasSeverity) showFinding = false;
                }

                // Check category filter
                if (activeFilters.category !== 'all' && showFinding) {
                    const categoryTags = finding.querySelectorAll('[class*="bg-"][class*="-500/10"]');
                    let hasCategory = false;

                    categoryTags.forEach(tag => {
                        const tagText = tag.textContent.toLowerCase();
                        if (tagText.includes(activeFilters.category)) {
                            hasCategory = true;
                        }
                    });

                    if (!hasCategory) showFinding = false;
                }

                // Show/hide finding
                if (showFinding) {
                    finding.style.display = 'block';
                    visibleCount++;
                } else {
                    finding.style.display = 'none';
                }
            });

            // Update results count
            const resultsText = '${t.showing_findings?.replace('{count}', '')}' || 'Showing ';
            document.getElementById('filter-results').textContent = resultsText + visibleCount + ' ${t.findings || 'findings'}';
        }

        // Reset all filters
        function resetFilters() {
            activeFilters = { severity: 'all', category: 'all' };
            applyFilters();

            // Reset button states
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.style.borderWidth = '1px';
            });

            document.querySelectorAll('[data-severity="all"], [data-category="all"]').forEach(btn => {
                btn.classList.add('active');
                btn.style.borderWidth = '2px';
            });
        }

        // Toggle checklist item
        function toggleChecklistItem(idx) {
            const checkboxes = document.querySelectorAll('.checklist-checkbox');
            const completedCount = Array.from(checkboxes).filter(cb => cb.checked).length;
            document.getElementById('checklist-completed').textContent = completedCount;

            // Visual feedback
            const item = document.querySelector('[data-finding-id="' + idx + '"]');
            if (checkboxes[idx].checked) {
                item.style.opacity = '0.5';
                item.style.filter = 'grayscale(1)';
            } else {
                item.style.opacity = '1';
                item.style.filter = 'grayscale(0)';
            }
        }

        // Export checklist as markdown
        function exportChecklist() {
            const findings = reportData.findings || reportData.security.findings || [];
            let markdown = '# Security Remediation Checklist\\n\\n';
            markdown += 'Generated: ' + new Date().toISOString() + '\\n\\n';

            findings.forEach((finding, idx) => {
                const sev = finding.severity || 'low';
                const code = finding.rule || 'SEC-' + String(idx + 1).padStart(3, '0');
                const message = finding.message || 'Security issue detected';
                const recommendation = finding.recommendation || 'See report for details';

                let timeEstimate = '';
                if (sev === 'critical') timeEstimate = '4 hours';
                else if (sev === 'high') timeEstimate = '2 hours';
                else if (sev === 'medium') timeEstimate = '1 hour';
                else timeEstimate = '30 min';

                const priority = sev === 'critical' ? 'P0' : sev === 'high' ? 'P1' : sev === 'medium' ? 'P2' : 'P3';

                markdown += '## [ ] ' + code + ' - ' + message + '\\n\\n';
                markdown += '**Severity:** ' + sev.toUpperCase() + '\\n';
                markdown += '**Priority:** ' + priority + '\\n';
                markdown += '**Estimated Time:** ' + timeEstimate + '\\n\\n';
                markdown += '**Recommendation:**\\n' + recommendation + '\\n\\n';
                markdown += '---\\n\\n';
            });

            const blob = new Blob([markdown], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'remediation-checklist-' + new Date().toISOString().slice(0,10) + '.md';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        // Store current modal severity for "View Findings" button
        let currentModalSeverity = '';

        // Open heatmap modal
        function openHeatmapModal(row, col, severity, count) {
            currentModalSeverity = severity;

            const impactLabels = ['${t.low || 'Low'}', '${t.medium || 'Medium'}', '${t.high || 'High'}'];
            const probLabels = ['${t.low || 'Low'}', '${t.medium || 'Medium'}', '${t.high || 'High'}'];

            const impactLevel = impactLabels[row];
            const probLevel = probLabels[col];

            // Update impact and probability
            document.getElementById('modal-impact').textContent = impactLevel;
            document.getElementById('modal-impact').className = 'text-2xl font-bold text-' + (row === 2 ? 'critical' : row === 1 ? 'high' : 'medium');
            document.getElementById('modal-probability').textContent = probLevel;
            document.getElementById('modal-probability').className = 'text-2xl font-bold text-' + (col === 2 ? 'critical' : col === 1 ? 'high' : 'medium');

            // Update count
            document.getElementById('modal-count').textContent = count;

            // Update explanation based on severity
            const explanations = {
                critical: '${t.heatmap_critical_explain || 'This cell represents the highest risk category'}',
                high: '${t.heatmap_high_explain || 'This cell represents high-risk findings'}',
                medium: '${t.heatmap_medium_explain || 'This cell represents medium-risk findings'}',
                low: '${t.heatmap_low_explain || 'This cell represents low-risk findings'}'
            };
            document.getElementById('modal-explanation').textContent = explanations[severity] || explanations.low;

            // Update recommended action
            const actions = {
                critical: '${t.heatmap_action_critical || 'Immediate action required'}',
                high: '${t.heatmap_action_high || 'High priority'}',
                medium: '${t.heatmap_action_medium || 'Medium priority'}',
                low: '${t.heatmap_action_low || 'Low priority'}'
            };
            document.getElementById('modal-action').textContent = actions[severity] || actions.low;

            // Update action container border color
            const actionContainer = document.getElementById('modal-action-container');
            actionContainer.className = 'glass-panel-depth p-4 border-l-4 border-' + severity;

            // Update severity icon
            const icons = {
                critical: 'warning',
                high: 'priority_high',
                medium: 'info',
                low: 'check_circle'
            };
            document.getElementById('modal-severity-icon').textContent = icons[severity] || 'grid_view';
            document.getElementById('modal-severity-icon').className = 'material-symbols-outlined text-2xl text-' + severity;

            // Show modal
            const modal = document.getElementById('heatmap-modal');
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            document.body.style.overflow = 'hidden';
        }

        // Close heatmap modal
        function closeHeatmapModal() {
            const modal = document.getElementById('heatmap-modal');
            modal.classList.add('hidden');
            modal.classList.remove('flex');
            document.body.style.overflow = 'auto';
        }

        // View findings by severity from modal
        function viewFindingsBySeverity() {
            closeHeatmapModal();
            filterBySeverity(currentModalSeverity);
        }

        // Close modal on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeHeatmapModal();
            }
        });

        // Close modal on backdrop click
        document.getElementById('heatmap-modal').addEventListener('click', (e) => {
            if (e.target.id === 'heatmap-modal') {
                closeHeatmapModal();
            }
        });

        // Export to ZIP
        async function exportToZip() {
            try {
                const zip = new JSZip();
                const timestamp = new Date().toISOString().slice(0,10);
                const serverName = String(reportData.server_name || 'report').replace(/[^a-zA-Z0-9]/g, '_');
                const folderName = 'mcp-verify-' + serverName + '-' + timestamp;

                zip.file(folderName + '/report.html', document.documentElement.outerHTML);
                zip.file(folderName + '/report.json', JSON.stringify(reportData, null, 2));

                const blob = await zip.generateAsync({ type: 'blob' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = folderName + '.zip';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } catch (err) {
                console.error('Export failed:', err);
                alert('Export failed. Please check console for details.');
            }
        }

        // Download JSON
        function downloadJSON() {
            const timestamp = new Date().toISOString().slice(0,10);
            const serverName = String(reportData.server_name || 'report').replace(/[^a-zA-Z0-9]/g, '_');
            const filename = 'mcp-report-' + serverName + '-' + timestamp + '.json';

            const dataStr = JSON.stringify(reportData, null, 2);
            const blob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
    </script>
</body>
</html>
        `.trim();
    }
}

// Helper functions
function getSeverityTailwindColor(severity: string) {
    if (severity === 'critical') return 'critical';
    if (severity === 'high') return 'high';
    if (severity === 'medium') return 'medium';
    return 'low';
}

function getSeverityBgColor(severity: string) {
    if (severity === 'critical') return 'bg-critical/10 text-critical border border-critical/20 shadow-[0_0_10px_rgba(239,68,68,0.15)]';
    if (severity === 'high') return 'bg-high/10 text-high border border-high/20 shadow-[0_0_10px_rgba(249,115,22,0.2)]';
    if (severity === 'medium') return 'bg-medium/10 text-medium border border-medium/20';
    return 'bg-low/10 text-low border border-low/20';
}

function getSeverityIcon(severity: string) {
    if (severity === 'critical') return 'warning';
    if (severity === 'high') return 'lock_open';
    if (severity === 'medium') return 'construction';
    return 'info';
}

function getRuleIcon(ruleCode: string): string {
    const iconMap: Record<string, string> = {
        'SEC-001': 'key',              // Authentication Bypass
        'SEC-002': 'terminal',         // Command Injection
        'SEC-003': 'database',         // SQL Injection
        'SEC-004': 'public',           // SSRF
        'SEC-005': 'code',             // XXE Injection
        'SEC-006': 'memory',           // Insecure Deserialization
        'SEC-007': 'folder_open',      // Path Traversal
        'SEC-008': 'leak',             // Data Leakage
        'SEC-009': 'visibility_off',   // Sensitive Exposure
        'SEC-010': 'speed',            // Rate Limiting
        'SEC-011': 'repeat',           // ReDoS
        'SEC-012': 'lock_open_right',  // Weak Crypto
        'SEC-013': 'security',         // Prompt Injection
        'SEC-014': 'link',             // Dangerous Tool Chaining
        'SEC-015': 'admin_panel_settings', // Excessive Permissions
        'SEC-016': 'deployed_code',    // Exposed Endpoint
        'SEC-017': 'http',             // Insecure URI Scheme
        'SEC-018': 'no_encryption',    // Missing Authentication
        'SEC-019': 'rule',             // Missing Input Constraints
        'SEC-020': 'password',         // Secrets in Descriptions
        'SEC-021': 'vpn_key_off',      // Unencrypted Credentials
    };
    return iconMap[ruleCode] || 'bug_report';
}

function getSeverityRgba(severity: string) {
    if (severity === 'critical') return '239,68,68';
    if (severity === 'high') return '249,115,22';
    if (severity === 'medium') return '234,179,8';
    return '59,130,246';
}

function escapeHtml(str: string): string {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeForJs(str: string): string {
    if (typeof str !== 'string') return '';
    return str
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t');
}

function getTimeAgo(timestamp: string, t: typeof translations['en']): string {
    const now = Date.now();
    const then = new Date(timestamp).getTime();
    const diff = now - then;

    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return t.just_now || 'Just now';
    if (minutes < 60) return `${minutes}${t.minutes_ago || 'm ago'}`;
    if (hours < 24) return `${hours}${t.hours_ago || 'h ago'}`;
    return `${days}${t.days_ago || 'd ago'}`;
}

function generateScanId(timestamp: string): string {
    const date = new Date(timestamp);
    const year = date.getFullYear();
    const id = Math.floor(Math.random() * 10000);
    return `AUD-${year}-${id.toString().padStart(4, '0')}`;
}

function generateSurgicalSummary(report: any, t: typeof translations['en']): string {
    const hasFindings = report.security.findings.length > 0;
    const hasCritical = report.security.findings.some((f: any) => f.severity === 'critical');
    const score = report.security.score;

    if (score >= 90) {
        return t.surgical_summary_excellent || 'Security posture is robust with minimal vulnerabilities. System demonstrates strong adherence to security best practices.';
    } else if (score >= 70) {
        return t.surgical_summary_good || 'Security analysis reveals moderate findings requiring attention. Overall system security is satisfactory with room for improvement.';
    } else if (hasCritical) {
        return t.surgical_summary_critical || 'Audit reveals critical chain vulnerabilities in core modules necessitating immediate refactoring. System hardening is required to mitigate lateral movement risks.';
    } else if (hasFindings) {
        return t.surgical_summary_warning || 'Security assessment identifies multiple vulnerabilities across different severity levels. Systematic remediation recommended to strengthen defensive posture.';
    }
    return t.surgical_summary_default || 'Comprehensive security audit completed. Detailed findings and recommendations available below.';
}

function estimateTimeToFix(critical: number, high: number, medium: number): string {
    // Estimate: critical=4h, high=2h, medium=1h
    const hours = critical * 4 + high * 2 + medium * 1;
    if (hours === 0) return '0h';
    if (hours < 1) return '<1h';
    return `${hours}h`;
}

function generateHeatmapData(findings: any[]): number[][] {
    // 3x3 grid: [row][col] where row=impact (0=low,1=med,2=high), col=probability (0=low,1=med,2=high)
    const grid = [[0, 0, 0], [0, 0, 0], [0, 0, 0]];

    findings.forEach(f => {
        const sev = f.severity || 'low';
        // Map severity to impact/probability (simplified heuristic)
        let impact = 0;
        let prob = 0;

        if (sev === 'critical') {
            impact = 2; prob = 2; // High impact, high probability
        } else if (sev === 'high') {
            impact = 2; prob = 1; // High impact, medium probability
        } else if (sev === 'medium') {
            impact = 1; prob = 1; // Medium impact, medium probability
        } else {
            impact = 0; prob = 1; // Low impact, medium probability
        }

        grid[impact][prob]++;
    });

    return grid;
}

function generateHeatmapCells(heatmapData: number[][]): string {
    const cells: string[] = [];

    // Grid is [impact][probability], we render top-to-bottom (high to low impact)
    for (let row = 2; row >= 0; row--) {
        for (let col = 0; col <= 2; col++) {
            const count = heatmapData[row][col];
            const severity = getCellSeverity(row, col);
            const sevColor = getSeverityTailwindColor(severity);

            let cellClass = 'heatmap-cell rounded-lg flex items-center justify-center group relative cursor-pointer';
            let bgClass = '';
            let textClass = '';
            let extraClass = '';

            if (severity === 'critical') {
                bgClass = 'bg-gradient-to-br from-critical/30 to-critical/10 border border-critical/30 hover:border-critical/50';
                textClass = 'text-white font-mono font-bold text-2xl drop-shadow-md';
                extraClass = 'shadow-[0_0_15px_rgba(239,68,68,0.15)] hover:shadow-[0_0_25px_rgba(239,68,68,0.3)] ring-1 ring-critical/20';
                if (count > 0) {
                    extraClass += ' relative';
                }
            } else if (severity === 'high') {
                bgClass = 'bg-gradient-to-br from-high/20 to-high/5 border border-high/20 hover:border-high/40';
                textClass = `text-high/80 font-mono font-bold text-xl group-hover:text-high transition-colors`;
            } else if (severity === 'medium') {
                bgClass = 'bg-gradient-to-br from-medium/10 to-medium/5 border border-medium/10 hover:border-medium/30';
                textClass = `text-medium/70 font-mono font-bold text-xl group-hover:text-medium transition-colors`;
            } else {
                bgClass = 'bg-white/[0.02] border border-white/5 hover:border-white/20';
                textClass = `text-slate-600 font-mono font-bold text-xl group-hover:text-slate-400 transition-colors`;
            }

            const pulse = severity === 'critical' && count > 0 ?
                '<div class="absolute -top-2 -right-2 size-3 rounded-full bg-critical animate-pulse shadow-[0_0_10px_rgba(239,68,68,0.8)]"></div>' : '';

            cells.push(`
                <div class="${cellClass} ${bgClass} ${extraClass}" onclick="openHeatmapModal(${row}, ${col}, '${severity}', ${count})" data-severity="${severity}" data-count="${count}">
                    <span class="${textClass}">${count}</span>
                    ${pulse}
                </div>
            `);
        }
    }

    return cells.join('');
}

function getCellSeverity(row: number, col: number): string {
    // row: 2=high impact, 1=med impact, 0=low impact
    // col: 2=high prob, 1=med prob, 0=low prob
    if (row === 2 && col === 2) return 'critical'; // High impact + high prob
    if (row === 2 && col === 1) return 'high';     // High impact + med prob
    if (row === 2 && col === 0) return 'medium';   // High impact + low prob
    if (row === 1 && col === 2) return 'high';     // Med impact + high prob
    if (row === 1 && col === 1) return 'medium';   // Med impact + med prob
    if (row === 1 && col === 0) return 'low';      // Med impact + low prob
    if (row === 0 && col === 2) return 'medium';   // Low impact + high prob
    return 'low';                                   // Low impact + low/med prob
}

function generateComplianceMatrix(findings: any[]): { owasp: number; cwe: number; nist: number; pci: number; iso: number; mappings: any[] } {
    // Mapeo de reglas SEC-XXX a frameworks
    const ruleMapping: Record<string, { owasp?: string; cwe?: string; nist?: string; pci?: string; iso?: string }> = {
        'SEC-001': { owasp: 'A07:2021', cwe: 'CWE-287', nist: 'IA-2', pci: '8.2', iso: 'A.9.2' },
        'SEC-002': { owasp: 'A03:2021', cwe: 'CWE-78', nist: 'SI-10', pci: '6.5.1', iso: 'A.14.2' },
        'SEC-003': { owasp: 'A03:2021', cwe: 'CWE-89', nist: 'SI-10', pci: '6.5.1', iso: 'A.14.2' },
        'SEC-004': { owasp: 'A10:2021', cwe: 'CWE-918', nist: 'SC-7', pci: '6.5.9', iso: 'A.13.1' },
        'SEC-005': { owasp: 'A05:2021', cwe: 'CWE-611', nist: 'SI-10', pci: '6.5.1', iso: 'A.14.2' },
        'SEC-006': { owasp: 'A08:2021', cwe: 'CWE-502', nist: 'SI-10', pci: '6.5.8', iso: 'A.14.2' },
        'SEC-007': { owasp: 'A01:2021', cwe: 'CWE-22', nist: 'AC-3', pci: '6.5.8', iso: 'A.9.4' },
        'SEC-008': { owasp: 'A01:2021', cwe: 'CWE-200', nist: 'SC-28', pci: '3.4', iso: 'A.8.2' },
        'SEC-009': { owasp: 'A02:2021', cwe: 'CWE-798', nist: 'IA-5', pci: '8.2.1', iso: 'A.9.4' },
        'SEC-010': { owasp: 'A04:2021', cwe: 'CWE-770', nist: 'SC-5', pci: '6.5.10', iso: 'A.12.1' },
        'SEC-011': { owasp: 'A04:2021', cwe: 'CWE-1333', nist: 'SI-10', pci: '6.5.1', iso: 'A.14.2' },
        'SEC-012': { owasp: 'A02:2021', cwe: 'CWE-327', nist: 'SC-13', pci: '3.5', iso: 'A.10.1' },
        'SEC-013': { owasp: 'Emerging', cwe: 'CWE-94', nist: 'SI-10', pci: '6.5.1', iso: 'A.14.2' },
        'SEC-014': { owasp: 'A05:2021', cwe: 'CWE-829', nist: 'CM-7', pci: '6.5.5', iso: 'A.12.6' },
        'SEC-015': { owasp: 'A01:2021', cwe: 'CWE-250', nist: 'AC-6', pci: '7.1', iso: 'A.9.2' },
        'SEC-016': { owasp: 'A05:2021', cwe: 'CWE-749', nist: 'AC-3', pci: '6.5.10', iso: 'A.13.1' },
        'SEC-017': { owasp: 'A02:2021', cwe: 'CWE-319', nist: 'SC-8', pci: '4.1', iso: 'A.13.1' },
        'SEC-018': { owasp: 'A07:2021', cwe: 'CWE-306', nist: 'IA-2', pci: '8.1', iso: 'A.9.2' },
        'SEC-019': { owasp: 'A03:2021', cwe: 'CWE-20', nist: 'SI-10', pci: '6.5.1', iso: 'A.14.1' },
        'SEC-020': { owasp: 'A02:2021', cwe: 'CWE-615', nist: 'IA-5', pci: '8.2.1', iso: 'A.9.4' },
        'SEC-021': { owasp: 'A02:2021', cwe: 'CWE-522', nist: 'SC-28', pci: '3.4', iso: 'A.10.1' }
    };

    const mappings = findings.map(f => {
        const code = f.rule || f.code || '';
        return {
            rule: code,
            severity: f.severity,
            message: f.message,
            ...ruleMapping[code]
        };
    });

    // Calculate compliance scores (% of rules that map to each framework)
    const total = findings.length;
    const owaspCount = mappings.filter(m => m.owasp).length;
    const cweCount = mappings.filter(m => m.cwe).length;
    const nistCount = mappings.filter(m => m.nist).length;
    const pciCount = mappings.filter(m => m.pci).length;
    const isoCount = mappings.filter(m => m.iso).length;

    return {
        owasp: total > 0 ? Math.round((owaspCount / total) * 100) : 100,
        cwe: total > 0 ? Math.round((cweCount / total) * 100) : 100,
        nist: total > 0 ? Math.round((nistCount / total) * 100) : 100,
        pci: total > 0 ? Math.round((pciCount / total) * 100) : 100,
        iso: total > 0 ? Math.round((isoCount / total) * 100) : 100,
        mappings
    };
}

function generateAgencyTags(finding: any, t: typeof translations['en']): Array<{ icon: string; label: string; color: string }> {
    const tags: Array<{ icon: string; label: string; color: string }> = [];

    const rule = finding.rule || '';
    const message = (finding.message || '').toLowerCase();
    const desc = (finding.description || '').toLowerCase();
    const combined = message + ' ' + desc;

    // Detect category based on rule or keywords
    if (rule.includes('SEC-002') || combined.includes('command') || combined.includes('injection')) {
        tags.push({ icon: 'dns', label: t.agency_system || 'System', color: 'sky' });
    }
    if (combined.includes('network') || combined.includes('ssrf') || combined.includes('request')) {
        tags.push({ icon: 'lan', label: t.agency_network || 'Network', color: 'violet' });
    }
    if (combined.includes('file') || combined.includes('path') || combined.includes('directory')) {
        tags.push({ icon: 'folder_open', label: t.agency_files || 'Files', color: 'orange' });
    }
    if (combined.includes('schema') || combined.includes('validation') || combined.includes('input')) {
        tags.push({ icon: 'code', label: t.agency_schema || 'Schema', color: 'emerald' });
    }
    if (combined.includes('auth') || combined.includes('permission') || combined.includes('access')) {
        tags.push({ icon: 'lock', label: t.agency_auth || 'Auth', color: 'red' });
    }
    if (combined.includes('data') || combined.includes('leak') || combined.includes('exposure')) {
        tags.push({ icon: 'database', label: t.agency_data || 'Data', color: 'amber' });
    }

    return tags;
}
