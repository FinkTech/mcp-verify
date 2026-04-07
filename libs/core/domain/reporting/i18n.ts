/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
export type Language = "en" | "es";

export const translations = {
  en: {
    // HTML Report Keys
    title: "MCP Validation Report",
    target: "Target",
    generated_label: "Generated",
    switch_theme: "Theme",
    theme: "Theme",
    protocol: "Protocol",
    response_time: "Response Time",
    security_audit: "Security Audit",
    scan_id_prefix: "ID",
    surgical_summary: "Surgical Summary",
    surgical_summary_excellent:
      "Security posture is robust with minimal vulnerabilities. System demonstrates strong adherence to security best practices.",
    surgical_summary_good:
      "Security analysis reveals moderate findings requiring attention. Overall system security is satisfactory with room for improvement.",
    surgical_summary_critical:
      "Audit reveals critical chain vulnerabilities in core modules necessitating immediate refactoring. System hardening is required to mitigate lateral movement risks.",
    surgical_summary_warning:
      "Security assessment identifies multiple vulnerabilities across different severity levels. Systematic remediation recommended to strengthen defensive posture.",
    surgical_summary_default:
      "Comprehensive security audit completed. Detailed findings and recommendations available below.",
    risk_heatmap: "Risk Heatmap",
    impact_vs_probability: "IMPACT vs PROBABILITY",
    critical_zone: "Critical Zone",
    impact: "Impact",
    probability: "Probability",
    agency_system: "System",
    agency_network: "Network",
    agency_files: "Files",
    agency_schema: "Schema",
    agency_auth: "Auth",
    agency_data: "Data",
    cli_reproducer: "CLI Reproducer",
    shielded_schema_diff: "Shielded Schema Diff",
    vulnerable: "Vulnerable",
    hardened: "Hardened",
    security_finding: "Security Finding",
    detected: "Detected",
    source: "Source",
    copy_remediation: "Copy Remediation",
    sort_severity: "Sort: Severity",
    by_severity: "By Severity",
    by_rule: "By Rule Code",
    most_recent: "Most Recent",
    introduced_risks: "Introduced Risks",
    resolved_risks: "Resolved Risks",
    new_label: "New",
    fixed_label: "Fixed",
    updated_label: "Updated",
    no_new_risks: "No new risks introduced",
    no_risks_resolved: "No risks resolved",
    minutes_ago: "m ago",
    hours_ago: "h ago",
    days_ago: "d ago",
    just_now: "Just now",
    heatmap_modal_title: "Risk Cell Analysis",
    heatmap_modal_impact: "Impact Level",
    heatmap_modal_probability: "Probability Level",
    heatmap_modal_findings: "Findings in this category",
    heatmap_modal_explanation: "Explanation",
    heatmap_modal_action: "Recommended Action",
    heatmap_critical_explain:
      "This cell represents the highest risk category - findings with both high impact and high probability of exploitation. These vulnerabilities pose immediate threats to system security and require urgent remediation.",
    heatmap_high_explain:
      "This cell represents high-risk findings that either have high impact with medium probability, or medium impact with high probability. These should be prioritized for remediation.",
    heatmap_medium_explain:
      "This cell represents medium-risk findings. While not immediately critical, these vulnerabilities should be addressed in your security roadmap.",
    heatmap_low_explain:
      "This cell represents low-risk findings. These are good opportunities for security improvements but can be scheduled for later remediation cycles.",
    heatmap_action_critical:
      "Immediate action required. Remediate within 24-48 hours. Consider emergency security patch deployment.",
    heatmap_action_high:
      "High priority. Address within 1-2 weeks. Schedule remediation in next sprint.",
    heatmap_action_medium:
      "Medium priority. Address within 1-2 months. Include in quarterly security improvements.",
    heatmap_action_low:
      "Low priority. Address when resources permit. Consider for future security enhancements.",
    view_findings: "View Findings",
    close: "Close",
    risk_breakdown: "Risk Breakdown",
    score_calculation: "Score Calculation",
    severity_weight: "Severity Weight",
    contribution: "Contribution",
    total_findings: "Total Findings",
    weighted_average: "Weighted Average",
    expand_breakdown: "Expand Breakdown",
    collapse_breakdown: "Collapse Breakdown",
    compliance_matrix: "Compliance Matrix",
    framework_mapping: "Framework Mapping",
    compliance_score: "Compliance Score",
    owasp_top_10: "OWASP Top 10",
    cwe_mapping: "CWE",
    nist_controls: "NIST SP 800-53",
    pci_dss: "PCI-DSS",
    iso_27001: "ISO 27001",
    compliant: "Compliant",
    non_compliant: "Non-Compliant",
    partial_compliance: "Partial Compliance",
    view_details: "View Details",
    historical_trends: "Historical Trends",
    security_evolution: "Security Evolution",
    trend_improving: "Improving",
    trend_degrading: "Degrading",
    trend_stable: "Stable",
    baseline_comparison: "Baseline Comparison",
    current_scan: "Current Scan",
    previous_scan: "Previous Scan",
    delta: "Delta",
    executive_summary: "Executive Summary",
    overall_risk_rating: "Overall Risk Rating",
    top_critical_issues: "Top Critical Issues",
    security_posture: "Security Posture",
    requires_immediate_action: "Requires Immediate Action",
    requires_attention: "Requires Attention",
    satisfactory: "Satisfactory",
    excellent: "Excellent",
    critical_findings_detected: "Critical findings detected",
    moderate_findings_detected: "Moderate findings detected",
    minor_findings_detected: "Minor findings detected",
    no_major_findings: "No major findings",
    remediation_checklist: "Remediation Checklist",
    priority: "Priority",
    status: "Status",
    estimated_time: "Estimated Time",
    hours: "hours",
    hour: "hour",
    export_checklist: "Export Checklist",
    mark_as_done: "Mark as Done",
    pending: "Pending",
    quick_filters: "Quick Filters",
    filter_by_severity: "Filter by Severity",
    filter_by_category: "Filter by Category",
    has_fix_available: "Has Fix Available",
    reset_filters: "Reset Filters",
    showing_findings: "Showing {count} findings",
    all_severities: "All Severities",
    all_categories: "All Categories",
    tools: "Tools",
    quality: "Quality",
    findings: "Findings",
    issues_found: "issues found",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    quality_suggestions: "quality suggestions",
    compliance: "Compliance",
    jsonrpc_20: "JSON-RPC 2.0",
    no_risks: "No security risks detected!",
    tip_label: "Tip",
    stats: "Statistics",
    resources: "Resources",
    prompts: "Prompts",
    architecture_map: "Architecture Map",
    zoom_instructions: "Scroll to zoom, drag to pan",
    input_schema: "Input Schema",
    generated_by: "Generated by",
    view_on_github: "View on GitHub",
    security_standards: "Security Standards",
    status_valid: "Valid",
    status_invalid: "Invalid",
    no_description: "No description available",
    na_label: "N/A",
    violations_detected: "Violations detected",
    standard_compliant: "Standard compliant",
    sec_heuristic_detected: "{msg} detected in tool",
    finding_rate_limit_missing: "Rate limiting not implemented",
    // Security Finding Keys
    finding_auth_weak_hashing: "Tool {tool} uses weak hashing algorithms",
    finding_auth_no_hashing_method:
      "Tool {tool} does not specify a password hashing method",
    finding_auth_min_length:
      "Parameter {param} lacks minimum length requirement",
    finding_auth_complexity: "Parameter {param} lacks complexity requirements",
    finding_auth_user_enumeration:
      "Parameter {param} might allow user enumeration",
    finding_auth_credentials_plain:
      "Parameter {param} accepts plain text credentials",
    finding_auth_no_hashing:
      "Tool {tool} does not appear to use strong hashing",
    finding_auth_no_brute_force:
      "Tool {tool} lacks brute force protection indicators",
    finding_deserialization_dangerous:
      "Tool {tool} appears to deserialize dangerous format: {format}",
    remediation_deserialization_safe:
      "Use a safe deserialization format like JSON instead of {format}",
    finding_deserialization_unsafe_yaml:
      "Tool {tool} uses unsafe YAML loading, allowing arbitrary code execution.",
    finding_deserialization_no_schema:
      "Tool {tool} deserializes data without a strict schema, leading to potential object injection.",
    finding_deserialization_no_type:
      "Parameter {param} is an object without explicit type, allowing arbitrary object injection.",
    finding_deserialization_arbitrary:
      "Parameter {param} allows arbitrary object properties, which can lead to injection attacks.",
    finding_deserialization_encoded:
      "Parameter {param} accepts encoded data which may hide serialized objects.",
    finding_deserialization_no_security:
      "Tool {tool} description does not mention any security measures against deserialization attacks.",
    finding_cmd_injection_no_schema:
      "Tool {tool} appears to execute commands but lacks schema",
    finding_cmd_injection_no_validation:
      "Parameter {param} in tool {tool} lacks validation pattern",
    finding_cmd_injection_weak_validation:
      "Parameter {param} uses weak validation pattern",
    finding_sql_no_schema:
      "Tool {tool} appears to execute SQL but lacks input schema",
    finding_sql_potential:
      "Parameter {param} in tool {tool} is vulnerable to SQL injection",
    finding_sql_type_mismatch:
      "Parameter {param} should be numeric but accepts string",
    finding_sql_no_prepared:
      "Tool {tool} description does not mention prepared statements",
    finding_ssrf_potential:
      "Parameter {param} appears to be a URL input without validation",
    finding_ssrf_weak_val: "Parameter {param} has weak URL validation",
    finding_xxe_dangerous_parser:
      "Tool {tool} appears to use a dangerous XML parser configuration",
    finding_xxe_no_schema: "Tool {tool} processes XML but lacks input schema",
    finding_xxe_no_pattern: "Parameter {param} lacks XML validation pattern",
    finding_xxe_uploads: "Parameter {param} accepts XML file uploads",
    finding_xxe_svg: "Parameter {param} accepts SVG input",
    finding_xxe_no_protection:
      "Tool {tool} does not explicitly disable external entities",
    finding_path_traversal_static_uri:
      "Resource {resource} points to a potentially sensitive system path: {uri}",
    finding_path_traversal_dynamic_uri:
      "Resource {resource} uses dynamic URI without restrictions",
    finding_path_traversal_file_scheme:
      "Resource {resource} uses file:// scheme with dynamic segments",
    finding_path_traversal_weak_pattern:
      "Parameter {param} uses weak path validation",
    finding_data_leakage_sensitive:
      "Tool {tool} accepts sensitive data '{param}' as argument",
    finding_data_leakage_resource:
      "Resource {resource} exposes potentially sensitive file",
    finding_sensitive_no_format:
      "Parameter {param} ({category}) lacks format specification",
    finding_sensitive_no_pattern:
      "Parameter {param} ({category}) lacks validation pattern",
    finding_sensitive_logging: "Parameter {param} ({category}) might be logged",
    finding_sensitive_no_protection:
      "Tool {tool} handles {category} data without protection",
    finding_sensitive_response: "Tool {tool} returns {category} data in {prop}",
    finding_rate_limit_auth_must:
      "Authentication tool {tool} must implement strict rate limiting",
    finding_rate_limit_no_size:
      "File upload parameter {param} lacks size limits",
    finding_redos_vulnerable:
      "Parameter {param} has a vulnerable regex pattern that can lead to ReDoS.",
    finding_redos_no_anchors:
      "Regex for parameter {param} is not anchored, which can lead to inefficient matching.",
    finding_crypto_weak_encryption: "Tool {tool} uses weak encryption {algo}",
    finding_crypto_weak_hashing: "Tool {tool} uses weak hashing {algo}",
    finding_crypto_insecure_random: "Tool {tool} uses insecure random {method}",
    finding_crypto_short_key: "Parameter {param} allows short keys",
    finding_crypto_danger_short:
      "Parameter {param} allows dangerously short keys",
    finding_crypto_weak_selection:
      "Parameter {param} allows selecting weak algorithms",
    finding_crypto_no_algorithms:
      "Tool {tool} does not specify strong algorithms",
    finding_prompt_injection_no_limit:
      "Parameter {param} in tool {tool} lacks length limits",
    finding_prompt_injection_no_pattern:
      "Parameter {param} in tool {tool} lacks validation pattern",
    finding_prompt_injection_prompt_args:
      "Prompt {prompt} takes arguments without validation schema",
    finding_prompt_injection_indirect:
      "Tool {tool} fetches external content (keyword: {keyword}) - potential indirect injection vector",
    finding_prompt_injection_chain:
      "CRITICAL: Tool {tool} fetches AND processes external content - high indirect injection risk",
    finding_prompt_injection_weak_pattern:
      "Parameter {param} in tool {tool} has weak validation pattern that allows injection",

    // MCP Server Tools
    mcp_tool_validate_server_desc:
      "Validates an MCP server (connection, schema, security, quality).",
    mcp_tool_scan_security_desc:
      "Performs a focused security scan on an MCP server.",
    mcp_tool_analyze_quality_desc:
      "Analyzes the quality and semantics of MCP tools and resources.",
    mcp_tool_generate_report_desc:
      "Generates a comprehensive validation report in various formats.",
    mcp_tool_list_installed_servers_desc:
      "Lists MCP servers configured in the local environment (e.g. Claude Desktop).",
    mcp_tool_self_audit_desc:
      "Performs a self-audit of the mcp-verify installation.",
    mcp_tool_compare_servers_desc:
      "Compares two MCP servers (e.g. regression testing).",

    // MCP Server Parameters
    mcp_param_command_desc:
      'The command to start the MCP server (e.g. "node server.js").',
    mcp_param_command_desc_short: "Server start command.",
    mcp_param_command_desc_compare: "Start command for this server.",
    mcp_param_args_desc: "Arguments for the command.",
    mcp_param_args_desc_compare: "Arguments for this server.",
    mcp_param_config_path_desc: "Path to mcp-verify.config.json (optional).",
    mcp_param_config_path_desc_claude:
      "Path to Claude Desktop config (optional).",
    mcp_param_rules_desc: "Specific security rules to enable (optional).",
    mcp_param_format_desc: "Report format (json, sarif, text).",
    mcp_param_output_path_desc: "Directory to save the report.",
    mcp_param_skip_validation_desc:
      "Skip active server validation during audit.",
    mcp_param_server_name_desc: "Name of the server.",
    mcp_param_servers_desc: "List of servers to compare.",

    // MCP Errors
    mcp_error_unknown_tool: "Unknown tool requested",
    mcp_error_connection_failed: "Connection to MCP server failed",
    mcp_error_failed_to_connect_quality:
      "Failed to connect for quality analysis",
    mcp_error_failed_to_analyze_quality: "Quality analysis failed",
    mcp_error_at_least_two_servers:
      "At least two servers are required for comparison",
    mcp_error_please_provide_two_servers: "Please provide at least two servers",
    mcp_error_config_not_found_audit: "Configuration file not found for audit",
    mcp_error_failed_to_discover_servers:
      "Failed to discover installed servers",
    mcp_error_handshake_failed: "Protocol handshake failed",
    mcp_error_failed_to_connect: "Failed to connect to server",
    mcp_error_failed_to_validate: "Validation failed",
    mcp_error_failed_to_compare_servers: "Failed to compare servers",
    mcp_error_failed_to_generate_report: "Failed to generate report",
    mcp_error_unsupported_platform: "Unsupported platform",
    mcp_error_config_not_found: "Configuration file not found",
    mcp_error_failed_to_read_config: "Failed to read configuration",
    mcp_error_failed_to_connect_security: "Failed to connect for security scan",
    mcp_error_failed_to_scan_security: "Security scan failed",
    mcp_error_native_addon_not_available:
      "Native addon module not available: {addon}",
    mcp_error_native_addon_not_found_sea:
      '[mcp-verify] Native addon "{addon}" not found next to the executable.\n  Expected .node file in: {dir}\n  Run the release script to include native addons with the binary.',
    mcp_error_native_addon_not_installed:
      '[mcp-verify] Native addon "{addon}" not installed. Run: npm install',
    mcp_error_keychain_save_failed:
      "Failed to save API key to keychain: {error}",
    mcp_error_keychain_get_failed: "Failed to retrieve API key from keychain",
    mcp_unknown_server: "Unknown Server",
    mcp_not_available: "Not Available",
    unknown_version: "Unknown Version",

    // LLM Errors
    llm_invalid_spec: "Invalid LLM provider spec: {spec}",
    llm_env_not_set: "Environment variable for {provider} not set",
    llm_key_invalid_format: "Invalid API key format for {provider}",
    llm_key_too_short: "API key too short for {provider}",
    llm_unknown_provider: "Unknown LLM provider: {provider}",
    llm_init_failed: "Failed to initialize {provider}: {error}",
    llm_validation_failed: "Validation failed for {provider}: {error}",
    llm_analysis_failed: "LLM analysis failed: {error}",
    ollama_model_not_found: "Ollama model not found",
    ollama_timeout: "Ollama request timed out after {timeout}ms",
    ollama_api_error: "Ollama API error: {error}",

    // Markdown Generator Keys
    suggested_solution: "Suggested Solution",
    md_security_findings: "Security Findings",
    md_no_critical_findings: "No critical findings detected.",
    md_capabilities_overview: "Capabilities Overview",
    table_desc: "Description",
    table_status: "Status",
    md_valid: "Valid",
    md_invalid: "Invalid",
    md_passed: "Passed",
    md_severity: "Severity",
    md_report_generated_by: "Report generated by",
    md_report_date: "Date",
    md_total: "Total",
    md_tools: "Tools",
    architecture_diagram: "Architecture Diagram",
    client_label: "Client",
    transport_label: "Transport",
    functionality_label: "Functionality",
    mcp_security_score: "Security Score",
    safety_layer_label: "Safety Layer",
    md_protocol_compliance: "Protocol Compliance",
    protocol_spec: "Protocol Specification",
    schema_valid: "Schema Validation",
    protocol_issues_detected: "Protocol Issues Detected",
    unknown_server: "Unknown Server",
    md_executive_summary: "Executive Summary",
    md_property: "Property",
    md_value: "Value",
    md_server_name: "Server Name",
    md_protocol_version: "Protocol Version",
    md_quality_score: "Quality Score",
    md_finding: "Finding",
    md_rule: "Rule",
    details_header: "Details",
    md_remediation: "Remediation",

    // Scan History Keys
    failed_parse_scan_file: "Failed to parse scan file {id}: {error}",
    scan_not_found: "Scan {id} not found",
    unknown_reason: "Unknown reason",

    // Heuristic Keys
    sec_heuristic_rce: "Remote Code Execution risk",
    sec_heuristic_auth: "Authentication/Credential risk",
    sec_heuristic_fs: "Filesystem operation risk",
    sec_heuristic_db: "Database operation risk",
    sec_heuristic_net: "Network operation risk",

    // Block A: OWASP LLM Top 10 in MCP Context (SEC-022 to SEC-030)
    sec_022_insecure_output_chained:
      'Tool "{toolName}" outputs unescaped data that is consumed by other tools. Enables stored XSS, command injection, and indirect prompt injection when output contaminates agent context.',
    sec_022_insecure_output_standalone:
      'Tool "{toolName}" outputs data without sanitization constraints. Missing format declaration or contentEncoding in output schema.',
    sec_022_recommendation:
      'Add output schema with contentEncoding: "base64" or explicit sanitization metadata. Alternatively, add description: "Outputs are HTML-escaped" or equivalent. Never pass tool outputs directly to eval(), exec(), or LLM context without validation.',

    // Block B: Multi-Agent & Agentic Chain Attacks (SEC-031 to SEC-041)
    sec_031_agent_spoofing:
      'Privileged tool "{toolName}" does not verify agent identity. Malicious agents can impersonate trusted agents (Claude, orchestrators) to access restricted operations. Missing authentication parameters (api_key, agent_id, token) or identity verification.',
    sec_031_recommendation:
      'Add authentication parameter to inputSchema: agent_id (required), api_key (required), or session_token (required). Alternatively, add description: "Requires verified agent identity" and implement server-side validation against agent registry.',

    // Block C: Operational & Enterprise Compliance (SEC-042 to SEC-050)
    sec_042_missing_audit_logging:
      "Server does not expose any audit logging mechanism. Missing tools like get_audit_log, list_events, or logging capabilities. Critical for SOC 2, ISO 27001, and GDPR compliance in autonomous AI systems.",
    sec_042_recommendation:
      "Implement audit logging tools: get_audit_log(time_range, filter), export_audit_trail(format), or equivalent. Include timestamps, user identifiers, actions performed, and results.",

    // Block D: AI Weaponization & Supply Chain (SEC-051 to SEC-060)
    sec_053_malicious_pattern:
      'CRITICAL: Server "{serverName}" has malicious command pattern: {pattern}. Command: {command}. This is the exact vector of CVE-2025-59536 - executes without user consent.',
    sec_053_recommendation:
      "DO NOT execute this project. Remove malicious server configuration. Report to security team if this came from a public repository.",
    sec_053_supply_chain_warning:
      "SUPPLY CHAIN ATTACK DETECTED: This .mcp.json is in a Git repository. Anyone cloning this repo will execute the malicious payload automatically.",
    sec_053_supply_chain_recommendation:
      "Report this repository immediately. Do not push commits. Consider this repo compromised.",
    sec_053_env_hijacking:
      'Server "{serverName}" overrides API endpoint: {envVar} = {value}. This can exfiltrate API keys before any trust prompt (CVE-2026-21852).',
    sec_054_endpoint_hijacking:
      'Server "{serverName}" overrides API endpoint: {envVar} = {value}. Can exfiltrate API keys on FIRST request (CVE-2026-21852).',
    sec_054_tool_endpoint_hijacking:
      'Tool "{tool}" can register or hijack API endpoints without proper validation. Allows unauthorized endpoint manipulation.',
    sec_054_recommendation:
      "Remove API endpoint override. Only use official endpoints: api.anthropic.com, api.openai.com. Localhost overrides require explicit justification.",
    sec_059_unvalidated_auth:
      'Tool "{toolName}" {reason}. Missing authorization validation allows privilege escalation.',
    sec_059_recommendation:
      "Add authorization parameters: require token/permission_level, implement RBAC checks, validate caller identity before tool invocation.",
    sec_060_missing_transaction:
      'Tool "{toolName}" performs multi-step critical operations without transaction semantics. No rollback/undo mechanism if operation fails mid-way.',
    sec_060_recommendation:
      "Implement transaction semantics: add rollback_on_error parameter, provide undo mechanism, use transaction_id for atomic operations, implement dry-run mode.",
    sec_061_server_name:
      'Server name "{name}" contains non-ASCII characters from confusable Unicode blocks ({blocks}) mixed with ASCII letters: {positions}. This enables homoglyph spoofing — the name appears identical to a legitimate server name but differs at the codepoint level, bypassing allowlist checks.',
    sec_061_tool_name:
      'Tool name "{toolName}" contains non-ASCII characters from confusable Unicode blocks ({blocks}) mixed with ASCII letters: {positions}. Attackers use look-alike characters to register malicious tools that bypass name-based security checks.',
    sec_061_resource_name:
      'Resource "{resourceName}" contains non-ASCII characters from confusable Unicode blocks ({blocks}) mixed with ASCII letters: {positions}. Look-alike characters in resource identifiers can bypass access control lists and monitoring filters.',
    sec_061_recommendation:
      "Restrict server name, tool names, and resource identifiers to ASCII characters only (A-Z, a-z, 0-9, hyphens, underscores). Implement Unicode normalization (NFC/NFKC) before comparisons. Use a Unicode confusables database (UTS#39) to validate identifiers at registration time.",

    // Remediation Keys (from rule files)
    ssrf_insecure_http: "Pattern allows insecure HTTP",
    ssrf_wildcard_start: "Pattern starts with wildcard",
    ssrf_not_anchored: "Pattern is not anchored (^...$)",
    risk_crypto_broken: "Algorithm {algo} is broken and insecure",
    risk_crypto_insufficient:
      "Algorithm {algo} has insufficient security margin",
    risk_crypto_collision:
      "Hash function {algo} is vulnerable to collision attacks",
    risk_crypto_resistance:
      "Hash function {algo} is weak against modern attacks",
    // End HTML Report Keys
    about_feature_i18n: "Internationalization (EN/ES)",
    about_feature_llm: "LLM semantic analysis (optional)",
    about_feature_owasp: "60 security rules (6 blocks)",
    about_feature_protocol: "MCP protocol validation",
    about_feature_reports: "Multiple report formats (JSON, HTML, SARIF, MD)",
    active_guardrails: "🛡️  Active Guardrails (v1.0):",
    add_a_clear_description_explaining_what_the_tool_d:
      "Add a clear description explaining what the tool does.",
    all_checks_passed: "All checks passed! Server looks healthy.",
    all_tests_passed_label: "All tests passed",
    allowed_label: "Allowed",
    anthropic_api_key_not_configured: "Anthropic API key not configured",
    anthropic_invalid_key_format:
      "[Anthropic] Invalid API key format. Expected: sk-ant-...",
    attempted_label: "Attempted",
    available_capabilities: "Available Capabilities",
    avoid_passing_secrets_as_tool_arguments_use_enviro:
      "Avoid passing secrets as tool arguments. Use environment variables or MCP resource templates for credential management to prevent leakage in LLM context logs.",
    avoid_using_file_uris_with_dynamic_segments_if_nec:
      "Avoid using file:// URIs with dynamic segments. If necessary, implement strict path canonicalization, jail the file access to a specific directory, and validate against a whitelist.",
    badge: "Badge",
    baseline_parse_error: "Failed to parse baseline file: {error}",
    baseline_critical_degradation: "CRITICAL: {count} new critical findings!",
    baseline_score_dropped:
      "Score dropped by more than allowed threshold (Security: {sec}, Quality: {qual})",
    baseline_degraded:
      "Overall score degraded (Security: {sec}, Quality: {qual})",
    baseline_improved:
      "Overall score improved! (Security: +{sec}, Quality: +{qual}, Fixed: {fixed})",
    baseline_build_failed:
      "Build failed: Baseline comparison detected unacceptable degradation",
    baseline_comparison_title: "Baseline Comparison",
    baseline_label: "Baseline",
    preparing_print: "Preparing to print...",
    baseline_no_changes: "➡️ No significant changes from baseline",
    baseline_saved_at: "Baseline saved at",
    basic_validation: "Basic Validation",
    blocked_by_guardrail: "Blocked by Guardrail",
    blocked_label: "Blocked",
    blocked_log: "BLOCKED",
    cannot_resolve: "Cannot resolve hostname",
    change_language_cambiar_idioma: "Change language / Cambiar idioma",
    chart_distribution: " Distribution",
    check_hostname_reachable:
      "Check that the hostname is correct and reachable",
    check_initialization_errors: "Check server logs for initialization errors",
    check_protocol_version: "Check protocol version compatibility",
    check_server_load: "Check server can handle load",
    check_server_running_detail: "Check that the server is running",
    check_url_correct: "Check that the URL is correct",
    ci_cd_integration: "CI/CD Integration",
    cleaning_up: "Cleaning up resources...",
    cleanup_complete: "Cleanup complete. Goodbye!",
    cleanup_error: "Error during cleanup:",
    cli_description: "CLI tool to validate and test MCP servers",
    cli_disclaimer_affiliation:
      "Not affiliated with Anthropic or the Model Context Protocol organization.",
    cli_disclaimer_independent: "This is an independent open-source tool.",
    cli_command: "CLI Command",
    client_connected_sse: "Client connected to Proxy SSE",
    client_disconnected_sse: "Client disconnected from Proxy SSE",
    clients_for: "clients for",
    copied: "Copied!",
    copy: "Copy",
    current_label: "Current",
    cmd_clear: "Clear screen",
    cmd_dashboard_desc: "Launch interactive web dashboard",
    cmd_doctor_desc: "Diagnose connection issues or check local environment",
    cmd_examples_desc: "Show usage examples",
    cmd_exit: "Exit tool",
    cmd_help: "Show help",
    cmd_init_desc: "Create default configuration file",
    cmd_mock_desc: "Start dummy MCP server",
    cmd_playground_desc: "Enter interactive playground for tools",
    cmd_proxy_desc: "Start security proxy gateway",
    cmd_stress_desc: "Run load testing on an MCP server",
    cmd_fuzz_desc: "Run security fuzzing on an MCP server",
    cmd_scan_config_desc:
      "Scan MCP config files for malicious patterns (Block D)",
    dashboard_title: "MCP-Verify Dashboard",
    dashboard_brand: "MCP-Verify",
    dashboard_connecting: "Connecting...",
    dashboard_traffic_inspector: "Traffic Inspector",
    dashboard_interactive_playground: "Interactive Playground",
    version_author: "by Fink",
    dashboard_live_traffic: "Live Traffic",
    dashboard_clear: "Clear",
    dashboard_waiting_requests: "Waiting for requests...",
    dashboard_connect_client: "Connect a client to see traffic",
    dashboard_configure_request: "Configure Request",
    dashboard_tool_capability: "Tool/Capability",
    dashboard_select_tool: "Select a tool...",
    dashboard_run_tool: "Run Tool",
    dashboard_response: "Response",
    dashboard_results_placeholder: "Results will appear here...",
    dashboard_no_arguments: "Tool has no arguments.",
    dashboard_running: "Running...",
    dashboard_connected: "Connected",
    dashboard_reconnecting: "Reconnecting...",
    dashboard_starting: "Starting Dashboard...",
    dashboard_target_server: "Target Server:",
    dashboard_active_at: "Dashboard active at",
    dashboard_connecting_server: "Connecting to server...",
    dashboard_connected_count: "Connected! Discovered {count} tools.",
    dashboard_error_connect: "Error connecting to server.",
    dashboard_mock_mode: "Using mock tools.",
    calculator_desc: "A simple calculator tool.",
    get_weather_desc: "Gets the weather for a given location.",
    dashboard_exec_failed: "Execution failed",
    dashboard_unknown_exec_error: "Unknown execution error",
    dashboard_mock_notice: "This is a mock response.",
    executed_successfully: "{tool} executed successfully.",
    execution_failed: "Execution failed.",
    dashboard_closing: "Dashboard closing...",
    dashboard_closed: "Dashboard closed.",
    cmd_validate_desc: "Validate an MCP server",
    cmd_fingerprint_desc: "Detect tech stack (reconnaissance)",
    cmd_inspect_desc: "List tools and resources",
    common_solutions: "Common Solutions",
    comparison_saved_at: "Comparison report saved at",
    config_created: "Configuration file created:",
    config_exists: "Config file already exists at:",
    connected: "Connected!",
    connected_to_transport: "Connected to transport",
    connecting: "Connecting via",
    connecting_server: "Connecting to server...",
    connecting_to_server: "Connecting to server",
    connection_failed: "Connection Failed",
    connection_failed_msg: "Connection failed",
    crashes_detected: "CRASHES DETECTED",
    created_by: "Created by:",
    deeply_nested_quantifiers: "Deeply nested quantifiers",
    define_a_strict_input_schema_with_expected_types_i:
      "Define a strict input schema with expected types. Implement schema validation before deserialization.",
    description_is_very_short: "Description is very short",
    detailed_guides: "Detailed Guides",
    detected_runtime: "Detected runtime",
    detected_transport: "Detected transport",
    diag_deno_desc:
      "Checks if Deno runtime is installed (required for sandbox mode)",
    diag_deno_details:
      "Deno is optional. It's only required if you want to use sandbox mode for server execution.",
    diag_deno_name: "Deno Runtime",
    diag_outdated: "{name} is outdated ({version})",
    diag_installed: "Installed ({version})",
    diag_not_found: "{name} not found",
    diag_git_desc: "Checks if Git is installed for version control operations",
    diag_git_name: "Git CLI",
    diag_install_deno: "Install Deno: https://deno.land/",
    diag_install_git: "Install Git: https://git-scm.com/downloads",
    diag_install_node: "Install Node.js: https://nodejs.org/",
    diag_install_python: "Install Python: https://www.python.org/downloads/",
    diag_node_desc: "Checks if Node.js runtime is installed",
    diag_node_name: "Node.js Runtime",
    diag_node_req: "mcp-verify requires Node.js 20 or higher.",
    diag_python_desc: "Checks if Python runtime is installed",
    diag_python_details:
      "Python is optional. It's only required if you want to test Python-based MCP servers.",
    diag_python_name: "Python Runtime",
    diagnostic_results: "Diagnostic Results",
    direct_filesystem_access_with_dynamic_paths:
      "Direct filesystem access with dynamic paths",
    static_resource_points_to_sensitive_system_path:
      "Static resource points to a sensitive system path",
    avoid_exposing_sensitive_system_files_as_static_re:
      "Avoid exposing sensitive system files or directories as static MCP resources. Use scoped access or virtual paths.",
    discovering: "Discovering tools and resources...",
    discovery_failed: "Discovery failed",
    dns_error: "Cannot resolve hostname",
    dns_resolution: "DNS Resolution",
    do_not_expose_configuration_files_keys_or_credenti:
      "Do not expose configuration files, keys, or credentials as MCP resources. Use specific, scoped data access.",
    doctor_title: "MCP Server Diagnostics",
    document_cryptographic_algorithms_aes256gcm_for_en:
      "Document cryptographic algorithms: AES-256-GCM for encryption, SHA-256+ for hashing, RSA-2048+ or ECC for asymmetric.",
    document_data_protection_1_encryption_at_rest_and:
      "Document data protection: (1) Encryption at rest and in transit, (2) Access controls, (3) Audit logging, (4) Data retention policies.",
    document_password_hashing_method_use_bcrypt_argon2:
      "Document password hashing method. Use bcrypt, Argon2, or scrypt with proper work factors.",
    document_the_password_hashing_algorithm_used_shoul:
      "Document the password hashing algorithm used (should be bcrypt, Argon2, or scrypt with proper parameters).",
    duration_ms: "Duration",
    edit_to_customize:
      "Edit this file to customize security rules and proxy settings.",
    editor_error: "Editor error",
    elevated_error_rate: "Elevated error rate",
    email_label: "Email",
    enforce_complexity_requirements_minimum_12_charact:
      "Enforce complexity requirements. Minimum 12 characters, mixed case, numbers, symbols.",
    enforce_minimum_256_bits_for_aes_2048_bits_for_rsa:
      "Enforce minimum: 256 bits for AES, 2048 bits for RSA, 256 bits for ECC.",
    ensure_the_server_validates_and_sanitizes_uri_para:
      "Ensure the server validates and sanitizes URI parameters. Consider using a whitelist of allowed paths or implementing strict input validation.",
    enter_arguments_json: "Enter arguments JSON.",
    err_auth_msg: "Access denied. Please check your credentials.",
    err_auth_title: "Authentication Failed",
    err_conn_msg: "Failed to connect to MCP server{target}",
    err_dns_msg: "Could not resolve hostname{target}",
    err_timeout_msg: "The request timed out{target}",
    err_cmd_failed: "Command '{command}' failed",
    err_conn_title: "Connection Failed",
    err_dns_title: "DNS Resolution Failed",
    err_protocol_msg: "The server response does not comply with MCP protocol.",
    err_protocol_title: "Protocol Error",
    err_timeout_title: "Connection Timeout",
    err_unknown_title: "Operation Failed",
    error: "Error",
    error_command_empty: "Command string cannot be empty",
    error_handling_request: "Error handling request",
    error_invalid_json_response: "Invalid JSON response from server",
    error_process_exit: "Process exited with code {code}",
    error_process_not_started: "Process not started",
    error_process_spawn: "Failed to spawn process: {message}",
    error_request_timeout: "Request timeout after {timeout}ms",
    request_timeout: "Request timed out after {ms}ms",
    error_testing_server: "for error testing",
    error_transport_connection: "Transport connection error",
    error_unknown_jsonrpc: "Unknown JSON-RPC error",
    errors_encountered: "Errors Encountered",
    evidence_label: "Evidence",
    payload: "Payload",
    payloads: "Payloads",
    evidence_redos_pattern: "Nested quantifiers detected",
    evidence_redos_timeout: "Pattern evaluation timeout",
    evidence_redos_too_long: "Pattern too long (>500 chars)",
    evidence_redos_vulnerable: "Vulnerable pattern structure",
    export_failed: "Export Failed",
    export_zip: "Export ZIP",
    exported: "Exported!",
    exporting: "Exporting...",
    even_with_prepared_statements_implement_input_vali:
      "Even with prepared statements, implement input validation to prevent logic errors.",
    example_1_desc: "Tests protocol, discovers tools, generates report",
    example_2_desc:
      "Includes 4 security rules (Path Traversal, Command Injection, SSRF, Data Leakage)",
    example_3_desc: "Tests with 10 concurrent users for 30 seconds",
    example_4_desc: "Test tools interactively with custom inputs",
    example_5_desc: "Generate SARIF report for GitHub Code Scanning",
    example_6_desc: "Start dummy MCP server to test validator",
    example_curl_command: "   $ curl",
    example_doctor_command: "   $ mcp-verify doctor",
    example_label: "Example",
    example_ps_command: "   $ ps aux | grep your-server",
    example_url: "Example: http://localhost:3000 or https://api.example.com",
    example_validate_command: "   $ mcp-verify validate",
    examples_title: "Quick Examples",
    executing_tool: "Executing Tool...",
    expand_description_to_at_least_20_characters_to_pr:
      "Expand description to at least 20 characters to provide context to the LLM.",
    failed_connect_server: "Failed to connect to MCP server",
    failed_label: "Failed",
    failures_label: "Failures",
    fetching_capabilities: "Fetching capabilities...",
    firewall_blocking: "Is there a firewall blocking the connection?",
    fix_label: "💡 Fix: ",
    fuzz_cmd_detected_desc:
      "Command injection detected - system command output in response",
    fuzz_cmd_detected_rem:
      "Never pass user input to system commands. Use allowlists and input validation.",
    fuzz_dangerous_detected:
      "Dangerous command detected in payload (safety check)",
    fuzz_empty_args: "Empty Arguments",
    fuzz_info_disclosure_desc: "Server error message exposed",
    fuzz_info_disclosure_rem:
      "Implement proper error handling. Do not expose internal errors to users.",
    fuzz_nosql_detected_desc: "NoSQL injection detected",
    fuzz_nosql_detected_rem:
      "Sanitize operators. Use schema validation. Avoid eval() or $where.",
    fuzz_path_detected_desc:
      "Path traversal detected - sensitive file content in response",
    fuzz_path_detected_rem:
      "Validate and sanitize file paths. Use allowlists. Restrict file access to specific directories.",
    fuzz_server_error_desc: "Payload caused server error (500)",
    fuzz_server_error_rem:
      "Implement proper input validation and error handling.",
    fuzz_sqli_detected_desc:
      "SQL error message detected - potential SQL injection",
    fuzz_sqli_detected_rem:
      "Use prepared statements with parameterized queries. Never concatenate user input into SQL.",
    fuzz_ssrf_detected_desc:
      "SSRF vulnerability detected - accessed internal resource",
    fuzz_ssrf_detected_rem:
      "Validate and allowlist URLs. Block internal IP ranges. Use egress filtering.",
    fuzz_stack_trace_desc: "Stack trace leaked in response",
    fuzz_stack_trace_rem:
      "Disable stack trace output in production. Use generic error messages.",
    fuzz_time_sqli_desc: "Time-based blind injection detected",
    fuzz_time_sqli_rem:
      "Use parameterized queries. Implement input validation.",
    fuzz_time_suspicious_desc:
      "Suspicious response time for time-based payload",
    fuzz_time_suspicious_rem:
      "Investigate potential time-based injection vulnerability.",
    fuzz_type_mismatch: "Type Mismatch",
    fuzz_unknown_props: "Unknown Properties",
    fuzz_xss_detected_desc: "Potential XSS vulnerability detected",
    fuzz_xss_detected_rem:
      "Sanitize all user inputs before rendering. Use Content-Security-Policy.",
    fuzz_xss_reflected_desc: "XSS payload reflected without encoding",
    fuzz_xss_reflected_rem:
      "Implement output encoding. Use proper Content-Security-Policy headers.",
    fuzz_xxe_detected_desc: "XXE vulnerability detected",
    fuzz_xxe_detected_rem:
      "Disable external entity processing in XML parser. Use safe XML libraries.",
    fuzz_large_payload: "Large Payload ({size})",
    fuzz_security_attack: "Security Attack ({type}): {key}",
    fuzz_mutated_attack: "Mutated Attack ({mutation} on {type}): {key}",
    fuzzing_label: "Fuzzing",
    generating_report: "Generating report...",
    gemini_api_key_not_configured:
      "Google API key not configured. Get free key at https://aistudio.google.com/apikey",
    gemini_invalid_key_format:
      "[Gemini] Invalid API key format. Expected: AIza...",
    getting_prompt: "Getting Prompt...",
    github_label: "GitHub",
    goodbye: "Goodbye!",
    guardrail_https_enforcement: "  ✓ HTTPS Enforcement",
    guardrail_input_sanitization: "  ✓ Input Sanitization (SQL, XSS, Command)",
    guardrail_auto_upgrade: "Auto-upgraded {count} insecure URLs to HTTPS.",
    guardrail_insecure_detected: "Detected insecure URLs: {urls}",
    guardrail_mixed_content: "Mixed content detected (HTTP in HTTPS context)",
    guardrail_pii_address: "IP Address detected",
    guardrail_pii_api_key: "API Key detected",
    guardrail_pii_cc: "Credit Card detected",
    guardrail_pii_email: "Email detected",
    guardrail_pii_phone: "Phone number detected",
    guardrail_pii_redaction: "  ✓ PII Redaction (SSN, Cards, Emails)",
    guardrail_pii_ssn: "SSN detected",
    guardrail_rate_burst:
      "Burst limit exceeded: {current}/{limit} requests in 1s",
    guardrail_rate_hour:
      "Rate limit exceeded: {current}/{limit} requests per hour",
    guardrail_rate_limiting: "  ✓ Rate Limiting (60 req/min)",
    guardrail_rate_minute:
      "Rate limit exceeded: {current}/{limit} requests per minute",
    guardrail_sanitizer_path: "Path traversal characters removed",
    guardrail_sanitizer_shell: "Shell metacharacters removed",
    guardrail_sanitizer_sql: "SQL injection characters removed",
    guardrail_sensitive_blocker: "  ✓ Sensitive Command Blocker",
    guardrail_sensitive_cmd: "Blocked sensitive command pattern: {pattern}",
    handshake_failed: "Handshake failed",
    handshake_failed_log: "Handshake failed",
    handshake_successful: "MCP handshake successful",
    high_average_response_time: "High average response time",
    high_memory_usage: "High memory usage",
    html_label: "HTML",
    http_response: "HTTP Response",
    if_the_tool_accepts_any_input_define_a_strict_inpu:
      "If the tool accepts any input, define a strict input schema. If it runs predefined queries only, document this in the description.",
    implement_1_rate_limiting_on_login_attempts_2_acco:
      "Implement: (1) Rate limiting on login attempts, (2) Account lockout after failed attempts, (3) Consider MFA support.",
    implement_complexity_requirements_uppercase_lowerc:
      "Implement complexity requirements: uppercase, lowercase, numbers, special characters.",
    implement_log_redaction_for_sensitive_fields_never:
      "Implement log redaction for sensitive fields. Never log passwords, API keys, credit cards, or PII.",
    implement_strict_validation_pattern_for_this_sensi:
      "Implement strict validation pattern for this sensitive field.",
    implement_strict_validation_ssn_d3d2d4_email_rfc_5:
      "Implement strict validation: SSN: ^\\d{3}-\\d{2}-\\d{4}$, Email: RFC 5322 compliant",
    info_cloud_caution:
      "   Be cautious on cloud infrastructure (AWS EC2, GCP instances)",
    info_direct_exec: "   Commands will execute directly on your system",
    info_local_safe: "   This is safe for local development",
    info_trust_only: "   Only use with servers you trust",
    initializing: "Initializing system...",
    input_received: "Input received.",
    interactive_about_desc:
      "Enterprise-grade security validation & testing tool for MCP servers.",
    interactive_about_desc_title: "About mcp-verify",
    interactive_about_title: "About mcp-verify",
    interactive_available_commands: "Available Commands",
    interactive_available_keys: "Available keys",
    interactive_available_languages: "Available languages",
    interactive_commands: "commands",
    interactive_config: "Configuration",
    interactive_config_title: "Current Configuration",
    interactive_current_language: "Current Language",
    interactive_did_you_mean: "Did you mean",
    interactive_empty: "(empty)",
    interactive_examples: "Examples",
    interactive_features: "Features",
    interactive_history_title: "Command History",
    interactive_invalid_language: "Invalid language",
    interactive_language_changed_to: "Language changed to",
    interactive_links: "Links",
    interactive_open_github_desc: "Open Fink's GitHub",
    interactive_open_linkedin_desc: "Open Fink's LinkedIn",
    interactive_open_website_desc: "Open website",
    interactive_playground: "Interactive Playground",
    interactive_set_target_desc: "Set default target",
    interactive_shell: "Interactive Shell",
    interactive_show_config_desc: "Show config",
    cmd_target_desc: "Set or show current target",
    cmd_profile_desc: "Manage security profiles (light/balanced/aggressive)",
    cmd_context_desc: "Manage multi-context workspace",
    cmd_status_desc: "Show workspace status",
    profile_help_title: "Profile Commands:",
    profile_help_set: "Switch to a profile",
    profile_help_save: "Save current settings as custom profile",
    profile_help_list: "List all available profiles",
    profile_help_show: "Show current profile details",
    interactive_show_history_desc: "Show history",
    interactive_social: "Social & Info",
    interactive_tab_hint: "Use Tab for command autocompletion",
    interactive_target_example: "Example: validate node server.js",
    interactive_target_required: "You need to specify a target",
    interactive_target_set: "Target set",
    interactive_to_change: "To change",
    interactive_tools: "Tools",
    interactive_type_help: 'Type "help" for commands, "exit" to quit.',
    interactive_unknown_command: "Unknown command",
    interactive_usage: "Usage",
    interactive_help_reference: "Command Reference",
    interactive_help_change_tab: "Change Tab",
    interactive_help_close: "Close Help",
    interactive_utilities: "Utilities",
    help_category_infra: "Infrastructure",
    invalid_command_format: "Invalid command format",
    invalid_json: "Server returned invalid JSON",
    invalid_option: "Invalid option / Opción inválida\n",
    invalid_regex_pattern: "Invalid regex pattern",
    invalid_selection: "Invalid selection.",
    invalid_url_format: "Invalid URL format",
    is_listening_port:
      "Is it listening on the right port? (netstat -an | grep LISTEN)",
    is_process_started: "Is the process started? (ps aux | grep your-server)",
    json_label: "JSON",
    jsonrpc_failed: "JSON-RPC call failed for method {method}",
    jsonrpc_violations: "JSON-RPC Standard Violations Detected:",
    label_docs: "Docs:",
    label_issues: "Issues:",
    label_run: "Run:",
    language_label: "Language",
    latency_avg: "Latency (Avg)",
    latency_distribution: "Latency",
    latency_max: "Latency (Max)",
    latency_p95: "Latency (P95)",
    latest_stderr_output: "Latest stderr output:",
    linkedin_label: "LinkedIn",
    listen_label: "Listen",
    llm_api_key_invalid:
      "API key is invalid or expired. Check your environment variables.",
    llm_continuing_without: "   Continuing without LLM analysis...",
    llm_example_anthropic: "     --llm anthropic:claude-haiku-4-5-20251001",
    llm_example_ollama: "     --llm ollama:llama3.2",
    llm_example_openai: "     --llm openai:gpt-4o-mini",
    llm_examples_block:
      "Examples:\n  --llm anthropic:claude-haiku-4-5-20251001  (requires ANTHROPIC_API_KEY)\n  --llm ollama:llama3.2                      (requires Ollama server)\n  --llm openai:gpt-4o-mini                   (requires OPENAI_API_KEY)",
    llm_examples_header: "   Examples:",
    llm_no_description: "No description provided",
    llm_no_prompts: "No prompts found",
    llm_no_provider_specified:
      "No LLM provider specified. Use --llm flag to enable AI analysis.",
    llm_no_resources: "No resources found",
    llm_no_tools: "No tools found",
    llm_rate_limit: "Rate limit exceeded. Please try again later.",
    llm_request_timeout:
      "LLM request timeout. Try increasing timeout or using a faster model.",
    llm_semantic_check_deprecated:
      "⚠️  --semantic-check is deprecated. Use --llm flag instead",
    llm_analysis_using: "LLM analysis using {provider}",
    baseline_not_found: "Baseline file not found at {path}",
    baseline_not_found_tip:
      "Run with --save-baseline to create one first: mcp-verify validate --save-baseline {path}",
    baseline_new_critical: "{count} new CRITICAL findings detected!",
    baseline_new_high: "{count} new HIGH findings detected.",
    baseline_findings_fixed: "{count} findings were fixed!",
    load_testing: "Load Testing",
    logs_appear_below: "Logs will appear below (Ctrl+C to stop)",
    markdown_label: "Markdown",
    mask_or_redact_sensitive_fields_in_responses_retur:
      "Mask or redact sensitive fields in responses. Return only necessary data. Implement field-level encryption if needed.",
    mcp_protocol: "MCP Protocol",
    security_score_explanation:
      "This score measures technical attack surface indicators, not business logic security or production readiness.",
    md_description: "Description",
    md_executive_security_report: "Executive Security Report",
    missing_description: "Missing description",
    missing_message_param:
      "Missing message parameter (SSE transport expects ?message=JSON)",
    mock_server: "Mock Server for Testing",
    mock_server_running: "Mock MCP Server running at",
    mock_received: "Mock server received request: {method}",
    multiple_consecutive_quantifiers: "Multiple consecutive quantifiers",
    need_help: "Need more help?",
    nested_quantifiers_detected_eg_a:
      "Nested quantifiers detected (e.g., (a+)+)",
    no_config_file_found_using_defaults:
      "No config file found, using defaults.",
    no_http_response: "No HTTP response",
    no_input_parameters_defined: "No input parameters defined",
    no_tools_prompts: "No tools or prompts found on this server.",
    not_found: "Not Found",
    not_http_url: "Not an HTTP URL (stdio mode?)",
    openai_api_key_not_configured: "OpenAI API key not configured",
    openai_invalid_key_format:
      "[OpenAI] Invalid API key format. Expected: sk-...",
    opening: "Opening",
    opening_editor: "Opening editor... (Close file to save)",
    option_allowed_score_drop_desc:
      "Allow score drop up to this amount (default: 5)",
    option_compare_baseline_desc: "Compare against baseline and show delta",
    option_concurrent_users: "Concurrent users",
    option_dashboard_port: "Dashboard port",
    option_enable_fuzzing: "Enable Smart Fuzzing (Chaos Testing)",
    option_fuzz_concurrency: "Number of concurrent requests",
    option_fuzz_timeout: "Timeout per request in ms",
    option_fuzz_tool: "Target tool name to fuzz",
    option_fuzz_generators:
      "Generators to use (prompt,json-rpc,schema,classic,sqli,xss,cmd,path,ssrf,xxe,nosql,ssti,jwt,proto,time-based,all)",
    option_fuzz_detectors:
      "Detectors to use (prompt-leak,jailbreak,protocol,path-traversal,weak-id,info,timing,all)",
    option_fuzz_format: "Report format (json, html, both)",
    option_fuzz_format_sarif: "Report format (json, html, sarif, all)",
    option_http_header:
      'HTTP header for authentication (e.g., "Authorization: Bearer token")',
    option_fuzz_param: "Target parameter name to inject payloads",
    option_fuzz_stop_on_first: "Stop on first vulnerability found",
    option_fuzz_fingerprint:
      "Enable server fingerprinting to auto-disable irrelevant generators",
    fingerprint_results: "Fingerprint Results",
    fingerprinting_target:
      "Fingerprinting target to optimize payload selection...",
    option_env_variables: "Environment variables (KEY=VALUE)",
    option_fail_on_degradation_desc:
      "Exit with code 2 if scores degrade from baseline",
    option_generate_html: "Generate HTML",
    option_generate_md: "Generate Markdown",
    option_generate_json: "Generate JSON",
    option_json_stdout_desc:
      "Output JSON to stdout for piping (also saves files to reports/)",
    option_lang_desc: "Force language (en, es)",
    option_list_only: "Only list capabilities and exit",
    option_llm_desc:
      "LLM provider for semantic analysis (e.g., anthropic:claude-haiku-4-5-20251001, ollama:llama3.2, openai:gpt-4o-mini)",
    option_no_color_desc: "Disable colored output",
    option_output_directory: "Output directory",
    option_port_listen: "Port to listen on",
    option_proxy_timeout: "Auto-stop the proxy after MS milliseconds",
    option_quiet_desc:
      "Suppress spinners and info messages (keeps errors and final output)",
    option_scan_all_configs:
      "Scan all MCP config files in project (.mcp.json, .claude/settings.json)",
    option_report_format: "Report format (json, sarif)",
    option_sandbox:
      "Execute server in isolated sandbox (Node/Deno only). For Python/Go, use --no-sandbox for static analysis only",
    option_save_baseline_desc:
      "Save current report as baseline for future comparisons",
    option_watch_desc: "Monitor environment and server in real-time",
    option_verbose_doctor_desc: "Show detailed diagnostic steps",
    option_show_history_desc: "Display integrity history (last 20 builds)",
    option_fix_integrity_desc:
      "Regenerate integrity manifest without full rebuild",
    option_clean_history_desc: "Keep only last N builds in history",
    option_save_scan: "Save scan to history for regression detection",
    option_semantic_check_desc:
      "Enable LLM-powered semantic analysis (requires API key)",
    option_test_duration: "Test duration",
    option_transport_stdio_http: "Transport type (http or stdio)",
    option_transport_type: "Transport type",
    option_verbose_logging: "Enable verbose logging",
    overlapping_alternation_detected_eg_aab:
      "Overlapping alternation detected (e.g., (a|ab)+)",
    passwords_can_be_cracked_easily_with_rainbow_table:
      "Passwords can be cracked easily with rainbow tables or brute force",
    path_security_output: "Invalid output path: {path}",
    path_security_baseline: "Invalid baseline path: {path}",
    path_security_baseline_req:
      "Baselines must be stored within your project for security.",
    path_security_traversal:
      "This could be a path traversal attack. Only paths within the output directory are permitted.",
    performance_report: "Performance Report",
    play_finding: "Test a specific tool",
    playground_invalid_json: "Invalid JSON!",
    port_check: "Port Check",
    print: "Print",
    port_not_reachable: "Port is not reachable or server is down",
    port_reachable: "Port {port} is reachable.",
    potential_excessive_backtracking: "Potential excessive backtracking",
    potentially_dangerous_pattern: "Potentially dangerous pattern",
    press_ctrl_c: "Press Ctrl+C to stop the server",
    project_label: "Project",
    prompt_label: "Prompt",
    protocol_compliance: "Protocol Compliance",
    protocol_error: "Protocol error",
    proxy_active: "MCP Proxy Active at",
    proxy_invalid_json: "Invalid JSON",
    proxy_port_in_use: "Port already in use",
    proxy_port_tip: "Please use --port to specify a different port",
    proxy_auto_stopping: "Proxy will auto-stop in {ms}ms.",
    quality_mimetype_suggestion:
      'Add a mimeType (e.g. "text/plain") to help the LLM understand how to read it.',
    quality_param_missing_desc: 'Parameter "{param}" is missing a description.',
    quality_param_desc_suggestion:
      'Add a detailed description for parameter "{param}" to improve semantic understanding.',
    quality_score: "Quality Score",
    rate_limit_config_options: "\nConfiguration options:",
    rate_limit_guideline_auth:
      "- Authentication: 5-10 attempts per minute per IP\n- Add exponential backoff after failed attempts\n- Implement account lockout after 5-10 failures",
    rate_limit_guideline_compute:
      "- Compute-intensive: 10 requests per minute\n- Implement job queuing for heavy processing",
    rate_limit_guideline_db:
      "- Database queries: 100 requests per minute per user\n- Implement query result caching",
    rate_limit_guideline_file:
      "- File uploads: 10 files per hour, max 10MB per file\n- Implement upload quotas per user",
    rate_limit_guideline_net:
      "- External API calls: 10-60 requests per minute\n- Implement request queuing and retry logic",
    rate_limit_option_docs: "- Document rate limits in tool description",
    rate_limit_option_extension: "- Add x-rate-limit extension to tool schema",
    rate_limit_option_header:
      "- Return 429 Too Many Requests with Retry-After header",
    received_signal: "Received signal",
    recommendations: "Recommendations",
    redirecting_to: "Redirecting to",
    reduce_users: "Reduce concurrent users: --users 5",
    remediation_cmd_injection_strengthen:
      "Strengthen the regex to strictly exclude shell metacharacters like ; & | ` $ ( ) < >",
    remediation_cmd_injection_whitelist:
      "Implement a strict whitelist regex (e.g., ^[a-zA-Z0-9]+$) to prevent shell metacharacter injection.",
    remediation_deserialization_all:
      "Implement: (1) Schema validation, (2) Type whitelisting, (3) Integrity checks (HMAC/signatures), (4) Avoid deserializing untrusted data when possible.",
    remediation_deserialization_encoded:
      "Validate decoded data structure. Never deserialize base64-decoded data without verification.",
    remediation_deserialization_explicit:
      "Define explicit type (string, object with properties) and validate against a schema.",
    remediation_deserialization_properties:
      "Define allowed properties in schema or set additionalProperties: false.",
    remediation_deserialization_strict:
      "Define a strict input schema with expected types. Implement schema validation before deserialization.",
    remediation_deserialization_yaml:
      "Use yaml.safe_load() instead of yaml.load() or yaml.unsafe_load().",
    remediation_plain_credentials:
      'Ensure credentials are transmitted over HTTPS only. Consider using format: "password" for sensitive fields.',
    remediation_prompt_injection_limit:
      "Implement maxLength to prevent long injection payloads.",
    remediation_prompt_injection_pattern:
      "Use a strict regex pattern to restrict allowed input.",
    remediation_prompt_injection_prompt_args:
      "Sanitize prompt arguments internally since MCP does not support schemas for them.",
    remediation_rate_limit_aggressive:
      "Implement aggressive rate limiting: 5-10 attempts per minute per IP. Add exponential backoff and account lockout after failures.",
    remediation_rate_limit_file:
      "Set maxLength or maxSize (e.g., 10MB max). Implement rate limiting on file uploads (e.g., 10 files per hour).",
    remediation_rate_limit_generic:
      "Implement rate limiting with the following guidelines:",
    remediation_redos_anchors:
      "Add anchors: ^pattern$ to ensure full string matching and prevent partial match abuse.",
    remediation_redos_simplify:
      "Simplify regex pattern to avoid nested quantifiers and overlapping alternations.",
    remediation_ssrf_restrict:
      "Restrict input to specific allowed domains using a strict regex pattern (e.g., ^https://api.example.com/).",
    remediation_ssrf_tighten:
      "Tighten regex to allow only specific schemas (https) and specific domains.",
    remediation_path_traversal_weak_pattern:
      "The current validation pattern for this path is weak ({pattern}). It should be more restrictive to prevent traversal.",
    remediation_user_enumeration:
      'Use generic error messages: "Invalid credentials" for both cases. Implement rate limiting.',
    remediation_xxe_critical:
      "CRITICAL: Disable external entities in parser AND add XML schema validation.",
    remediation_xxe_disable:
      "Disable external entities in XML parser. Set resolve_entities=False, load_dtd=False, no_network=True.",
    remediation_xxe_pattern:
      "Add pattern validation to restrict XML structure even with safe parser config.",
    remediation_xxe_strict:
      "Define input schema with XML validation. Explicitly disable external entities in your XML parser.",
    remediation_xxe_svg:
      "Sanitize SVG uploads by re-rendering or use a library like DOMPurify. Disable external entities in XML parser.",
    remediation_xxe_uploads:
      "Disable external entities before parsing uploaded XML files. Validate XML against a schema.",
    remediation_fuzzer_confirmed:
      "This vulnerability was CONFIRMED by dynamic fuzzing. Immediate remediation required. Review the evidence and implement input validation, output sanitization, or architectural changes.",
    remediation_prompt_injection_limit_enterprise:
      "Implement maxLength: {maxLength} to limit injection payload size. Consider implementing token-based limits for LLM contexts.",
    remediation_prompt_injection_pattern_specific:
      'Add pattern validation: "{pattern}" - {description}',
    remediation_prompt_injection_strengthen_pattern:
      "Current pattern is too permissive. Use a strict pattern that blocks injection markers like [INST], <<SYS>>, ###, etc.",
    remediation_prompt_injection_indirect:
      "This tool fetches external content. Implement: (1) URL/source validation, (2) Content sanitization before LLM processing, (3) Consider sandboxed content processing.",
    remediation_prompt_injection_chain:
      "CRITICAL: This tool both fetches AND processes external content. Implement: (1) Strict URL whitelist, (2) Content security policy, (3) Input/output boundaries, (4) Prompt isolation techniques.",
    remove_weak_algorithms_from_enum_only_allow_aes256:
      "Remove weak algorithms from enum. Only allow: AES-256, ChaCha20, SHA-256+, RSA-2048+.",
    replace_weak_hashing_with_bcrypt_argon2_or_scrypt:
      "Replace weak hashing with bcrypt, Argon2, or scrypt. Never use MD5, SHA1, or store passwords in plaintext.",
    replace_with_aes256gcm_chacha20poly1305_or_xchacha:
      "Replace with AES-256-GCM, ChaCha20-Poly1305, or XChaCha20-Poly1305.",
    replace_with_sha256_sha384_sha512_sha3_or_blake2bl:
      "Replace with SHA-256, SHA-384, SHA-512, SHA-3, or BLAKE2/BLAKE3.",
    req_sec: "req/sec",
    request_log: "Request",
    reproducer_desc: "Use this command to reproduce the exact same validation:",
    reproducer_title: "Reproduce This Scan",
    resolved_to: "Resolved to",
    resource_missing_mimetype: "Resource missing mimeType",
    resource_warnings_label: "Resource Warnings",
    response_log: "Response",
    result_label: "Result",
    risk_cmd_injection_unsanitized:
      "Unsanitized input in potential command execution context",
    risk_crypto_brute_force: "Keys < 128 bits can be brute-forced",
    risk_crypto_predictable:
      "Predictable random values can be exploited for key guessing",
    risk_crypto_weak_selection: "User can select weak/deprecated algorithms",
    risk_data_leakage_risky_file: "Risky file extension/name",
    risk_deserialization_encoded:
      "Hidden serialized objects in encoded strings",
    risk_deserialization_injection: "Arbitrary object injection",
    risk_deserialization_no_type: "No type validation on deserialized objects",
    risk_deserialization_properties:
      "Object injection with arbitrary properties",
    risk_deserialization_rce:
      "Remote Code Execution (RCE) during deserialization",
    risk_deserialization_yaml: "Arbitrary code execution via YAML tags",
    risk_level_critical: "Critical Risk",
    risk_level_high: "High Risk",
    risk_level_low: "Low Risk",
    risk_level_medium: "Medium Risk",
    risk_plain_credentials:
      "Credentials could be logged or leaked if not transmitted securely",
    risk_rate_limit_brute_force:
      "No protection against password brute-forcing or credential stuffing",
    risk_rate_limit_disk_space: "Unlimited file uploads can exhaust disk space",
    risk_rate_limit_exhaustion:
      "Unlimited requests can exhaust resources, cause DoS, or enable brute-force attacks",
    risk_redos_evaluation:
      "Malicious input can cause exponential regex evaluation time",
    risk_redos_partial: "Partial matches can be exploited with long inputs",
    risk_sensitive_invalid_format: "Invalid data format could be accepted",
    risk_sensitive_logging: "Sensitive data in logs could be exposed",
    risk_sensitive_no_format: "No format validation for sensitive data",
    risk_sensitive_response:
      "Sensitive data in responses could be logged or cached",
    risk_ssrf_arbitrary: "Arbitrary URL access",
    risk_user_enumeration:
      'Different error messages for "user not found" vs "wrong password" leak information',
    risk_weak_passwords: 'Weak passwords like "password123" could be accepted',
    risk_xxe_external_entities: "External entities or DTD processing enabled",
    risk_xxe_malicious_entities:
      "Unvalidated XML can contain malicious external entities",
    risk_xxe_svg: "SVG files can contain malicious XML entities",
    risk_xxe_unvalidated: "Unvalidated XML input with potential XXE",
    risk_xxe_uploads: "Uploaded XML files can exploit XXE vulnerability",
    risk_xxe_vulnerability:
      "XXE vulnerability - can read arbitrary files, SSRF, DoS",
    rpc_001: "Server did not return error for non-existent method",
    rpc_002: "Server returned empty error",
    rpc_003: 'Server accepted request missing "jsonrpc" field',
    run_basic_validation: "Run basic validation first",
    running_fuzzer: "Running Smart Fuzzer (Chaos Testing)...",
    running_protocol_tests: "Running protocol compliance tests...",
    running_security_scan: "Running security scan",
    runtime_security_gateway: "Runtime Security Gateway",
    sandbox_active:
      "🔒 Sandbox Active: Running server in isolated Deno environment.",
    sandbox_deno_only: "⚠️  This sandbox only supports Node.js/Deno servers.",
    sandbox_future_version: "   Future versions will support Python and Go.",
    sandbox_option_audit:
      "   1. Run with --no-sandbox (for audit/static analysis only, no execution):",
    sandbox_option_risky:
      "   2. Run WITHOUT sandbox (⚠️  RISKY - only for trusted servers):",
    sandbox_options_header: "Options:",
    sandbox_trust_notice:
      "⚠️  WARNING: --no-sandbox disables execution. Use only with trusted servers.",
    sandbox_unsupported_runtime: "   Detected runtime: {runtime}",
    sandbox_warning_title: "⚠️  SANDBOX LIMITATION",
    // Sandbox environment check messages
    sandbox_deno_not_found: "Deno binary not found in PATH",
    sandbox_install_deno:
      "Install Deno: curl -fsSL https://deno.land/install.sh | sh",
    sandbox_alt_docker:
      "Alternative: Use --sandbox=docker if Docker is available",
    sandbox_deno_version_too_old:
      "Deno version {current} is below minimum required {required}",
    sandbox_update_deno: "Update Deno: deno upgrade",
    sandbox_version_parse_failed: "Could not parse Deno version string",
    sandbox_version_check_failed: "Failed to check Deno version: {error}",
    sandbox_temp_not_writable: "Temp directory is not writable: {error}",
    sandbox_check_temp_perms: "Check permissions on your system temp directory",
    sandbox_ready: "✅ Deno sandbox ready (v{version})",
    sandbox_not_available: "⚠️  Deno sandbox is not available",
    sandbox_issues_header: "Issues detected:",
    sandbox_suggestions_header: "Suggestions:",
    sarif_label: "SARIF",
    schema_args: "Schema/Args",
    schema_compilation_failed: "Schema compilation failed",
    schema_dos_risk: "This schema is too complex and poses a DoS risk",
    schema_invalid_type: "Schema must be a non-null object",
    schema_missing_desc:
      'Schema lacks a "description" property (recommended for documentation)',
    schema_missing_keywords:
      'Schema missing required property: must have "type", "$ref", or composition keywords (allOf/anyOf/oneOf)',
    schema_permissive_props:
      "Schema allows additional properties, which may accept unexpected data",
    schema_permissive_string:
      "String schema has no pattern, format, or enum constraint",
    schema_remote_refs:
      "Schema contains remote $ref (external URLs are blocked for security)",
    schema_compilation_took:
      "Schema compilation took {elapsed}ms (threshold: {threshold}ms)",
    schema_dangerous_html: "Schema path {path} allows dangerous HTML content.",
    schema_dangerous_sql: "Schema path {path} allows dangerous SQL content.",
    score: "Score",
    sec_auth_bypass_desc:
      "Detects tools that might allow bypassing authentication mechanisms.",
    sec_auth_bypass_name: "Authentication Bypass",
    sec_command_injection_desc:
      "Detects tools that might execute system commands without proper input sanitization.",
    sec_command_injection_name: "Command Injection Detection",
    sec_data_leakage_desc:
      "Detects exposure of sensitive data like API keys or PII.",
    sec_data_leakage_name: "Data Leakage Detection",
    sec_insecure_deserialization_desc:
      "Detects unsafe deserialization of untrusted data.",
    sec_insecure_deserialization_name: "Insecure Deserialization",
    sec_path_traversal_desc:
      "Detects attempts to access files outside the intended directory.",
    sec_path_traversal_name: "Path Traversal Detection",
    sec_prompt_injection_name: "Prompt Injection Detection",
    sec_prompt_injection_desc:
      "Detects potential prompt injection vectors in tools and prompts.",
    finding_path_traversal_no_pattern: "No path validation pattern detected",
    remediation_path_traversal_add_pattern:
      "Implement path validation to prevent directory traversal attacks",
    sec_rate_limiting_desc: "Checks if rate limiting mechanisms are in place.",
    sec_rate_limiting_name: "Rate Limiting",
    sec_redos_desc:
      "Detects Regular Expression Denial of Service vulnerabilities.",
    sec_redos_name: "ReDoS Detection",
    sec_sensitive_exposure_desc:
      "Detects tools that expose sensitive system information.",
    sec_sensitive_exposure_name: "Sensitive Data Exposure",
    sec_sql_injection_desc:
      "Detects potential SQL injection vectors in database tools.",
    sec_sql_injection_name: "SQL Injection Detection",
    sec_ssrf_desc:
      "Detects potential Server-Side Request Forgery vulnerabilities.",
    sec_ssrf_name: "SSRF Detection",
    sec_weak_crypto_desc: "Detects usage of weak cryptographic algorithms.",
    sec_weak_crypto_name: "Weak Cryptography",
    sec_xxe_desc:
      "Detects XML External Entity vulnerabilities in input processing.",
    sec_xxe_name: "XXE Injection Detection",
    sec_exposed_endpoint_name: "Exposed Network Endpoint",
    sec_exposed_endpoint_desc:
      "Detects servers exposed on public network interfaces without proper protection.",
    sec_missing_auth_name: "Missing Authentication",
    sec_missing_auth_desc:
      "Detects servers and tools lacking authentication mechanisms.",
    // SEC-014: Exposed Endpoint findings
    finding_exposed_endpoint_dev_mode:
      "Server appears to be running in development/debug mode",
    finding_exposed_endpoint_public_binding:
      "Tool {tool} configures server to bind on public interface (0.0.0.0 or ::)",
    finding_exposed_endpoint_no_protection:
      "Tool {tool} handles network configuration without protection indicators",
    finding_exposed_endpoint_param_default:
      "Parameter {param} has dangerous default value: {value}",
    finding_exposed_endpoint_param_allows:
      "Parameter {param} allows dangerous values: {values}",
    finding_exposed_endpoint_param_no_validation:
      "Network parameter {param} lacks validation pattern",
    // SEC-014: Exposed Endpoint risks
    risk_exposed_endpoint_dev:
      "Development servers often have debug features and relaxed security",
    risk_exposed_endpoint_unauthorized_access:
      "Any network-accessible client can connect and execute tools",
    risk_exposed_endpoint_unprotected:
      "Server exposed without firewall or network-level protection",
    risk_exposed_endpoint_default_public:
      "Default configuration exposes server to entire network",
    risk_exposed_endpoint_configurable:
      "User can configure server to bind on public interfaces",
    // SEC-014: Exposed Endpoint attack vectors
    attack_vector_direct_jsonrpc:
      "Direct JSON-RPC calls bypassing intended clients",
    attack_vector_prompt_injection:
      "Prompt injection via network-accessible endpoints",
    attack_vector_tool_abuse: "Unauthorized tool execution and resource abuse",
    // SEC-014: Exposed Endpoint remediation
    remediation_exposed_endpoint_prod_config:
      "Use production-ready configuration. Disable debug features. Bind to 127.0.0.1 for local-only access.",
    remediation_exposed_endpoint_localhost:
      "Bind to 127.0.0.1 (localhost) instead of 0.0.0.0. Only expose on public interfaces if absolutely required with proper authentication and firewall rules.",
    remediation_exposed_endpoint_add_protection:
      "Implement network protection: firewall rules, IP allowlisting, VPN requirement, or authentication.",
    remediation_exposed_endpoint_safe_default:
      "Change default to 127.0.0.1 (localhost). Document security implications if users must change it.",
    remediation_exposed_endpoint_restrict_enum:
      "Remove public interface options from enum. Only allow localhost (127.0.0.1) and private network IPs.",
    remediation_exposed_endpoint_add_validation:
      "Add validation pattern to restrict to safe IP addresses (127.0.0.1, 10.x.x.x, 192.168.x.x).",
    // SEC-015: Missing Authentication findings
    finding_missing_auth_server:
      "Server does not implement authentication mechanism",
    finding_missing_auth_admin_tool:
      "Administrative tool {tool} lacks authentication",
    finding_missing_auth_sensitive_tool:
      "Tool {tool} performs sensitive operations ({ops}) without authentication",
    finding_missing_auth_insecure_param:
      "Authentication parameter {param} transmitted insecurely",
    finding_missing_auth_not_marked_sensitive:
      "Authentication parameter {param} not marked as sensitive",
    // SEC-015: Missing Authentication risks
    risk_missing_auth_unauthorized_access:
      "Any client can connect and execute all tools without authentication",
    risk_missing_auth_privilege_escalation:
      "Unauthorized users can execute administrative operations",
    risk_missing_auth_data_breach:
      "Unrestricted access to sensitive data and operations",
    risk_missing_auth_logged_credentials:
      "Credentials in query/path parameters are logged in server logs and proxy caches",
    // SEC-015: Missing Authentication impacts
    impact_missing_auth_full_control:
      "Complete control over server functionality by any network-accessible client",
    // SEC-015: Missing Authentication remediation
    remediation_missing_auth_implement:
      "Implement server-level authentication using API keys, OAuth 2.0, or mutual TLS (mTLS).",
    remediation_missing_auth_tool_level:
      "Implement tool-level authentication checks. Validate user permissions before executing sensitive operations.",
    remediation_missing_auth_server_level:
      "Implement server-level authentication to protect all tools:",
    remediation_missing_auth_tool_specific:
      "Add tool-specific authorization checks even when server-level auth exists.",
    remediation_missing_auth_header_only:
      "Transmit authentication credentials only in HTTP headers (Authorization, X-API-Key), never in query parameters or path.",
    remediation_missing_auth_mark_sensitive:
      'Mark authentication parameters with format: "password" or add "x-sensitive": true extension.',
    // SEC-015: Missing Authentication options
    auth_option_api_key:
      "- API Key: Require X-API-Key header with secure token (min 32 bytes random)",
    auth_option_oauth:
      "- OAuth 2.0: Use Bearer token authentication with JWT validation",
    auth_option_mtls: "- mTLS: Mutual TLS with client certificate validation",
    // SEC-015: Missing Authentication guidelines
    auth_guideline_admin:
      "- Administrative operations: Require role-based access control (RBAC) with admin role",
    auth_guideline_deletion:
      "- Data deletion: Require explicit confirmation + elevated permissions",
    auth_guideline_modification:
      "- Data modification: Validate write permissions for specific resources",
    auth_guideline_sensitive:
      "- Sensitive data access: Implement field-level access control",
    auth_implementation_note:
      "\nImplementation: Add authentication middleware that validates credentials before routing to tool handlers.",

    // SEC-016: Insecure URI Scheme Detection
    sec_insecure_uri_name: "Insecure URI Scheme Detection",
    sec_insecure_uri_desc:
      "Detects use of dangerous or unencrypted URI schemes in resources.",
    finding_insecure_uri_scheme:
      "Resource {resource} uses insecure URI scheme: {scheme}",
    finding_insecure_uri_malformed: "Resource {resource} has malformed URI",
    finding_insecure_uri_file_scheme:
      "Resource {resource} uses file:// scheme (potential path traversal)",
    finding_insecure_uri_credentials:
      "Resource {resource} contains credentials in URI",
    risk_insecure_uri_file_traversal:
      "File scheme allows path traversal attacks",
    risk_insecure_uri_exposed_creds:
      "Credentials in URI are exposed in logs and browser history",
    remediation_insecure_uri_fix_format: "Fix URI format to valid syntax",
    remediation_insecure_uri_use_secure: "Use secure alternative: {scheme}",
    remediation_insecure_uri_file_validate:
      "Validate file paths and restrict access to allowed directories",
    remediation_insecure_uri_remove_creds:
      "Remove credentials from URI. Use secure authentication headers instead.",

    // SEC-017: Excessive Tool Permissions
    sec_excessive_perms_name: "Excessive Tool Permissions",
    sec_excessive_perms_desc:
      "Detects tools with overprivileged access violating least privilege principle.",
    finding_excessive_perms_detected:
      "Tool {tool} has excessive permissions (risk score: {score})",
    finding_excessive_perms_destructive_unrestricted:
      "Tool {tool} combines destructive operations with unrestricted access",
    finding_excessive_perms_param_all:
      "Parameter {param} in tool {tool} uses overly permissive naming (all/any)",
    risk_excessive_perms_privilege_escalation:
      "Privilege escalation through overprivileged tools",
    risk_excessive_perms_data_loss:
      "Destructive operations without restrictions can cause data loss",
    remediation_excessive_perms_least_privilege:
      "Apply principle of least privilege: limit tool permissions to minimum required, implement role-based access control",
    remediation_excessive_perms_split_permissions:
      "Split into separate tools with specific, limited permissions",
    remediation_excessive_perms_specific_params:
      'Use specific parameter names instead of generic "all" or "any"',

    // SEC-018: Sensitive Data in Tool Descriptions
    sec_secrets_desc_name: "Sensitive Data in Tool Descriptions",
    sec_secrets_desc_desc:
      "Detects sensitive information leaked in tool descriptions and parameters.",
    finding_secrets_desc_detected:
      "{type} detected in {location} for tool {tool}",
    finding_secrets_desc_keywords:
      "Sensitive keywords found in {location} for tool {tool}",
    risk_secrets_desc_disclosure: "Information disclosure to LLM and end users",
    remediation_secrets_desc_remove:
      "Remove {type} from descriptions. Use placeholder values in examples.",
    remediation_secrets_desc_review:
      "Review descriptions for sensitive information and replace with generic examples",

    // SEC-019: Missing Input Constraints
    sec_missing_constraints_name: "Missing Input Constraints",
    sec_missing_constraints_desc:
      "Detects parameters lacking validation constraints (maxLength, pattern, bounds).",
    finding_missing_constraints_maxlength:
      "Parameter {param} in tool {tool} lacks maxLength constraint",
    finding_missing_constraints_pattern:
      "Parameter {param} in tool {tool} lacks pattern validation",
    finding_missing_constraints_minimum:
      "Parameter {param} in tool {tool} lacks minimum bound",
    finding_missing_constraints_maximum:
      "Parameter {param} in tool {tool} lacks maximum bound",
    finding_missing_constraints_maxitems:
      "Array parameter {param} in tool {tool} lacks maxItems constraint",
    finding_missing_constraints_maxprops:
      "Object parameter {param} in tool {tool} lacks maxProperties or properties definition",
    risk_missing_constraints_dos:
      "Denial of Service via extremely large inputs",
    risk_missing_constraints_overflow: "Integer overflow vulnerabilities",
    risk_missing_constraints_memory: "Memory exhaustion with unbounded arrays",
    remediation_missing_constraints_add_maxlength:
      "Add maxLength constraint (recommended: {recommended} bytes or less)",
    remediation_missing_constraints_add_pattern:
      "Add pattern validation using regular expressions",
    remediation_missing_constraints_add_bounds:
      "Add minimum and maximum bounds for numeric values",
    remediation_missing_constraints_add_maxitems:
      "Add maxItems constraint (recommended: {recommended} items or less)",
    remediation_missing_constraints_define_schema:
      "Define explicit properties schema or add maxProperties limit",

    // SEC-020: Dangerous Tool Chaining
    sec_tool_chaining_name: "Dangerous Tool Chaining Potential",
    sec_tool_chaining_desc:
      "Detects tools that generate executable code or accept unsanitized input from other tools.",
    finding_tool_chaining_potential:
      "Server has {codeGenCount} code generation tools and {execCount} execution tools (chaining risk)",
    finding_tool_chaining_codegen_no_safety:
      "Code generation tool {tool} lacks safety warnings",
    finding_tool_chaining_dynamic_gen:
      "Tool {tool} generates code from dynamic inputs: {params}",
    risk_tool_chaining_injection:
      "Chaining code generation with execution enables injection attacks",
    risk_tool_chaining_unsafe_output:
      "Generated code may contain malicious content without validation",
    risk_tool_chaining_template_injection:
      "Template injection via dynamic code generation",
    remediation_tool_chaining_validate:
      "Validate and sanitize all tool outputs before passing to execution tools",
    remediation_tool_chaining_add_warning:
      'Add explicit warning in description: "Output must be validated before execution"',
    remediation_tool_chaining_sanitize_input:
      "Sanitize template inputs to prevent injection attacks",

    // SEC-021: Unencrypted Credential Storage
    sec_unencrypted_creds_name: "Unencrypted Credential Storage",
    sec_unencrypted_creds_desc:
      "Detects tools that store credentials without encryption or secure storage.",
    finding_unencrypted_creds_explicit:
      "Tool {tool} explicitly stores credentials using insecure methods: {methods}",
    finding_unencrypted_creds_no_security:
      "Tool {tool} stores {credTypes} without mentioning encryption",
    finding_unencrypted_creds_base64:
      "Tool {tool} uses base64 encoding (NOT encryption) for credentials",
    finding_unencrypted_creds_param:
      "Parameter {param} in tool {tool} stores credentials without security measures",
    risk_unencrypted_creds_plaintext:
      "Plaintext credential storage exposes secrets to attackers",
    risk_unencrypted_creds_exposure:
      "Credential exposure via database compromise or file access",
    risk_unencrypted_creds_encoding_not_encryption:
      "Base64 is encoding, not encryption - provides no security",
    risk_unencrypted_creds_param_storage:
      "Parameter stores credentials without protection",
    remediation_unencrypted_creds_encrypt:
      "Use AES-256 or stronger encryption for stored credentials",
    remediation_unencrypted_creds_implement:
      "Implement secure credential storage: use OS keychain, encrypted vault, or hashing (bcrypt/scrypt) for passwords",
    remediation_unencrypted_creds_real_encryption:
      "Replace base64 encoding with real encryption (AES-256-GCM)",
    remediation_unencrypted_creds_param_secure:
      "Add encryption/hashing for credential storage in this parameter",

    security_scan: "Security Scan",
    select_item_or_exit: 'Select item (number) or "exit"',
    select_option: "Select an option",
    selected: "Selected",
    semantic_issues: "semantic issues found (check report)",
    server: "Server",
    server_no_mcp: "Server responds but does not support MCP protocol",
    server_not_running: "Server is not running or wrong port",
    server_reachable_not_http: "Server is reachable but not responding to HTTP",
    server_responded: "Server responded with",
    server_slow: "Server is taking too long to respond",
    set_minimum_key_length_to_256_bits_for_symmetric_e:
      "Set minimum key length to 256 bits for symmetric encryption, 2048 bits for RSA.",
    set_minlength_to_at_least_8_characters_preferably:
      "Set minLength to at least 8 characters, preferably 12 or more.",
    shorten_duration: "Shorten test duration: --duration 10",
    simulating_load: "Simulating load",
    starting_stress_test: "Starting stress test...",
    strengthen_the_regex_to_strictly_exclude_sql_metac:
      "Strengthen the regex to strictly exclude SQL metacharacters like '",
    stress_test_complete: "Stress test complete!",
    stress_test_error: "Stress Test Error",
    stress_test_failed_msg: "Stress test failed",
    stress_high_cpu: "HIGH CPU USAGE: Peak {peak}%, Average {avg}%",
    stress_high_memory:
      "HIGH MEMORY USAGE: Peak {peak}%, Average {avg}% (Min available: {avail}MB)",
    stress_low_memory:
      "CRITICAL LOW MEMORY: Only {avail}MB available during test",
    editor_exited_with_code: "Editor exited with code {code}",
    // Fuzz command
    initializing_fuzzer: "Initializing fuzzer...",
    fuzzing_progress: "Fuzzing",
    vulnerability_found: "Vulnerability found",
    fuzz_session_summary: "Fuzz Session Summary",
    vulnerabilities_detected: "Vulnerabilities Detected",
    fuzz_complete_vulns_found: "Fuzzing complete - vulnerabilities found",
    fuzz_complete_no_vulns: "Fuzzing complete - no vulnerabilities detected",
    errors_during_fuzzing: "Errors during fuzzing",
    fuzz_failed: "Fuzzing failed",
    fuzz_error: "Fuzz Error",
    no_generators_selected: "No generators selected",
    no_detectors_selected: "No detectors selected",
    connecting_to_target: "Connecting to target...",
    discovering_schema: "Discovering tool schema...",
    starting_fuzz_session: "Starting fuzz session",
    check_server_running: "Check if the server is running",
    try_doctor_command: "Try the doctor command first",
    reduce_concurrency: "Try reducing concurrency",
    success_label: "Success",
    success_rate: "Success Rate",
    suggestions: "Suggestions",
    system_diagnostic: "System Diagnostic",
    target_label: "Target",
    test_servers: "Test Servers",
    testing_handshake: "Testing protocol handshake...",
    tests_label: "tests",
    throughput: "Throughput",
    timeout_error: "Timeout",
    tip_auth_creds: "Check authentication credentials",
    tip_check_implementation: "Check server implementation",
    tip_check_logs: "Check server logs for errors",
    tip_check_permissions: "Ensure you have permission to access this server",
    tip_check_process: "Check if server process is active",
    tip_check_process_generic:
      "Check if the server is running: ps aux | grep node",
    tip_check_server: "Check that your server is running:",
    tip_check_spelling: "Check spelling of the hostname",
    tip_increase_timeout: "Increase timeout with --timeout 10000",
    tip_increase_timeout_30: "Try increasing timeout: --timeout 30000",
    tip_ping_hostname: "Verify DNS is working (ping hostname)",
    tip_protocol_mismatch:
      "The server might not implement MCP protocol correctly",
    tip_run_doctor: "Run diagnostics for detailed analysis:",
    tip_slow_server: "The server might be slow or overloaded",
    tip_try_transport: "Try using a different transport:",
    tip_use_ip: "Try using an IP address instead of hostname",
    tip_use_verbose_raw: "Use --verbose to see raw response",
    tip_verbose: "Run with --verbose for more details",
    tip_verify_dns_generic:
      "Verify that host {host} is reachable (ping {host})",
    tip_verify_mcp_server: "Verify the server is an MCP server (not HTTP API)",
    tip_verify_port: "Verify port number is correct",
    tip_verify_tokens: "Verify API keys or tokens are correct",
    tip_verify_url: "Verify the URL is correct:",
    tool_label: "Tool",
    total_requests: "Total Requests",
    troubleshooting_tips: "Troubleshooting Tips",
    try_different_transport: "Try different transport: -t stdio or -t http",
    try_ping: "Try: ping",
    try_prefix: "Try:",
    try_running: "Try running",
    type_editor: 'Type ".editor" to open external editor',
    type_lang_to_change: ' (type "lang" to change)',
    type_simple_json: 'Type simple JSON directly (e.g. {"key": "val"})',
    unclear_if_passwords_are_stored_securely:
      "Unclear if passwords are stored securely",
    unclear_if_strong_cryptography_is_used:
      "Unclear if strong cryptography is used",
    config_using_path: "   Using configuration from: {path}",
    config_using_default: "   Using default configuration",
    config_load_error: "⚠️  Config load error (using defaults):",
    unexpected_error: "Unexpected error occurred",
    unknown: "Unknown",
    unknown_compilation_failure: "Unknown compilation failure",
    unknown_key: "Unknown key",
    unsanitized_input_in_sql_query_context:
      "Unsanitized input in SQL query context",
    update_description_to_explicitly_state_that_extern:
      "Update description to explicitly state that external entities are disabled. Configure XML parser with: resolve_entities=False, load_dtd=False, no_network=True.",
    update_tool_description_to_explicitly_state_use_of:
      "Update tool description to explicitly state use of prepared statements, ORMs, or query builders. Never concatenate user input into SQL strings.",
    upgrade_to_aes256_or_rsa2048_minimum:
      "Upgrade to AES-256 or RSA-2048+ minimum.",
    upgrade_to_sha256_or_stronger: "Upgrade to SHA-256 or stronger.",
    upstream_error: "Upstream error",
    url_format: "URL Format",
    use_cryptographically_secure_random_number_generat:
      "Use cryptographically secure random number generator (CSPRNG): crypto.randomBytes(), secrets module, or /dev/urandom.",
    use_prepared_statements_with_placeholders_and_impl:
      "Use prepared statements with placeholders AND implement strict input validation (e.g., ^[a-zA-Z0-9_]+$ for identifiers).",
    valid_label: "valid",
    valid_url: "Valid URL",
    validate_against_medical_coding_standards_icd10_sn:
      "Validate against medical coding standards (ICD-10, SNOMED). Ensure HIPAA compliance.",
    view_evidence: "View Evidence",
    validate_biometric_template_format_ensure_irrevers:
      "Validate biometric template format. Ensure irreversibility.",
    validate_card_numbers_with_luhn_algorithm_cvv_d34:
      "Validate card numbers with Luhn algorithm. CVV: ^\\d{3,4}$. Never store CVV.",
    validate_date_formats_yyyymmdd_implement_age_range:
      "Validate date formats (YYYY-MM-DD). Implement age range checks.",
    validating_schema: "Validating schema compliance...",
    validation_complete: "Validation complete!",
    validation_failed: "Validation Failed",
    validation_report: "Validation Report",
    verify_endpoint_path: "Verify the endpoint path is correct",
    verify_mcp_server: "Verify this is actually an MCP server",
    warn_dos_attempt:
      "This may indicate a misconfigured or malicious server attempting DoS.",
    warn_no_sandbox: "⚠️  Running without sandbox (--no-sandbox)",
    warn_private_ip: "⚠️  Connecting to private/internal address",
    welcome_title: "Automated Validator for Model Context Protocol",
    working_server: "working server",

    // Doctor Pro keys
    section_binary_integrity: "Binary Integrity",
    section_environment: "Environment",
    section_mcp_server: "MCP Server",
    section_env_audit: "Environment Security Audit",
    integrity_manifest: "Integrity Manifest",
    integrity_manifest_missing:
      "Manifest file missing (not a production build?)",
    integrity_manifest_parse_error: "Manifest file corrupted",
    integrity_manifest_found: "Manifest found",
    integrity_hash: "SHA-256 Checksum",
    integrity_hash_read_error: "Could not read current binary",
    integrity_hash_ok: "Binary is authentic",
    integrity_hash_mismatch: "INTEGRITY BREACH: Binary has been modified!",
    integrity_build_age: "Build Age",
    integrity_build_stale: "Build is older than 30 days",
    integrity_build_fresh: "Build is up to date",
    env_reports_dir: "Reports Directory",
    env_reports_dir_writable: "Directory is writable",
    env_reports_dir_created: "Directory created",
    env_reports_dir_not_writable: "Directory is not writable",
    mcp_tools: "Tools",
    mcp_resources: "Resources",
    mcp_prompts: "Prompts",
    mcp_tools_detected: "{count} tools detected",
    mcp_resources_detected: "{count} resources detected",
    mcp_prompts_detected: "{count} prompts detected",
    mcp_no_tools: "No tools found",
    mcp_no_resources: "No resources found",
    audit_total_env_vars: "Env Variables",
    audit_env_scanned: "variables scanned",
    audit_sensitive_names: "Sensitive Names",
    audit_no_sensitive_vars: "No suspicious variable names found",
    audit_sensitive_var_warning: "Potential secret found in variable name",
    audit_file_perms: "Permissions",
    audit_file_perms_loose: "Permissions are too permissive",
    audit_file_perms_ok: "Permissions are secure",
    summary_issues_found: "{count} issues found",
    summary_critical: "critical",
    summary_warnings: "warnings",
    summary_no_critical: "No critical issues",
    summary_all_ok: "All systems operational",
    watch_live: "Live Monitoring",
    watch_next_in: "next update in {seconds}s",
    found: "found",
    verbose_mode_active: "DETAILED DIAGNOSTIC LOGS ENABLED",
    verbose_integrity_binary_path: "Executing binary",
    verbose_integrity_manifest_path: "Integrity manifest",
    verbose_integrity_manifest_found: "Manifest file loaded successfully",
    verbose_integrity_build_date: "Build creation date",
    verbose_integrity_computing_hash: "Computing SHA-256 hash of binary...",
    verbose_integrity_computed: "Computed hash",
    verbose_integrity_expected: "Expected hash",
    verbose_env_registering_checks: "Registering system checks...",
    verbose_env_running_checks: "Executing diagnostics...",
    verbose_env_checking_reports_dir: "Testing write access to",
    verbose_env_reports_dir_created:
      "Directory did not exist, created successfully",
    verbose_server_non_http_target:
      "Target is local (stdio), skipping network checks",
    verbose_server_dns_lookup: "Resolving DNS for",
    verbose_server_dns_resolved: "DNS lookup successful",
    verbose_server_dns_failed: "DNS lookup failed",
    verbose_server_socket_opening: "Opening TCP socket to",
    verbose_server_socket_connected: "Connection established",
    verbose_server_socket_closing: "closing socket",
    verbose_server_socket_closed: "Socket closed",
    verbose_server_socket_timeout: "Socket timed out",
    verbose_server_socket_error: "Socket error",
    verbose_server_transport_type: "Selected transport",
    verbose_server_handshake_sending: "Sending MCP initialize handshake...",
    verbose_server_handshake_ok: "Handshake accepted by server",
    verbose_server_handshake_failed: "Handshake rejected",
    verbose_server_capabilities_raw: "Raw capabilities JSON",
    verbose_server_inventory: "Inventory extracted",
    verbose_server_exception: "Protocol exception",
    verbose_audit_scanning: "Scanning",
    verbose_audit_env_vars: "environment variables",
    verbose_audit_no_sensitive_found:
      "No sensitive patterns detected in variable names",
    verbose_audit_sensitive_triggered: "Suspicious variable names detected",
    verbose_audit_file_perms: "Checking permissions for",

    // Disclaimer keys
    disclaimer_title: "Important Disclaimer",
    disclaimer_main_text:
      "This report is provided for informational purposes only and does not constitute a security certification or guarantee.",
    disclaimer_scope_title: "What this tool analyzes:",
    disclaimer_scope_1:
      "Input validation patterns and common vulnerability signatures",
    disclaimer_scope_2: "MCP protocol compliance",
    disclaimer_scope_3: "Known attack vector indicators",
    disclaimer_scope_4: "Code quality and documentation",
    disclaimer_limitations_title: "What this tool does NOT analyze:",
    disclaimer_limitations_1: "Business logic vulnerabilities",
    disclaimer_limitations_2:
      "Authentication/authorization implementation correctness",
    disclaimer_limitations_3: "Runtime behavior under real conditions",
    disclaimer_limitations_4: "Third-party dependencies security",
    disclaimer_limitations_5: "Production environment configuration",
    disclaimer_no_warranty:
      'This tool is provided "AS IS" without warranty of any kind. A passing score does not guarantee security.',
    disclaimer_llm_notice:
      "LLM Analysis Notice: Tool/resource metadata was sent to {provider} API for semantic analysis. No actual server requests or responses were shared.",
    disclaimer_professional_audit:
      "For production deployments, a professional security audit is recommended.",

    // New HTML Generator Tailwind Design
    interactive: "Interactive",
    intelligence_report: "Intelligence Report",
    threat_landscape: "Threat Landscape",
    active_findings: "Active Findings",
    recommendation: "Remediation",
    summary: "Summary",
    scan_id: "Scan ID",
    issues: "Issues",
    critical_vulnerabilities: "Critical Vulnerabilities",
    high_severity: "High Severity",
    medium_severity: "Medium Severity",
    low_severity: "Low Severity",
    click_to_zoom: "Click to zoom and interact",
    settings: "Settings",
    protocol_compliance_full: "Protocol Compliance",
    compliance_passed: "All protocol checks passed",
    compliance_failed: "Protocol validation failed",
    mcp_version: "MCP Version",
    evidence: "Evidence",
    sort_severity_desc: "SORT: SEVERITY (DESC)",
    time_ago_just_now: "Just now",
    time_ago_minutes: "{n}m ago",
    time_ago_hours: "{n}h ago",
    time_ago_days: "{n}d ago",

    // Additional Report Keys
    risk_score: "Risk Score",
    system_health: "System Health",
    completed: "completed",

    // Target Validation
    target_validation_empty: "Target cannot be empty",
    target_validation_invalid_url: "Invalid URL format",
    target_validation_detected_sse:
      "Detected: SSE (Server-Sent Events) endpoint",
    target_validation_detected_http: "Detected: HTTP endpoint",
    target_validation_detected_nodejs: "Detected: Node.js script",
    target_validation_detected_nodejs_esm: "Detected: Node.js ES module",
    target_validation_detected_nodejs_cjs: "Detected: Node.js CommonJS module",
    target_validation_detected_typescript:
      "Detected: TypeScript script (requires ts-node)",
    target_validation_detected_python: "Detected: Python script",
    target_validation_detected_bash: "Detected: Bash script",
    target_validation_detected_batch: "Detected: Batch file",
    target_validation_detected_cmd: "Detected: Command file",
    target_validation_detected_executable: "Detected: Executable file",
    target_validation_detected_npx: "Detected: npx package",
    target_validation_detected_runtime: "Detected: {runtime} command",
    target_validation_detected_shell: "Detected: shell command ({command})",
    target_validation_warning_not_found:
      'Warning: "{command}" not found in PATH or filesystem',
    target_validation_will_likely_fail:
      "You can still use it, but it will likely fail.",
    target_examples_title: "Examples:",
    target_example_node: "target node server.js",
    target_example_http: "target http://localhost:3000",
    target_example_npx: "target npx my-mcp-server",

    // Interactive Shell - Shared/Target Resolution
    interactive_target_not_set: "Target not set. Enter URL or command:",
    interactive_operation_cancelled: "Operation cancelled. Target required.",
    interactive_example: "Example:",
    interactive_target_set_success: "Target set:",
    interactive_using_profile: "Using profile:",

    // Interactive Shell - Session Management
    interactive_set_usage: "Usage: set <key> <value>",
    interactive_set_keys: "Keys: target, lang",
    interactive_config_set: "Config set:",
    interactive_current_target: "Current target:",
    interactive_target_usage: "Usage: target <command|url>",
    interactive_not_set: "(not set)",
    interactive_lang_usage: "Usage: lang <en|es>",
    interactive_available_langs: "Available: en, es",
    interactive_lang_success: "Language:",
    interactive_workspace: "Workspace:",
    interactive_none: "(none)",
    interactive_language: "Language:",
    interactive_target: "Target:",
    interactive_this_session: "this session",
    interactive_elapsed: "Elapsed:",
    interactive_started: "Started:",
    interactive_history_file: "History file:",
    interactive_session_file: "Session file:",
    interactive_active: "(active)",
    interactive_not_saved: "(not saved)",
    interactive_history_cleared: "History cleared.",
    interactive_history_clear_failed: "Could not clear history.",
    interactive_history_total: "total",
    interactive_no_history: "No history yet.",
    interactive_history_more: "earlier. Use --last N to show more.",
    interactive_target_set_warning: "Target set:",

    // Interactive Shell - Help & Info
    interactive_security_tools: "Security Tools:",
    interactive_session_config: "Session & Config:",
    interactive_workspace_profiles: "Workspace & Profiles:",
    interactive_output_redirection: "Output Redirection:",
    interactive_overwrite: "overwrite",
    interactive_append: "append",
    interactive_redirect_example: "redirect validate output",
    interactive_prompt: "mcp-verify >",
    interactive_version: "Version:",
    interactive_license: "License:",
    interactive_license_value: "AGPL-3.0",
    interactive_maintained_by: "Maintained by:",
    interactive_maintained_by_value: "Fink",
    interactive_github: "GitHub:",
    interactive_github_url: "github.com/FinkTech/mcp-verify",
    interactive_docs: "Docs:",
    interactive_docs_url: "github.com/FinkTech/mcp-verify#readme",
    interactive_security: "Security:",
    interactive_security_url:
      "github.com/FinkTech/mcp-verify/blob/main/SECURITY.md",
    interactive_issues: "Issues:",
    interactive_issues_url: "github.com/FinkTech/mcp-verify/issues",

    // Interactive Shell - Router & Commands
    interactive_to_list_commands: "to list all commands.",
    interactive_context_unknown_subcommand: "Unknown context subcommand:",
    interactive_context_commands: "Context Commands:",
    interactive_context_list: "context list",
    interactive_context_list_desc: "List all contexts",
    interactive_context_switch: "context switch <name>",
    interactive_context_switch_desc: "Switch to a context",
    interactive_context_create: "context create <name>",
    interactive_context_create_desc: "Create a new context",
    interactive_context_clone: "context clone <source> <new_name>",
    interactive_context_clone_desc: "Clone an existing context",
    interactive_context_delete: "context delete <name>",
    interactive_context_delete_desc: "Delete a context",
    interactive_context_clone_examples: "Clone examples:",
    interactive_context_clone_example1: "context clone dev staging",
    interactive_context_clone_example2:
      'context clone dev prod --target "http://prod.example.com"',
    interactive_session_summary: "Session Summary",
    interactive_duration: "Duration:",
    interactive_history_saved: "History saved →",
    interactive_invalid_url: "Invalid URL:",
    interactive_opening: "Opening",
    interactive_could_not_open_browser:
      "Could not open browser. Visit manually:",

    // Proxy Command - Help Text
    proxy_help_title: "Security Proxy Help:",
    proxy_help_syntax: "proxy <target>",
    proxy_help_desc: "Starts a security gateway between client and server",
    proxy_help_options: "Options:",
    proxy_help_port: "--port <number>",
    proxy_help_port_desc: "Port to listen on (default: 9000)",
    proxy_help_logfile: "--log-file <path>",
    proxy_help_logfile_desc: "Save session logs to a file",
    proxy_help_timeout: "--timeout <ms>",
    proxy_help_timeout_desc: "Auto-stop proxy after X milliseconds",
    proxy_help_guardrails: "Guardrails Active:",
    proxy_help_guardrail_1:
      "• Sensitive Command Blocker (Blocks shell injection)",
    proxy_help_guardrail_2:
      "• PII Redactor (Masks sensitive data like SSN, Keys)",
    proxy_help_guardrail_3: "• Rate Limiter (Prevents DoS/Abuse)",
    proxy_help_guardrail_4: "• Input Sanitizer (SQL/Command clean-up)",
    proxy_help_guardrail_5: "• HTTPS Enforcer (Forces secure upstream calls)",
    proxy_help_usage_example: "Usage Example:",
    proxy_help_example_cmd:
      'proxy "node server.js" --port 8080 --log-file audit.log',

    // Fingerprint Command
    fingerprint_title: "Fingerprinting",
    fingerprint_language: "Language:",
    fingerprint_framework: "Framework:",
    fingerprint_database: "Database:",
    fingerprint_unknown: "Unknown",
    fingerprint_none: "None/Unknown",
    fingerprint_evidence: "Evidence:",
    fingerprint_evidence_item: "- ",
    fingerprint_failed: "Fingerprint failed:",

    // Inspect Command
    inspect_title: "Inspecting capabilities of",

    // Context Clone
    context_clone_invalid_syntax:
      "Invalid syntax. Expected: context clone <source> <new_name>",
    context_clone_example:
      'Example: context clone dev staging --target "http://staging.example.com"',
    context_clone_source_not_exist: 'Source context "{source}" does not exist.',
    context_clone_available_contexts: "Available contexts",
    context_clone_target_exists: 'Context "{target}" already exists.',
    context_clone_choose_different:
      "Choose a different name or delete the existing context first.",
    context_clone_failed: 'Failed to clone context "{source}" → "{target}".',
    context_clone_success: "Context cloned",
    context_clone_config_title: "Cloned configuration:",
    context_clone_target_label: "Target:",
    context_clone_language_label: "Language:",
    context_clone_profile_label: "Profile:",
    context_clone_target_overridden: "Target overridden",
    context_clone_switch_hint: "Switch to new context",

    // Rate Limiting & Quota Protection
    quota_stop_title: "API QUOTA EXCEEDED",
    quota_stop_msg:
      "The target server responded with a rate limit error (429 Too Many Requests). Fuzzing stopped immediately to protect your API quota.",
    quota_stop_recommendation:
      "Use --rate-limit flag to control request rate (e.g., --rate-limit 10 for 10 req/s)",
    rate_limit_flag_desc: "Maximum requests per second (default: unlimited)",
    rate_limit_active: "Rate limiting active",
    rate_limit_requests_per_sec: "requests/sec",
    fuzz_panic_stop: "PANIC STOP",
    fuzz_quota_detected_http: "HTTP 429 error detected from target server",
    fuzz_quota_detected_jsonrpc: "JSON-RPC rate limit error detected",

    // CLI Disclaimers
    disclaimer_fuzz_title: "Fuzzing Disclaimer",
    disclaimer_fuzz_line1:
      "You are about to run FUZZING tests against an MCP server.",
    disclaimer_fuzz_line2:
      "Fuzzing sends potentially malicious payloads to test security boundaries.",
    disclaimer_fuzz_line3: "This can:",
    disclaimer_fuzz_point1: "• Trigger security alerts on the target system",
    disclaimer_fuzz_point2: "• Consume significant resources",
    disclaimer_fuzz_point3: "• Leave traces in server logs",
    disclaimer_fuzz_warning:
      "⚠️  ONLY fuzz systems you own or have explicit authorization to test.",
    disclaimer_fuzz_legal:
      "Unauthorized fuzzing may violate laws in your jurisdiction (CFAA, Computer Misuse Act, etc.)",
    disclaimer_fuzz_responsibility:
      "YOU ARE LEGALLY RESPONSIBLE for any unauthorized testing.",

    disclaimer_stress_title: "Stress Testing Disclaimer",
    disclaimer_stress_line1:
      "You are about to run STRESS TESTS against an MCP server.",
    disclaimer_stress_line2:
      "Stress testing simulates high load with concurrent requests.",
    disclaimer_stress_line3: "This can:",
    disclaimer_stress_point1: "• Temporarily degrade server performance",
    disclaimer_stress_point2: "• Consume bandwidth and CPU resources",
    disclaimer_stress_point3: "• Trigger rate limiting or DDoS protection",
    disclaimer_stress_warning:
      "⚠️  ONLY stress test systems you own or have explicit authorization to test.",
    disclaimer_stress_legal:
      "Unauthorized stress testing may be considered Denial of Service (DoS) attack.",
    disclaimer_stress_responsibility:
      "YOU ARE LEGALLY RESPONSIBLE for any unauthorized testing.",

    disclaimer_proxy_title: "Security Proxy Disclaimer",
    disclaimer_proxy_line1: "You are about to start a SECURITY PROXY server.",
    disclaimer_proxy_line2:
      "The proxy intercepts and inspects traffic between clients and MCP servers.",
    disclaimer_proxy_line3: "This can:",
    disclaimer_proxy_point1: "• Modify requests and responses in transit",
    disclaimer_proxy_point2: "• Log sensitive data (credentials, API keys)",
    disclaimer_proxy_point3: "• Introduce latency",
    disclaimer_proxy_warning:
      "⚠️  ONLY proxy traffic you are authorized to inspect.",
    disclaimer_proxy_legal:
      "Unauthorized traffic interception may violate wiretapping laws.",
    disclaimer_proxy_responsibility:
      "YOU ARE LEGALLY RESPONSIBLE for any unauthorized interception.",

    disclaimer_validate_title: "Validation Notice",
    disclaimer_validate_line1: "You are about to run SECURITY VALIDATION.",
    disclaimer_validate_line2:
      "Validation tests 60 security rules and attempts to detect vulnerabilities.",
    disclaimer_validate_line3: "This can:",
    disclaimer_validate_point1:
      "• Trigger security alerts on monitored systems",
    disclaimer_validate_point2: "• Leave traces in audit logs",
    disclaimer_validate_point3: "• Expose sensitive information in reports",
    disclaimer_validate_warning:
      "⚠️  ONLY validate servers you own or have explicit authorization to audit.",
    disclaimer_validate_legal:
      "Unauthorized security scanning may violate unauthorized access laws.",
    disclaimer_validate_responsibility:
      "YOU ARE LEGALLY RESPONSIBLE for any unauthorized scanning.",

    disclaimer_question: "Do you understand and accept the risks?",
    disclaimer_action_yes: "Yes, I have authorization to proceed",
    disclaimer_action_no: "No, cancel this operation",
    disclaimer_action_never: "Yes, and don't show this again",
    disclaimer_dismissed:
      "Disclaimer dismissed. You can re-enable warnings with: mcp-verify disclaimers reset",
    disclaimer_aborted: "Operation cancelled by user.",

    disclaimer_status_title: "Disclaimer Status",
    disclaimer_status_none: "No disclaimers permanently dismissed.",
    disclaimer_status_header_type: "Type",
    disclaimer_status_header_status: "Status",
    disclaimer_status_active: "Active (will show)",
    disclaimer_status_dismissed: "Dismissed (won't show)",
    disclaimer_status_reset_one: "Disclaimer reset: {type}",
    disclaimer_status_reset_all: "All disclaimers reset",
    disclaimer_status_footer_one:
      "To reset one: mcp-verify disclaimers reset --type {type}",
    disclaimer_status_footer_all: "To reset all: mcp-verify disclaimers reset",

    // Block A: OWASP LLM Top 10 (SEC-023 to SEC-030)
    sec_023_excessive_agency:
      'Tool "{toolName}" appears to be a read-only operation (get_/fetch_/read_) but includes destructive parameters. Violates principle of least privilege - tool scope exceeds semantic intent.',
    sec_023_recommendation:
      "Split tool into separate read and write operations. Remove destructive parameters (delete, force, recursive) from read-only tools. Follow single-responsibility principle.",
    sec_024_prompt_injection:
      'Tool "{toolName}" accepts unvalidated prompt-related parameters: {params}. These can be exploited for direct prompt injection if passed to LLM context or other tools without sanitization.',
    sec_024_recommendation:
      "Add maxLength constraint (≤500 chars), pattern validation, or enum for prompt-related parameters. Never pass user input directly to LLM system prompts. Implement content filtering for injection patterns.",
    sec_024_description_injection:
      'Tool "{toolName}" description contains imperative instructions targeting AI context: "…{snippet}…". Attackers embed instructions in tool metadata to manipulate LLM behavior without touching code.',
    sec_024_description_recommendation:
      "Rewrite the tool description to describe functionality only — not what the AI should do. Remove any imperatives like 'when processing', 'include a summary of', 'forward all', or references to conversation/session context. Treat tool descriptions as untrusted content visible to the LLM.",
    sec_024_default_injection:
      'Tool "{toolName}" parameter "{param}" has a default value containing embedded instructions: "{snippet}". Default values are interpolated into LLM context and can act as covert injection vectors.',
    sec_024_default_recommendation:
      "Default values must be simple, format-only strings (e.g. 'csv', 'json', 'asc'). Never embed natural language instructions or multi-clause strings in defaults. Move any operational guidance to external documentation.",
    sec_024_annotation_injection:
      'Tool "{toolName}" annotation field "{field}" contains instruction-like content: "{snippet}". Custom x-* annotation fields are included in LLM tool context and can carry covert injection payloads.',
    sec_024_annotation_recommendation:
      "Remove instruction content from annotation fields. Annotations should only carry machine-readable hints (boolean flags, enum values). Never use x-* fields to pass natural language directives to the AI.",
    sec_024_resource_injection:
      'Resource "{resourceName}" description contains imperative instructions targeting AI context: "…{snippet}…". Resource descriptions are visible to the LLM and can carry injection payloads just like tool descriptions.',
    sec_024_prompt_template_injection:
      'Prompt template "{promptName}" description contains imperative instructions targeting AI context: "…{snippet}…". Prompt templates have direct access to the LLM context window — injection here is especially dangerous.',
    sec_024_prompt_template_recommendation:
      "Prompt template descriptions must describe the template purpose only. Remove any imperative language, references to conversation history, or instructions targeting the AI runtime. Treat prompt descriptions as untrusted metadata.",
    sec_024_prompt_arg_injection:
      'Prompt template "{promptName}" argument "{argName}" description contains imperative instructions: "…{snippet}…". Argument descriptions are shown to the LLM to explain how to fill the template — injection here manipulates argument handling.',
    sec_025_unpinned_deps:
      "Server declares {count} dependencies with unpinned versions: {deps}. Allows supply chain attacks through malicious package updates (typosquatting, compromised maintainer).",
    sec_025_recommendation:
      "Pin all dependencies to exact versions (remove ^, ~, *, latest). Use lockfiles (package-lock.json, pnpm-lock.yaml). Implement SCA scanning (npm audit, Snyk, Dependabot).",
    sec_025_no_deps_declared:
      "Server does not declare dependencies in serverInfo. If using external packages, this prevents supply chain auditing.",
    sec_025_declare_deps_recommendation:
      "Declare all dependencies in serverInfo.dependencies with pinned versions for supply chain transparency.",
    sec_026_sensitive_exposure:
      'Tool "{toolName}" handles sensitive data (PII, credentials, health info) but lacks output redaction mechanisms. Missing contentEncoding, format constraints, or redaction keywords in description.',
    sec_026_recommendation:
      'Implement output filtering: add outputSchema with contentEncoding, or document redaction in description ("outputs are masked/anonymized"). Never return raw PII in tool responses.',
    sec_027_training_poisoning:
      'Tool "{toolName}" accepts training/corpus data without validation constraints. Vulnerable to data poisoning attacks - malicious training data can inject backdoors into models.',
    sec_027_recommendation:
      "Add validation for training data: maxLength, maxItems, pattern, or format constraints. Implement data provenance tracking. Consider cryptographic signatures for training datasets.",
    sec_028_model_dos:
      'Tool "{toolName}" has unbounded parameters: {params}. Can be exploited for model DoS by exhausting context windows or causing infinite loops.',
    sec_028_recommendation:
      "Add constraints: maxItems (≤100) for arrays, maxLength (≤10000) for strings. Implement timeouts for recursive operations. Add rate limiting for expensive tools.",
    sec_029_insecure_plugin:
      'Tool "{toolName}" has design flaws: {issues}. Violates secure plugin design principles (missing inputSchema, no required params, mixes read/write, lacks validation).',
    sec_029_recommendation:
      "Fix design issues: add inputSchema, make critical params required, separate read/write operations (SRP), add validation constraints (pattern, format, enum).",
    sec_030_excessive_disclosure:
      'Tool "{toolName}" retrieves data without pagination/filtering: {reason}. Violates data minimization - returns more data than necessary for LLM task, increasing leakage risk.',
    sec_030_recommendation:
      "Add pagination params (limit, offset), filtering params (filter, where, fields). Implement default limits (≤100 items). Document what data is actually returned.",

    // Block B: Multi-Agent Attacks (SEC-032 to SEC-041)
    sec_032_result_tampering:
      'Tool "{toolName}" consumes results from other tools but lacks integrity verification (signatures, hashes, HMAC). Vulnerable to agent-in-the-middle attacks.',
    sec_032_recommendation:
      "Add integrity verification: require signature/hash parameter, implement HMAC validation, or use authenticated channels. Document expected result format with verification metadata.",
    sec_033_recursive_loop:
      'Tool "{toolName}" has recursive/loop patterns without depth limits. Can be exploited to create infinite loops, causing resource exhaustion (stack overflow, memory leak).',
    sec_033_recommendation:
      "Add depth limit parameters: max_depth, recursion_limit, max_iterations. Implement server-side recursion tracking. Set reasonable defaults (≤10 depth).",
    sec_033_circular_chain:
      "Detected circular tool dependency chain: {chain}. Multiple tools reference each other, creating infinite loop potential in multi-agent scenarios.",
    sec_033_chain_recommendation:
      "Break circular dependencies: redesign tool interfaces, add explicit exit conditions, implement call stack tracking, set global recursion limit.",
    sec_034_privilege_escalation:
      'Tool "{toolName}" allows privilege delegation (on_behalf_of, delegate_to) without role validation. Enables low-privilege agents to escalate permissions.',
    sec_034_recommendation:
      "Add role validation: require agent_id + role parameters, implement RBAC checks, validate delegation chains, log all privilege changes for audit.",
    sec_034_mixed_privileges:
      'Tool "{toolName}" mixes read and write operations at different privilege levels. Violates separation of duties - enables privilege confusion attacks.',
    sec_034_separation_recommendation:
      "Separate tools by privilege level: create distinct admin/user versions, implement least privilege per tool, add explicit permission requirements.",
    sec_035_state_poisoning:
      'Tool "{toolName}" modifies shared agent state without validation or isolation: {issue}. Malicious agents can corrupt state for other agents.',
    sec_035_recommendation:
      "Implement state isolation: require agent_id for all state operations, add validation constraints, use namespaced storage, implement state integrity checks (hashes).",
    sec_036_agent_ddos:
      'Tool "{toolName}" is vulnerable to distributed agent DoS: {reason}. Multiple agents can coordinate to exhaust resources (amplification, no per-agent limits).',
    sec_036_recommendation:
      "Implement per-agent rate limiting, add global quotas, track agent_id for all operations, set resource limits (CPU, memory, bandwidth) per agent.",
    sec_037_cross_agent_injection:
      'Tool "{toolName}" forwards messages between agents with vulnerable parameters: {params}. Agent A can inject prompts into Agent B\'s context.',
    sec_037_recommendation:
      "Sanitize all forwarded content: add maxLength (≤500), implement prompt injection filters, use structured message formats (not free-text), validate sender identity.",
    sec_038_reputation_hijacking:
      'Tool "{toolName}" modifies agent reputation/trust scores without cryptographic verification. Enables reputation spoofing and Sybil attacks.',
    sec_038_recommendation:
      "Add cryptographic signatures to reputation data: require proof-of-work or certificates, implement decentralized verification, use blockchain/distributed ledger for reputation.",
    sec_039_path_traversal_chain:
      'Tool "{toolName}" consumes file paths from: {producers}. Lacks path validation - vulnerable to path traversal attacks when chained with path-producing tools.',
    sec_039_recommendation:
      "Implement path validation: canonicalize paths, whitelist allowed directories, reject ../ sequences, use path.resolve() and validate against basedir.",
    sec_041_memory_injection:
      'Tool "{toolName}" writes to agent memory with {issue}. Malicious agents can inject system instructions or malicious context into long-term memory.',
    sec_041_recommendation:
      'Restrict memory types: use enum for entry_type (exclude "system", "instruction"), add validation for memory content, implement memory sandboxing per agent.',

    // Block C: Operational (SEC-043 to SEC-050)
    sec_043_session_mgmt:
      'Tool "{toolName}" uses session tokens without expiration or invalidation. Sessions can be hijacked and reused indefinitely.',
    sec_043_no_invalidation:
      "Multiple tools ({count}) manage sessions but no logout/invalidation tool is provided.",
    sec_043_recommendation:
      "Implement session expiration: add ttl/expires_at to session params, provide logout/invalidate tools, use short-lived tokens (≤1 hour) with refresh mechanism.",
    sec_044_no_versioning:
      "Server does not declare version in serverInfo. Prevents compatibility checks, baseline comparisons, and security patch tracking.",
    sec_044_no_server_version:
      "Server is missing semantic versioning in its metadata. Critical for security regression tracking.",
    sec_044_recommendation:
      "Add version field to serverInfo using semantic versioning (1.0.0). Document breaking changes, implement version negotiation in handshake.",
    sec_045_error_granularity:
      "Tool error responses may be too detailed, leaking internal implementation details. (Requires runtime fuzzing to confirm)",
    sec_045_recommendation:
      "Ensure error messages are helpful but sanitized. Remove stack traces, environment details, and internal paths from production error responses.",
    sec_046_no_cors_mention:
      "Server description does not mention CORS or origin validation for HTTP/SSE transport. Risk of CSRF/cross-origin attacks in development.",
    sec_046_recommendation:
      "Implement strict CORS policy: whitelist allowed origins, reject requests with invalid Origin headers, use same-origin policies for local servers.",
    sec_047_destructive_no_optin:
      'Tool "{toolName}" performs destructive operations (purge, delete, format) but is enabled by default without opt-in flags.',
    sec_047_recommendation:
      'Follow "Secure by Default": make destructive tools opt-in via configuration, add manual confirmation flags, or implement temporary soft-delete.',
    sec_048_capability_negotiation:
      "Server implement capabilities not declared in handshake, or vice-versa. Inconsistency leads to protocol-level exploits.",
    sec_048_recommendation:
      "Strictly align declared capabilities with implementation. Use automated handshake validation, reject calls to undeclared methods.",
    sec_049_timing_attacks:
      "Authentication operations may be vulnerable to timing attacks. (Requires runtime fuzzing to confirm)",
    sec_049_recommendation:
      "Use constant-time comparison algorithms for tokens/passwords. Add random jitter to authentication response times to mask calculation duration.",
    sec_050_weak_entropy:
      'Tool "{toolName}" generates security identifiers or tokens with insufficient entropy (randomness). Predictable outputs allow enumeration.',
    sec_050_recommendation:
      "Use cryptographically secure PRNGs (crypto.getRandomValues). Increase identifier length (min 128 bits), use random UUIDs (v4) or ulids.",

    // Block D: AI Weaponization (SEC-051, SEC-052, SEC-055 to SEC-058)
    sec_051_weaponized_fuzzer:
      'Tool "{toolName}" implements offensive security capabilities (fuzzing, exploitation) without authorization checks. Can be weaponized for unauthorized testing.',
    sec_051_recommendation:
      "Require authorization: add authorization_token parameter, implement scope of consent (whitelisted targets only), log all offensive tool usage, require user confirmation.",
    sec_052_autonomous_backdoor:
      'Tool "{toolName}" has suspicious autonomous behavior: {behavior}. Potential backdoor or malware characteristics detected.',
    sec_052_recommendation:
      "CRITICAL: Review tool thoroughly. Remove self-modification code, eliminate stealth behaviors, disable autonomous execution, consider this MCP server compromised.",
    sec_052_server_autonomous:
      "Server description mentions autonomous/stealth behaviors. Potential malware or backdoor detected at server level.",
    sec_052_server_recommendation:
      "DO NOT EXECUTE. Report to security team. Quarantine this MCP server. Perform full malware scan.",
    sec_055_jailbreak_service:
      'Tool "{toolName}" provides LLM jailbreak or adversarial attack capabilities. Enables abuse of other LLM systems.',
    sec_055_recommendation:
      "Restrict usage: require authorization for red team use, implement logging/auditing, limit to approved research contexts, add disclaimer about ethical use.",
    sec_055_server_jailbreak:
      "Server description mentions jailbreak or adversarial LLM capabilities. Potential abuse risk.",
    sec_055_server_recommendation:
      "Ensure proper authorization controls. Implement usage logging. Restrict to authorized security research only.",
    sec_056_phishing_tool:
      'Tool "{toolName}" appears designed for phishing or social engineering attacks. Can generate deceptive content, fake login pages, or impersonation.',
    sec_056_recommendation:
      "Remove phishing capabilities or restrict to authorized security testing only. Implement strict logging, require authorization tokens, add ethical use disclaimers.",
    sec_057_steganography:
      'Tool "{toolName}" implements steganography (data hiding in media). Can be used for covert data exfiltration.',
    sec_057_recommendation:
      "Implement DLP controls: log all encoding operations, require authorization for steganography tools, monitor for anomalous media generation patterns.",
    sec_058_self_replicating:
      'Tool "{toolName}" has self-replication capabilities: {capability}. Worm-like behavior detected - can spread to other systems.',
    sec_058_recommendation:
      "CRITICAL: Quarantine this MCP server immediately. Remove replication code. Report to security team. Consider this malware.",
    sec_058_server_worm:
      "Server description mentions self-replication or worm behavior. Malware detected.",
    sec_058_server_recommendation:
      "DO NOT EXECUTE. Quarantine. Perform malware analysis. Report to security authorities.",

    press_q_to_exit: "Press [Q] to stop proxy and save session",
    option_proxy_log_file: "Save proxy audit logs to a text file",
    proxy_session_ended: "Proxy session ended.",
    proxy_save_question: "Would you like to save the session logs?",
    proxy_save_none: "Don't save",
    proxy_save_txt: "Save as .txt (Human readable)",
    proxy_save_json: "Save as .json (Structured data)",
    proxy_save_md: "Save as .md (Markdown)",
    proxy_save_format_question: "Select export format:",
    proxy_filename_prompt: "Enter filename:",
  },
  es: {
    // HTML Report Keys
    title: "Informe de Validación MCP",
    target: "Objetivo",
    generated_label: "Generado",
    switch_theme: "Tema",
    theme: "Tema",
    protocol: "Protocolo",
    response_time: "Tiempo de Respuesta",
    security_audit: "Auditoría de Seguridad",
    scan_id_prefix: "ID",
    surgical_summary: "Resumen Quirúrgico",
    surgical_summary_excellent:
      "La postura de seguridad es robusta con vulnerabilidades mínimas. El sistema demuestra una fuerte adherencia a las mejores prácticas de seguridad.",
    surgical_summary_good:
      "El análisis de seguridad revela hallazgos moderados que requieren atención. La seguridad general del sistema es satisfactoria con margen de mejora.",
    surgical_summary_critical:
      "La auditoría revela vulnerabilidades críticas en cadena en módulos centrales que requieren refactorización inmediata. Se requiere fortificación del sistema para mitigar riesgos de movimiento lateral.",
    surgical_summary_warning:
      "La evaluación de seguridad identifica múltiples vulnerabilidades en diferentes niveles de severidad. Se recomienda remediación sistemática para fortalecer la postura defensiva.",
    surgical_summary_default:
      "Auditoría de seguridad completa completada. Hallazgos detallados y recomendaciones disponibles a continuación.",
    risk_heatmap: "Mapa de Calor de Riesgo",
    impact_vs_probability: "IMPACTO vs PROBABILIDAD",
    critical_zone: "Zona Crítica",
    impact: "Impacto",
    probability: "Probabilidad",
    agency_system: "Sistema",
    agency_network: "Red",
    agency_files: "Archivos",
    agency_schema: "Esquema",
    agency_auth: "Autenticación",
    agency_data: "Datos",
    cli_reproducer: "Reproductor CLI",
    shielded_schema_diff: "Diferencia de Esquema Protegido",
    vulnerable: "Vulnerable",
    hardened: "Fortificado",
    security_finding: "Hallazgo de Seguridad",
    detected: "Detectado",
    source: "Fuente",
    copy_remediation: "Copiar Remediación",
    sort_severity: "Ordenar: Severidad",
    by_severity: "Por Severidad",
    by_rule: "Por Código de Regla",
    most_recent: "Más Recientes",
    introduced_risks: "Riesgos Introducidos",
    resolved_risks: "Riesgos Resueltos",
    new_label: "Nuevo",
    fixed_label: "Corregido",
    updated_label: "Actualizado",
    no_new_risks: "No se introdujeron nuevos riesgos",
    no_risks_resolved: "No se resolvieron riesgos",
    minutes_ago: "m atrás",
    hours_ago: "h atrás",
    days_ago: "d atrás",

    // Additional Report Keys
    risk_score: "Puntuación de Riesgo",
    system_health: "Salud del Sistema",
    completed: "completados",

    // Target Validation
    target_validation_empty: "El target no puede estar vacío",
    target_validation_invalid_url: "Formato de URL inválido",
    target_validation_detected_sse:
      "Detectado: endpoint SSE (Server-Sent Events)",
    target_validation_detected_http: "Detectado: endpoint HTTP",
    target_validation_detected_nodejs: "Detectado: script Node.js",
    target_validation_detected_nodejs_esm: "Detectado: módulo ES de Node.js",
    target_validation_detected_nodejs_cjs:
      "Detectado: módulo CommonJS de Node.js",
    target_validation_detected_typescript:
      "Detectado: script TypeScript (requiere ts-node)",
    target_validation_detected_python: "Detectado: script Python",
    target_validation_detected_bash: "Detectado: script Bash",
    target_validation_detected_batch: "Detectado: archivo Batch",
    target_validation_detected_cmd: "Detectado: archivo de comandos",
    target_validation_detected_executable: "Detectado: archivo ejecutable",
    target_validation_detected_npx: "Detectado: paquete npx",
    target_validation_detected_runtime: "Detectado: comando {runtime}",
    target_validation_detected_shell: "Detectado: comando shell ({command})",
    target_validation_warning_not_found:
      'Advertencia: "{command}" no encontrado en PATH o sistema de archivos',
    target_validation_will_likely_fail:
      "Aún podés usarlo, pero probablemente fallará.",
    target_examples_title: "Ejemplos:",
    target_example_node: "target node server.js",
    target_example_http: "target http://localhost:3000",
    target_example_npx: "target npx my-mcp-server",

    // Interactive Shell - Shared/Target Resolution
    interactive_target_not_set: "Target no configurado. Ingresa URL o comando:",
    interactive_operation_cancelled: "Operación cancelada. Se requiere target.",
    interactive_example: "Ejemplo:",
    interactive_target_set_success: "Target configurado:",
    interactive_using_profile: "Usando perfil:",

    // Interactive Shell - Session Management
    interactive_set_usage: "Uso: set <clave> <valor>",
    interactive_set_keys: "Claves: target, lang",
    interactive_config_set: "Configuración establecida:",
    interactive_current_target: "Target actual:",
    interactive_target_usage: "Uso: target <comando|url>",
    interactive_not_set: "(no configurado)",
    interactive_lang_usage: "Uso: lang <en|es>",
    interactive_available_langs: "Disponibles: en, es",
    interactive_lang_success: "Idioma:",
    interactive_workspace: "Espacio de trabajo:",
    interactive_none: "(ninguno)",
    interactive_language: "Idioma:",
    interactive_target: "Target:",
    interactive_this_session: "esta sesión",
    interactive_elapsed: "Transcurrido:",
    interactive_started: "Iniciado:",
    interactive_history_file: "Archivo de historial:",
    interactive_session_file: "Archivo de sesión:",
    interactive_active: "(activo)",
    interactive_not_saved: "(no guardado)",
    interactive_history_cleared: "Historial limpiado.",
    interactive_history_clear_failed: "No se pudo limpiar el historial.",
    interactive_history_total: "total",
    interactive_no_history: "Aún no hay historial.",
    interactive_history_more: "anteriores. Usa --last N para ver más.",
    interactive_target_set_warning: "Target configurado:",

    // Interactive Shell - Help & Info
    interactive_security_tools: "Herramientas de Seguridad:",
    interactive_session_config: "Sesión y Configuración:",
    interactive_workspace_profiles: "Espacio de Trabajo y Perfiles:",
    interactive_output_redirection: "Redirección de Salida:",
    interactive_overwrite: "sobrescribir",
    interactive_append: "agregar",
    interactive_redirect_example: "redirigir salida de validate",
    interactive_prompt: "mcp-verify >",
    interactive_version: "Versión:",
    interactive_license: "Licencia:",
    interactive_license_value: "AGPL-3.0",
    interactive_maintained_by: "Mantenido por:",
    interactive_maintained_by_value: "Fink",
    interactive_github: "GitHub:",
    interactive_github_url: "github.com/FinkTech/mcp-verify",
    interactive_docs: "Documentación:",
    interactive_docs_url: "github.com/FinkTech/mcp-verify#readme",
    interactive_security: "Seguridad:",
    interactive_security_url:
      "github.com/FinkTech/mcp-verify/blob/main/SECURITY.md",
    interactive_issues: "Issues:",
    interactive_issues_url: "github.com/FinkTech/mcp-verify/issues",

    // Interactive Shell - Router & Commands
    interactive_to_list_commands: "para listar todos los comandos.",
    interactive_context_unknown_subcommand:
      "Subcomando de contexto desconocido:",
    interactive_context_commands: "Comandos de Contexto:",
    interactive_context_list: "context list",
    interactive_context_list_desc: "Listar todos los contextos",
    interactive_context_switch: "context switch <nombre>",
    interactive_context_switch_desc: "Cambiar a un contexto",
    interactive_context_create: "context create <nombre>",
    interactive_context_create_desc: "Crear un nuevo contexto",
    interactive_context_clone: "context clone <origen> <nuevo_nombre>",
    interactive_context_clone_desc: "Clonar un contexto existente",
    interactive_context_delete: "context delete <nombre>",
    interactive_context_delete_desc: "Eliminar un contexto",
    interactive_context_clone_examples: "Ejemplos de clonación:",
    interactive_context_clone_example1: "context clone dev staging",
    interactive_context_clone_example2:
      'context clone dev prod --target "http://prod.example.com"',
    interactive_session_summary: "Resumen de Sesión",
    interactive_duration: "Duración:",
    interactive_history_saved: "Historial guardado →",
    interactive_invalid_url: "URL inválida:",
    interactive_opening: "Abriendo",
    interactive_could_not_open_browser:
      "No se pudo abrir el navegador. Visita manualmente:",

    // Proxy Command - Help Text
    proxy_help_title: "Ayuda del Proxy de Seguridad:",
    proxy_help_syntax: "proxy <target>",
    proxy_help_desc:
      "Inicia una puerta de enlace de seguridad entre cliente y servidor",
    proxy_help_options: "Opciones:",
    proxy_help_port: "--port <número>",
    proxy_help_port_desc: "Puerto en el que escuchar (por defecto: 9000)",
    proxy_help_logfile: "--log-file <ruta>",
    proxy_help_logfile_desc: "Guardar logs de sesión en un archivo",
    proxy_help_timeout: "--timeout <ms>",
    proxy_help_timeout_desc:
      "Detener proxy automáticamente después de X milisegundos",
    proxy_help_guardrails: "Guardarrieles Activos:",
    proxy_help_guardrail_1:
      "• Bloqueador de Comandos Sensibles (Bloquea inyección shell)",
    proxy_help_guardrail_2:
      "• Redactor de PII (Enmascara datos sensibles como SSN, Keys)",
    proxy_help_guardrail_3: "• Limitador de Tasa (Previene DoS/Abuso)",
    proxy_help_guardrail_4:
      "• Sanitizador de Entrada (Limpieza de SQL/Comandos)",
    proxy_help_guardrail_5:
      "• Forzador HTTPS (Fuerza llamadas upstream seguras)",
    proxy_help_usage_example: "Ejemplo de Uso:",
    proxy_help_example_cmd:
      'proxy "node server.js" --port 8080 --log-file audit.log',

    // Fingerprint Command
    fingerprint_title: "Fingerprinting",
    fingerprint_language: "Lenguaje:",
    fingerprint_framework: "Framework:",
    fingerprint_database: "Base de datos:",
    fingerprint_unknown: "Desconocido",
    fingerprint_none: "Ninguno/Desconocido",
    fingerprint_evidence: "Evidencia:",
    fingerprint_evidence_item: "- ",
    fingerprint_failed: "Fingerprint falló:",

    // Inspect Command
    inspect_title: "Inspeccionando capacidades de",

    // Context Clone
    context_clone_invalid_syntax:
      "Sintaxis inválida. Se esperaba: context clone <source> <new_name>",
    context_clone_example:
      'Ejemplo: context clone dev staging --target "http://staging.example.com"',
    context_clone_source_not_exist:
      'El contexto de origen "{source}" no existe.',
    context_clone_available_contexts: "Contextos disponibles",
    context_clone_target_exists: 'El contexto "{target}" ya existe.',
    context_clone_choose_different:
      "Elige un nombre diferente o elimina el contexto existente primero.",
    context_clone_failed:
      'Falló al clonar el contexto "{source}" → "{target}".',
    context_clone_success: "Contexto clonado",
    context_clone_config_title: "Configuración clonada:",
    context_clone_target_label: "Target:",
    context_clone_language_label: "Idioma:",
    context_clone_profile_label: "Perfil:",
    context_clone_target_overridden: "Target sobrescrito",
    context_clone_switch_hint: "Cambiar al nuevo contexto",

    // Rate Limiting & Quota Protection
    quota_stop_title: "CUOTA DE API EXCEDIDA",
    quota_stop_msg:
      "El servidor objetivo respondió con un error de límite de tasa (429 Too Many Requests). El fuzzing se detuvo inmediatamente para proteger tu cuota de API.",
    quota_stop_recommendation:
      "Usa la flag --rate-limit para controlar la tasa de peticiones (ej. --rate-limit 10 para 10 req/s)",
    rate_limit_flag_desc:
      "Máximo de peticiones por segundo (por defecto: ilimitado)",
    rate_limit_active: "Limitación de tasa activa",
    rate_limit_requests_per_sec: "peticiones/seg",
    fuzz_panic_stop: "PARADA DE EMERGENCIA",
    fuzz_quota_detected_http:
      "Error HTTP 429 detectado desde el servidor objetivo",
    fuzz_quota_detected_jsonrpc: "Error de límite de tasa JSON-RPC detectado",

    // CLI Disclaimers
    disclaimer_fuzz_title: "Aviso de Fuzzing",
    disclaimer_fuzz_line1:
      "Estás a punto de ejecutar pruebas de FUZZING contra un servidor MCP.",
    disclaimer_fuzz_line2:
      "El fuzzing envía cargas potencialmente maliciosas para probar los límites de seguridad.",
    disclaimer_fuzz_line3: "Esto puede:",
    disclaimer_fuzz_point1:
      "• Activar alertas de seguridad en el sistema objetivo",
    disclaimer_fuzz_point2: "• Consumir recursos significativos",
    disclaimer_fuzz_point3: "• Dejar rastros en los registros del servidor",
    disclaimer_fuzz_warning:
      "⚠️  SOLO ejecuta fuzzing en sistemas que poseas o tengas autorización explícita para probar.",
    disclaimer_fuzz_legal:
      "El fuzzing no autorizado puede violar leyes en tu jurisdicción (CFAA, Computer Misuse Act, etc.)",
    disclaimer_fuzz_responsibility:
      "TÚ ERES LEGALMENTE RESPONSABLE de cualquier prueba no autorizada.",

    disclaimer_stress_title: "Aviso de Prueba de Estrés",
    disclaimer_stress_line1:
      "Estás a punto de ejecutar PRUEBAS DE ESTRÉS contra un servidor MCP.",
    disclaimer_stress_line2:
      "Las pruebas de estrés envían grandes volúmenes de solicitudes para probar límites de rendimiento.",
    disclaimer_stress_line3: "Esto puede:",
    disclaimer_stress_point1: "• Degradar el rendimiento del sistema objetivo",
    disclaimer_stress_point2: "• Activar mecanismos de protección DDoS",
    disclaimer_stress_point3:
      "• Afectar a usuarios legítimos durante las pruebas",
    disclaimer_stress_warning:
      "⚠️  SOLO ejecuta pruebas de estrés en sistemas que poseas o tengas autorización explícita para probar.",
    disclaimer_stress_legal:
      "Las pruebas de estrés no autorizadas pueden violar leyes de abuso informático.",
    disclaimer_stress_responsibility:
      "TÚ ERES LEGALMENTE RESPONSABLE de cualquier impacto causado por pruebas no autorizadas.",

    disclaimer_proxy_title: "Aviso de Proxy de Seguridad",
    disclaimer_proxy_line1:
      "Estás a punto de iniciar un PROXY DE SEGURIDAD entre un cliente y un servidor MCP.",
    disclaimer_proxy_line2:
      "El proxy interceptará y puede modificar todo el tráfico entre cliente y servidor.",
    disclaimer_proxy_line3: "Esto puede:",
    disclaimer_proxy_point1: "• Introducir latencia en las comunicaciones",
    disclaimer_proxy_point2:
      "• Bloquear solicitudes legítimas si están mal configuradas las reglas",
    disclaimer_proxy_point3: "• Requerir consentimiento de ambas partes",
    disclaimer_proxy_warning:
      "⚠️  SOLO ejecuta proxies en comunicaciones que controles o tengas autorización para interceptar.",
    disclaimer_proxy_legal:
      "La interceptación no autorizada puede violar leyes de escuchas ilegales y privacidad.",
    disclaimer_proxy_responsibility:
      "TÚ ERES LEGALMENTE RESPONSABLE de cualquier interceptación no autorizada.",

    disclaimer_validate_title: "Aviso de Validación de Seguridad",
    disclaimer_validate_line1:
      "Estás a punto de ejecutar un ESCANEO DE SEGURIDAD contra un servidor MCP.",
    disclaimer_validate_line2:
      "La validación probará 60 reglas de seguridad e intentará detectar vulnerabilidades.",
    disclaimer_validate_line3: "Esto puede:",
    disclaimer_validate_point1:
      "• Activar alertas de seguridad en sistemas monitoreados",
    disclaimer_validate_point2: "• Dejar rastros en registros de auditoría",
    disclaimer_validate_point3: "• Exponer información sensible en informes",
    disclaimer_validate_warning:
      "⚠️  SOLO valida servidores que poseas o tengas autorización explícita para auditar.",
    disclaimer_validate_legal:
      "Los escaneos de seguridad no autorizados pueden violar leyes de acceso no autorizado.",
    disclaimer_validate_responsibility:
      "TÚ ERES LEGALMENTE RESPONSABLE de cualquier escaneo no autorizado.",

    disclaimer_question: "¿Deseas continuar?",
    disclaimer_action_yes: "Sí, continuar",
    disclaimer_action_never: "Sí, y no volver a preguntar",
    disclaimer_action_no: "No, cancelar",
    disclaimer_dismissed: "Aviso descartado. No volverás a ver esto.",
    disclaimer_aborted: "Operación cancelada por el usuario.",

    disclaimer_status_title: "Estado de Avisos",
    disclaimer_status_none: "Ningún aviso descartado permanentemente.",
    disclaimer_status_header_type: "Tipo",
    disclaimer_status_header_status: "Estado",
    disclaimer_status_active: "Activo (se mostrará)",
    disclaimer_status_dismissed: "Descartado (no se mostrará)",
    disclaimer_status_reset_one: "Aviso restablecido: {type}",
    disclaimer_status_reset_all: "Todos los avisos restablecidos",
    disclaimer_status_footer_one:
      "Para restablecer uno: mcp-verify disclaimers reset --type {type}",
    disclaimer_status_footer_all:
      "Para restablecer todos: mcp-verify disclaimers reset",

    just_now: "Ahora mismo",
    heatmap_modal_title: "Análisis de Celda de Riesgo",
    heatmap_modal_impact: "Nivel de Impacto",
    heatmap_modal_probability: "Nivel de Probabilidad",
    heatmap_modal_findings: "Hallazgos en esta categoría",
    heatmap_modal_explanation: "Explicación",
    heatmap_modal_action: "Acción Recomendada",
    heatmap_critical_explain:
      "Esta celda representa la categoría de riesgo más alta - hallazgos con alto impacto y alta probabilidad de explotación. Estas vulnerabilidades representan amenazas inmediatas a la seguridad del sistema y requieren remediación urgente.",
    heatmap_high_explain:
      "Esta celda representa hallazgos de alto riesgo que tienen alto impacto con probabilidad media, o impacto medio con alta probabilidad. Estos deben ser priorizados para remediación.",
    heatmap_medium_explain:
      "Esta celda representa hallazgos de riesgo medio. Aunque no son inmediatamente críticos, estas vulnerabilidades deben abordarse en tu hoja de ruta de seguridad.",
    heatmap_low_explain:
      "Esta celda representa hallazgos de bajo riesgo. Estas son buenas oportunidades para mejoras de seguridad pero pueden programarse para ciclos de remediación posteriores.",
    heatmap_action_critical:
      "Acción inmediata requerida. Remediar en 24-48 horas. Considerar despliegue de parche de seguridad de emergencia.",
    heatmap_action_high:
      "Alta prioridad. Abordar en 1-2 semanas. Programar remediación en próximo sprint.",
    heatmap_action_medium:
      "Prioridad media. Abordar en 1-2 meses. Incluir en mejoras de seguridad trimestrales.",
    heatmap_action_low:
      "Baja prioridad. Abordar cuando los recursos lo permitan. Considerar para futuras mejoras de seguridad.",
    view_findings: "Ver Hallazgos",
    close: "Cerrar",
    risk_breakdown: "Desglose de Riesgo",
    score_calculation: "Cálculo de Puntaje",
    severity_weight: "Peso por Severidad",
    contribution: "Contribución",
    total_findings: "Total de Hallazgos",
    weighted_average: "Promedio Ponderado",
    expand_breakdown: "Expandir Desglose",
    collapse_breakdown: "Contraer Desglose",
    compliance_matrix: "Matriz de Cumplimiento",
    framework_mapping: "Mapeo de Frameworks",
    compliance_score: "Puntaje de Cumplimiento",
    owasp_top_10: "OWASP Top 10",
    cwe_mapping: "CWE",
    nist_controls: "Controles NIST SP 800-53",
    pci_dss: "PCI-DSS",
    iso_27001: "ISO 27001",
    compliant: "Cumple",
    non_compliant: "No Cumple",
    partial_compliance: "Cumplimiento Parcial",
    view_details: "Ver Detalles",
    historical_trends: "Tendencias Históricas",
    security_evolution: "Evolución de Seguridad",
    trend_improving: "Mejorando",
    trend_degrading: "Degradando",
    trend_stable: "Estable",
    baseline_comparison: "Comparación con Línea Base",
    current_scan: "Escaneo Actual",
    previous_scan: "Escaneo Anterior",
    delta: "Delta",
    executive_summary: "Resumen Ejecutivo",
    overall_risk_rating: "Calificación General de Riesgo",
    top_critical_issues: "Principales Problemas Críticos",
    security_posture: "Postura de Seguridad",
    requires_immediate_action: "Requiere Acción Inmediata",
    requires_attention: "Requiere Atención",
    satisfactory: "Satisfactorio",
    excellent: "Excelente",
    critical_findings_detected: "Hallazgos críticos detectados",
    moderate_findings_detected: "Hallazgos moderados detectados",
    minor_findings_detected: "Hallazgos menores detectados",
    no_major_findings: "Sin hallazgos mayores",
    remediation_checklist: "Lista de Remediación",
    priority: "Prioridad",
    status: "Estado",
    estimated_time: "Tiempo Estimado",
    hours: "horas",
    hour: "hora",
    export_checklist: "Exportar Lista",
    mark_as_done: "Marcar como Completado",
    pending: "Pendiente",
    quick_filters: "Filtros Rápidos",
    filter_by_severity: "Filtrar por Severidad",
    filter_by_category: "Filtrar por Categoría",
    has_fix_available: "Tiene Solución Disponible",
    reset_filters: "Resetear Filtros",
    showing_findings: "Mostrando {count} hallazgos",
    all_severities: "Todas las Severidades",
    all_categories: "Todas las Categorías",
    tools: "Herramientas",
    quality: "Calidad",
    findings: "Hallazgos",
    issues_found: "problemas encontrados",
    critical: "Crítico",
    high: "Alto",
    medium: "Medio",
    low: "Bajo",
    quality_suggestions: "sugerencias de calidad",
    compliance: "Cumplimiento",
    jsonrpc_20: "JSON-RPC 2.0",
    no_risks: "¡No se detectaron riesgos de seguridad!",
    tip_label: "Consejo",
    stats: "Estadísticas",
    resources: "Recursos",
    prompts: "Prompts",
    architecture_map: "Mapa de Arquitectura",
    zoom_instructions: "Scroll para zoom, arrastra para mover",
    input_schema: "Esquema de Entrada",
    generated_by: "Generado por",
    view_on_github: "Ver en GitHub",
    security_standards: "Estándares de Seguridad",
    status_valid: "Válido",
    status_invalid: "Inválido",
    no_description: "Sin descripción disponible",
    na_label: "N/A",
    violations_detected: "Violaciones detectadas",
    standard_compliant: "Cumple el estándar",
    sec_heuristic_detected: "{msg} detectado en la herramienta",
    finding_rate_limit_missing: "Limitación de tasa no implementada",
    // Security Finding Keys
    finding_auth_weak_hashing:
      "La herramienta {tool} utiliza algoritmos de hash débiles",
    finding_auth_no_hashing_method:
      "La herramienta {tool} no especifica un método de hash de contraseñas",
    finding_auth_min_length:
      "El parámetro {param} carece de requisito de longitud mínima",
    finding_auth_complexity:
      "El parámetro {param} carece de requisitos de complejidad",
    finding_auth_user_enumeration:
      "El parámetro {param} podría permitir la enumeración de usuarios",
    finding_auth_credentials_plain:
      "El parámetro {param} acepta credenciales en texto plano",
    finding_auth_no_hashing:
      "La herramienta {tool} no parece utilizar hash fuerte",
    finding_auth_no_brute_force:
      "La herramienta {tool} carece de indicadores de protección contra fuerza bruta",
    finding_deserialization_dangerous:
      "La herramienta {tool} parece deserializar un formato peligroso: {format}",
    remediation_deserialization_safe:
      "Utilice un formato de deserialización seguro como JSON en lugar de {format}",
    finding_deserialization_unsafe_yaml:
      "La herramienta {tool} utiliza una carga YAML insegura, permitiendo la ejecución de código arbitrario.",
    finding_deserialization_no_schema:
      "La herramienta {tool} deserializa datos sin un esquema estricto, lo que lleva a una posible inyección de objetos.",
    finding_deserialization_no_type:
      "El parámetro {param} es un objeto sin tipo explícito, permitiendo la inyección de objetos arbitrarios.",
    finding_deserialization_arbitrary:
      "El parámetro {param} permite propiedades de objeto arbitrarias, lo que puede conducir a ataques de inyección.",
    finding_deserialization_encoded:
      "El parámetro {param} acepta datos codificados que pueden ocultar objetos serializados.",
    finding_deserialization_no_security:
      "La descripción de la herramienta {tool} no menciona ninguna medida de seguridad contra los ataques de deserialización.",
    finding_cmd_injection_no_schema:
      "La herramienta {tool} parece ejecutar comandos pero carece de esquema",
    finding_cmd_injection_no_validation:
      "El parámetro {param} en la herramienta {tool} carece de patrón de validación",
    finding_cmd_injection_weak_validation:
      "El parámetro {param} utiliza un patrón de validación débil",
    finding_sql_no_schema:
      "La herramienta {tool} parece ejecutar SQL pero carece de esquema de entrada",
    finding_sql_potential:
      "El parámetro {param} en la herramienta {tool} es vulnerable a inyección SQL",
    finding_sql_type_mismatch:
      "El parámetro {param} debería ser numérico pero acepta cadenas",
    finding_sql_no_prepared:
      "La descripción de la herramienta {tool} no menciona sentencias preparadas",
    finding_ssrf_potential:
      "El parámetro {param} parece ser una entrada URL sin validación",
    finding_ssrf_weak_val:
      "El parámetro {param} tiene una validación de URL débil",
    finding_xxe_dangerous_parser:
      "La herramienta {tool} parece usar una configuración de parser XML peligrosa",
    finding_xxe_no_schema:
      "La herramienta {tool} procesa XML pero carece de esquema de entrada",
    finding_xxe_no_pattern:
      "El parámetro {param} carece de patrón de validación XML",
    finding_xxe_uploads: "El parámetro {param} acepta subida de archivos XML",
    finding_xxe_svg: "El parámetro {param} acepta entrada SVG",
    finding_xxe_no_protection:
      "La herramienta {tool} no deshabilita explícitamente entidades externas",
    finding_path_traversal_static_uri:
      "El recurso {resource} apunta a una ruta del sistema potencialmente sensible: {uri}",
    finding_path_traversal_dynamic_uri:
      "El recurso {resource} utiliza una URI dinámica sin restricciones",
    finding_path_traversal_file_scheme:
      "El recurso {resource} usa esquema file:// con segmentos dinámicos",
    finding_path_traversal_weak_pattern:
      "El parámetro {param} usa validación de ruta débil",
    finding_data_leakage_sensitive:
      "La herramienta {tool} acepta datos sensibles '{param}' como argumento",
    finding_data_leakage_resource:
      "El recurso {resource} expone un archivo potencialmente sensible",
    finding_sensitive_no_format:
      "El parámetro {param} ({category}) carece de especificación de formato",
    finding_sensitive_no_pattern:
      "El parámetro {param} ({category}) carece de patrón de validación",
    finding_sensitive_logging:
      "El parámetro {param} ({category}) podría ser registrado en logs",
    finding_sensitive_no_protection:
      "La herramienta {tool} maneja datos de {category} sin protección",
    finding_sensitive_response:
      "La herramienta {tool} devuelve datos de {category} en {prop}",
    finding_rate_limit_auth_must:
      "La herramienta de autenticación {tool} debe implementar límites de tasa estrictos",
    finding_rate_limit_no_size:
      "El parámetro de subida de archivo {param} carece de límites de tamaño",
    finding_redos_vulnerable:
      "El parámetro {param} tiene un patrón de regex vulnerable que puede conducir a ReDoS.",
    finding_redos_no_anchors:
      "La regex para el parámetro {param} no está anclada, lo que puede llevar a una coincidencia ineficiente.",
    finding_crypto_weak_encryption:
      "La herramienta {tool} usa cifrado débil {algo}",
    finding_crypto_weak_hashing: "La herramienta {tool} usa hash débil {algo}",
    finding_crypto_insecure_random:
      "La herramienta {tool} usa aleatoriedad insegura {method}",
    finding_crypto_short_key: "El parámetro {param} permite claves cortas",
    finding_crypto_danger_short:
      "El parámetro {param} permite claves peligrosamente cortas",
    finding_crypto_weak_selection:
      "El parámetro {param} permite seleccionar algoritmos débiles",
    finding_crypto_no_algorithms:
      "La herramienta {tool} no especifica algoritmos fuertes",
    finding_prompt_injection_no_limit:
      "El parámetro {param} en la herramienta {tool} carece de límites de longitud",
    finding_prompt_injection_no_pattern:
      "El parámetro {param} en la herramienta {tool} carece de patrón de validación",
    finding_prompt_injection_prompt_args:
      "El prompt {prompt} acepta argumentos sin esquema de validación",
    finding_prompt_injection_indirect:
      "La herramienta {tool} obtiene contenido externo (palabra clave: {keyword}) - vector potencial de inyección indirecta",
    finding_prompt_injection_chain:
      "CRÍTICO: La herramienta {tool} obtiene Y procesa contenido externo - alto riesgo de inyección indirecta",
    finding_prompt_injection_weak_pattern:
      "El parámetro {param} en la herramienta {tool} tiene un patrón de validación débil que permite inyección",

    // MCP Server Tools
    mcp_tool_validate_server_desc:
      "Valida un servidor MCP (conexión, esquema, seguridad, calidad).",
    mcp_tool_scan_security_desc:
      "Realiza un escaneo de seguridad enfocado en un servidor MCP.",
    mcp_tool_analyze_quality_desc:
      "Analiza la calidad y semántica de herramientas y recursos MCP.",
    mcp_tool_generate_report_desc:
      "Genera un reporte de validación completo en varios formatos.",
    mcp_tool_list_installed_servers_desc:
      "Lista servidores MCP configurados en el entorno local (ej. Claude Desktop).",
    mcp_tool_self_audit_desc:
      "Realiza una auto-auditoría de la instalación de mcp-verify.",
    mcp_tool_compare_servers_desc:
      "Compara dos servidores MCP (ej. pruebas de regresión).",

    // MCP Server Parameters
    mcp_param_command_desc:
      'El comando para iniciar el servidor MCP (ej. "node server.js").',
    mcp_param_command_desc_short: "Comando de inicio del servidor.",
    mcp_param_command_desc_compare: "Comando de inicio para este servidor.",
    mcp_param_args_desc: "Argumentos para el comando.",
    mcp_param_args_desc_compare: "Argumentos para este servidor.",
    mcp_param_config_path_desc: "Ruta a mcp-verify.config.json (opcional).",
    mcp_param_config_path_desc_claude:
      "Ruta a la config de Claude Desktop (opcional).",
    mcp_param_rules_desc:
      "Reglas de seguridad específicas a habilitar (opcional).",
    mcp_param_format_desc: "Formato del reporte (json, sarif, text).",
    mcp_param_output_path_desc: "Directorio para guardar el reporte.",
    mcp_param_skip_validation_desc:
      "Saltar validación activa del servidor durante la auditoría.",
    mcp_param_server_name_desc: "Nombre del servidor.",
    mcp_param_servers_desc: "Lista de servidores a comparar.",

    // MCP Errors
    mcp_error_unknown_tool: "Herramienta desconocida solicitada",
    mcp_error_connection_failed: "Conexión al servidor MCP fallida",
    mcp_error_failed_to_connect_quality:
      "Falló la conexión para análisis de calidad",
    mcp_error_failed_to_analyze_quality: "Análisis de calidad fallido",
    mcp_error_at_least_two_servers:
      "Se requieren al menos dos servidores para comparar",
    mcp_error_please_provide_two_servers:
      "Por favor proporcione al menos dos servidores",
    mcp_error_config_not_found_audit:
      "Archivo de configuración no encontrado para auditoría",
    mcp_error_failed_to_discover_servers:
      "Falló el descubrimiento de servidores instalados",
    mcp_error_handshake_failed: "Handshake de protocolo fallido",
    mcp_error_failed_to_connect: "Falló la conexión al servidor",
    mcp_error_failed_to_validate: "Validación fallida",
    mcp_error_failed_to_compare_servers: "Falló la comparación de servidores",
    mcp_error_failed_to_generate_report: "Falló la generación del reporte",
    mcp_error_unsupported_platform: "Plataforma no soportada",
    mcp_error_config_not_found: "Archivo de configuración no encontrado",
    mcp_error_failed_to_read_config: "Falló la lectura de la configuración",
    mcp_error_failed_to_connect_security:
      "Falló la conexión para el escaneo de seguridad",
    mcp_error_failed_to_scan_security: "Escaneo de seguridad fallido",
    mcp_error_native_addon_not_available:
      "Módulo nativo no disponible: {addon}",
    mcp_error_native_addon_not_found_sea:
      '[mcp-verify] Módulo nativo "{addon}" no encontrado junto al ejecutable.\n  Se esperaba archivo .node en: {dir}\n  Ejecute el script de lanzamiento para incluir los módulos nativos con el binario.',
    mcp_error_native_addon_not_installed:
      '[mcp-verify] Módulo nativo "{addon}" no instalado. Ejecute: npm install',
    mcp_error_keychain_save_failed:
      "Error al guardar la clave API en el llavero: {error}",
    mcp_error_keychain_get_failed: "Error al obtener la clave API del llavero",
    mcp_unknown_server: "Servidor Desconocido",
    mcp_not_available: "No Disponible",
    unknown_version: "Versión Desconocida",

    // LLM Errors
    llm_invalid_spec: "Especificación de proveedor LLM inválida: {spec}",
    llm_env_not_set: "Variable de entorno para {provider} no configurada",
    llm_key_invalid_format: "Formato de clave API inválido para {provider}",
    llm_key_too_short: "Clave API demasiado corta para {provider}",
    llm_unknown_provider: "Proveedor LLM desconocido: {provider}",
    llm_init_failed: "Falló la inicialización de {provider}: {error}",
    llm_validation_failed: "Falló la validación para {provider}: {error}",
    llm_analysis_failed: "Análisis LLM fallido: {error}",
    ollama_model_not_found: "Modelo Ollama no encontrado",
    ollama_timeout: "La solicitud a Ollama expiró después de {timeout}ms",
    ollama_api_error: "Error de API Ollama: {error}",

    // Markdown Generator Keys
    suggested_solution: "Solución Sugerida",
    md_security_findings: "Hallazgos de Seguridad",
    md_no_critical_findings: "No se detectaron hallazgos críticos.",
    md_capabilities_overview: "Resumen de Capacidades",
    table_desc: "Descripción",
    table_status: "Estado",
    md_valid: "Válido",
    md_invalid: "Inválido",
    md_passed: "Pasó",
    md_severity: "Severidad",
    md_report_generated_by: "Reporte generado por",
    md_report_date: "Fecha",
    md_total: "Total",
    md_tools: "Herramientas",
    architecture_diagram: "Diagrama de Arquitectura",
    client_label: "Cliente",
    transport_label: "Transporte",
    functionality_label: "Funcionalidad",
    mcp_security_score: "Puntaje de Seguridad",
    safety_layer_label: "Capa de Seguridad",
    md_protocol_compliance: "Cumplimiento de Protocolo",
    protocol_spec: "Especificación de Protocolo",
    schema_valid: "Validación de Esquema",
    protocol_issues_detected: "Problemas de Protocolo Detectados",
    unknown_server: "Servidor Desconocido",
    md_executive_summary: "Resumen Ejecutivo",
    md_property: "Propiedad",
    md_value: "Valor",
    md_server_name: "Nombre del Servidor",
    md_protocol_version: "Versión del Protocolo",
    md_quality_score: "Puntaje de Calidad",
    md_finding: "Hallazgo",
    md_rule: "Regla",
    details_header: "Detalles",
    md_remediation: "Remediación",

    // Scan History Keys
    failed_parse_scan_file:
      "Error al procesar archivo de escaneo {id}: {error}",
    scan_not_found: "Escaneo {id} no encontrado",
    unknown_reason: "Razón desconocida",

    // Heuristic Keys
    sec_heuristic_rce: "Riesgo de Ejecución Remota de Código",
    sec_heuristic_auth: "Riesgo de Autenticación/Credenciales",
    sec_heuristic_fs: "Riesgo de operación en Sistema de Archivos",
    sec_heuristic_db: "Riesgo de operación en Base de Datos",
    sec_heuristic_net: "Riesgo de operación de Red",

    // Block A: OWASP LLM Top 10 in MCP Context (SEC-022 to SEC-030)
    sec_022_insecure_output_chained:
      'La herramienta "{toolName}" emite datos sin escapar que son consumidos por otras herramientas. Habilita XSS almacenado, inyección de comandos e inyección indirecta de prompts cuando el output contamina el contexto del agente.',
    sec_022_insecure_output_standalone:
      'La herramienta "{toolName}" emite datos sin restricciones de sanitización. Falta declaración de format o contentEncoding en el schema de salida.',
    sec_022_recommendation:
      'Agregar schema de salida con contentEncoding: "base64" o metadata explícita de sanitización. Alternativamente, agregar description: "Los outputs están HTML-escaped" o equivalente. Nunca pasar outputs de tools directamente a eval(), exec(), o contexto LLM sin validación.',

    // Block B: Multi-Agent & Agentic Chain Attacks (SEC-031 to SEC-041)
    sec_031_agent_spoofing:
      'La herramienta privilegiada "{toolName}" no verifica la identidad del agente. Agentes maliciosos pueden hacerse pasar por agentes de confianza (Claude, orchestrators) para acceder a operaciones restringidas. Faltan parámetros de autenticación (api_key, agent_id, token) o verificación de identidad.',
    sec_031_recommendation:
      'Agregar parámetro de autenticación al inputSchema: agent_id (requerido), api_key (requerido), o session_token (requerido). Alternativamente, agregar description: "Requiere identidad de agente verificada" e implementar validación del lado del servidor contra registro de agentes.',

    // Block C: Operational & Enterprise Compliance (SEC-042 to SEC-050)
    sec_042_missing_audit_logging:
      "El servidor no expone ningún mecanismo de logging de auditoría. Faltan herramientas como get_audit_log, list_events, o capacidades de logging. Crítico para cumplimiento SOC 2, ISO 27001 y GDPR en sistemas AI autónomos.",
    sec_043_no_invalidation:
      "Múltiples herramientas ({count}) gestionan sesiones pero no se proporciona ninguna herramienta de cierre de sesión/invalidación.",
    sec_042_recommendation:
      "Implementar herramientas de logging de auditoría: get_audit_log(time_range, filter), export_audit_trail(format), o equivalente. Incluir timestamps, identificadores de usuario, acciones realizadas y resultados.",
    sec_043_session_mgmt:
      'La herramienta "{toolName}" utiliza tokens de sesión sin expiración ni invalidación. Las sesiones pueden ser secuestradas y reutilizadas indefinidamente.',
    sec_043_recommendation:
      "Implementar expiración de sesión: agregar ttl/expires_at a los parámetros de sesión, proporcionar herramientas de logout/invalidación, usar tokens de corta duración (≤1 hora) con mecanismo de refresh.",
    sec_044_no_versioning:
      "El servidor no declara la versión en serverInfo. Impide verificaciones de compatibilidad, comparaciones con baseline y seguimiento de parches de seguridad.",
    sec_044_no_server_version:
      "Al servidor le falta el versionado semántico en sus metadatos. Crítico para el seguimiento de regresiones de seguridad.",
    sec_044_recommendation:
      "Agregar el campo version a serverInfo usando versionado semántico (1.0.0). Documentar breaking changes, implementar negociación de versión en el handshake.",
    sec_045_error_granularity:
      "Las respuestas de error de la herramienta pueden ser demasiado detalladas, filtrando detalles de implementación interna. (Requiere fuzzing en tiempo de ejecución para confirmar)",
    sec_045_recommendation:
      "Asegurar que los mensajes de error sean útiles pero sanitizados. Eliminar stack traces, detalles del entorno y rutas internas de las respuestas de error en producción.",
    sec_046_no_cors_mention:
      "La descripción del servidor no menciona CORS o validación de origen para transporte HTTP/SSE. Riesgo de ataques CSRF/cross-origin en desarrollo.",
    sec_046_recommendation:
      "Implementar una política CORS estricta: lista blanca de orígenes permitidos, rechazar solicitudes con encabezados Origin inválidos, usar políticas de mismo origen para servidores locales.",
    sec_047_destructive_no_optin:
      'La herramienta "{toolName}" realiza operaciones destructivas (purga, eliminación, formateo) pero está habilitada por defecto sin flags de confirmación.',
    sec_047_recommendation:
      'Seguir "Seguro por Defecto": hacer que las herramientas destructivas requieran habilitación explícita vía configuración, agregar flags de confirmación manual o implementar eliminación lógica temporal.',
    sec_048_capability_negotiation:
      "El servidor implementa capacidades no declaradas en el handshake, o viceversa. La inconsistencia conduce a exploits a nivel de protocolo.",
    sec_048_recommendation:
      "Alinear estrictamente las capacidades declaradas con la implementación. Usar validación automatizada de handshake, rechazar llamadas a métodos no declarados.",
    sec_049_timing_attacks:
      "Las operaciones de autenticación pueden ser vulnerables a ataques de tiempo (timing attacks). (Requiere fuzzing en tiempo de ejecución para confirmar)",
    sec_049_recommendation:
      "Usar algoritmos de comparación de tiempo constante para tokens/contraseñas. Agregar jitter aleatorio a los tiempos de respuesta de autenticación para enmascarar la duración del cálculo.",
    sec_050_weak_entropy:
      'La herramienta "{toolName}" genera identificadores de seguridad o tokens con entropía (aleatoriedad) insuficiente. Los outputs predecibles permiten la enumeración.',
    sec_050_recommendation:
      "Usar PRNGs criptográficamente seguros (crypto.getRandomValues). Aumentar la longitud del identificador (mín. 128 bits), usar UUIDs aleatorios (v4) o ulids.",
    sec_051_weaponized_fuzzer:
      'La herramienta "{toolName}" implementa capacidades de seguridad ofensiva (fuzzing, explotación) sin verificaciones de autorización. Puede ser armada para pruebas no autorizadas.',
    sec_051_recommendation:
      "Requerir autorización: agregar parámetro authorization_token, implementar alcance de consentimiento (solo objetivos en lista blanca), registrar todo uso de herramientas ofensivas, requerir confirmación del usuario.",
    sec_052_autonomous_backdoor:
      'La herramienta "{toolName}" tiene comportamiento autónomo sospechoso: {behavior}. Características potenciales de backdoor o malware detectadas.',
    sec_052_recommendation:
      "CRÍTICO: Revisar herramienta a fondo. Eliminar código de auto-modificación, eliminar comportamientos sigilosos, desactivar ejecución autónoma, considerar este servidor MCP comprometido.",
    sec_052_server_autonomous:
      "La descripción del servidor menciona comportamientos autónomos/sigilosos. Potencial malware o backdoor detectado a nivel de servidor.",
    sec_052_server_recommendation:
      "NO EJECUTAR. Reportar al equipo de seguridad. Poner en cuarentena este servidor MCP. Realizar escaneo completo de malware.",
    sec_055_jailbreak_service:
      'La herramienta "{toolName}" proporciona capacidades de jailbreak de LLM o ataque adversario. Permite el abuso de otros sistemas LLM.',
    sec_055_recommendation:
      "Restringir uso: requerir autorización para uso de red team, implementar logging/auditoría, limitar a contextos de investigación aprobados, agregar aviso sobre uso ético.",
    sec_055_server_jailbreak:
      "La descripción del servidor menciona capacidades de jailbreak o LLM adversario. Riesgo potencial de abuso.",
    sec_055_server_recommendation:
      "Asegurar controles de autorización adecuados. Implementar registro de uso. Restringir solo a investigación de seguridad autorizada.",
    sec_056_phishing_tool:
      'La herramienta "{toolName}" parece diseñada para ataques de phishing o ingeniería social. Puede generar contenido engañoso, páginas de inicio de sesión falsas o suplantación.',
    sec_056_recommendation:
      "Eliminar capacidades de phishing o restringir solo a pruebas de seguridad autorizadas. Implementar registro estricto, requerir tokens de autorización, agregar avisos de uso ético.",
    sec_057_steganography:
      'La herramienta "{toolName}" implementa esteganografía (ocultación de datos en medios). Puede usarse para exfiltración encubierta de datos.',
    sec_057_recommendation:
      "Implementar controles DLP: registrar todas las operaciones de codificación, requerir autorización para herramientas de esteganografía, monitorear patrones anómalos de generación de medios.",
    sec_058_self_replicating:
      'La herramienta "{toolName}" tiene capacidades de auto-replicación: {capability}. Comportamiento tipo gusano detectado - puede propagarse a otros sistemas.',
    sec_058_recommendation:
      "CRÍTICO: Poner en cuarentena este servidor MCP inmediatamente. Eliminar código de replicación. Reportar al equipo de seguridad. Considerar esto malware.",
    sec_058_server_worm:
      "La descripción del servidor menciona auto-replicación o comportamiento de gusano. Malware detectado.",
    sec_058_server_recommendation:
      "NO EJECUTAR. Poner en cuarentena. Realizar análisis de malware. Reportar a las autoridades de seguridad.",

    // Block D: AI Weaponization & Supply Chain (SEC-051 to SEC-060)
    sec_053_malicious_pattern:
      'CRÍTICO: El servidor "{serverName}" tiene patrón de comando malicioso: {pattern}. Comando: {command}. Este es el vector exacto de CVE-2025-59536 - se ejecuta sin consentimiento del usuario.',
    sec_053_recommendation:
      "NO ejecutes este proyecto. Elimina la configuración de servidor malicioso. Reporta al equipo de seguridad si esto vino de un repositorio público.",
    sec_053_supply_chain_warning:
      "ATAQUE DE SUPPLY CHAIN DETECTADO: Este .mcp.json está en un repositorio Git. Cualquiera que clone este repo ejecutará el payload malicioso automáticamente.",
    sec_053_supply_chain_recommendation:
      "Reporta este repositorio inmediatamente. No hagas push de commits. Considera este repo comprometido.",
    sec_053_env_hijacking:
      'El servidor "{serverName}" sobrescribe el endpoint de API: {envVar} = {value}. Esto puede exfiltrar API keys antes de cualquier prompt de confianza (CVE-2026-21852).',
    sec_054_endpoint_hijacking:
      'El servidor "{serverName}" sobrescribe endpoint de API: {envVar} = {value}. Puede exfiltrar claves API en la PRIMERA solicitud (CVE-2026-21852).',
    sec_054_tool_endpoint_hijacking:
      'La herramienta "{tool}" puede registrar o secuestrar endpoints de API sin validación apropiada. Permite manipulación no autorizada de endpoints.',
    sec_054_recommendation:
      "Elimina el override del endpoint de API. Solo usa endpoints oficiales: api.anthropic.com, api.openai.com. Overrides a localhost requieren justificación explícita.",
    sec_059_unvalidated_auth:
      'La herramienta "{toolName}" {reason}. Falta de validación de autorización permite escalación de privilegios.',
    sec_059_recommendation:
      "Agregar parámetros de autorización: requerir token/permission_level, implementar verificaciones RBAC, validar identidad del llamador antes de invocación de herramienta.",
    sec_060_missing_transaction:
      'La herramienta "{toolName}" realiza operaciones críticas multi-paso sin semántica de transacción. Sin mecanismo de rollback/deshacer si la operación falla a mitad de camino.',
    sec_060_recommendation:
      "Implementar semántica de transacción: agregar parámetro rollback_on_error, proporcionar mecanismo de deshacer, usar transaction_id para operaciones atómicas, implementar modo dry-run.",
    sec_061_server_name:
      'El nombre del servidor "{name}" contiene caracteres no-ASCII de bloques Unicode confusables ({blocks}) mezclados con letras ASCII: {positions}. Esto habilita spoofing por homoglifos — el nombre parece idéntico a un servidor legítimo pero difiere a nivel de codepoint, evadiendo verificaciones de listas blancas.',
    sec_061_tool_name:
      'El nombre de herramienta "{toolName}" contiene caracteres no-ASCII de bloques Unicode confusables ({blocks}) mezclados con letras ASCII: {positions}. Los atacantes usan caracteres visualmente similares para registrar herramientas maliciosas que evaden verificaciones de seguridad basadas en nombres.',
    sec_061_resource_name:
      'El recurso "{resourceName}" contiene caracteres no-ASCII de bloques Unicode confusables ({blocks}) mezclados con letras ASCII: {positions}. Los caracteres visualmente similares en identificadores de recursos pueden evadir listas de control de acceso y filtros de monitoreo.',
    sec_061_recommendation:
      "Restringir el nombre del servidor, nombres de herramientas e identificadores de recursos solo a caracteres ASCII (A-Z, a-z, 0-9, guiones, guiones bajos). Implementar normalización Unicode (NFC/NFKC) antes de comparaciones. Usar base de datos de confusables Unicode (UTS#39) para validar identificadores al momento del registro.",

    // Remediation Keys (from rule files)
    ssrf_insecure_http: "El patrón permite HTTP inseguro",
    ssrf_wildcard_start: "El patrón comienza con comodín",
    ssrf_not_anchored: "El patrón no está anclado (^...$)",
    risk_crypto_broken: "El algoritmo {algo} está roto y es inseguro",
    risk_crypto_insufficient:
      "El algoritmo {algo} tiene un margen de seguridad insuficiente",
    risk_crypto_collision:
      "La función hash {algo} es vulnerable a ataques de colisión",
    risk_crypto_resistance:
      "La función hash {algo} es débil contra ataques modernos",
    // End HTML Report Keys
    about_feature_i18n: "Internacionalización (EN/ES)",
    about_feature_llm: "Análisis semántico con LLM (opcional)",
    about_feature_owasp: "60 reglas de seguridad (6 bloques)",
    about_feature_protocol: "Validación de protocolo MCP",
    about_feature_reports:
      "Múltiples formatos de reporte (JSON, HTML, SARIF, MD)",
    active_guardrails: "🛡️  Guardrails Activos (v1.0):",
    add_a_clear_description_explaining_what_the_tool_d:
      "Añade una descripción clara explicando qué hace la herramienta.",
    all_checks_passed:
      "¡Todas las verificaciones pasaron! El servidor se ve saludable.",
    all_tests_passed_label: "Todas las pruebas pasaron",
    allowed_label: "Permitido",
    anthropic_api_key_not_configured: "Clave API de Anthropic no configurada",
    anthropic_invalid_key_format:
      "[Anthropic] Formato de clave API inválido. Esperado: sk-ant-...",
    attempted_label: "Intentado",
    available_capabilities: "Capacidades Disponibles",
    avoid_passing_secrets_as_tool_arguments_use_enviro:
      "Evita pasar secretos como argumentos de herramienta. Usa variables de entorno o plantillas de recursos MCP para gestión de credenciales y prevenir fugas en logs de contexto LLM.",
    avoid_using_file_uris_with_dynamic_segments_if_nec:
      "Evita usar URIs file:// con segmentos dinámicos. Si es necesario, implementa canonización de rutas estricta, encierra el acceso a archivos en un directorio específico y valida contra lista blanca.",
    badge: "Insignia",
    baseline_parse_error: "Error al analizar el archivo de baseline: {error}",
    baseline_critical_degradation:
      "CRÍTICO: ¡{count} nuevos hallazgos críticos!",
    baseline_score_dropped:
      "La puntuación bajó más del umbral permitido (Seguridad: {sec}, Calidad: {qual})",
    baseline_degraded:
      "La puntuación general se ha degradado (Seguridad: {sec}, Calidad: {qual})",
    baseline_improved:
      "¡La puntuación general ha mejorado! (Seguridad: +{sec}, Calidad: +{qual}, Corregidos: {fixed})",
    baseline_build_failed:
      "Fallo de compilación: La comparación con el baseline detectó una degradación inaceptable",
    baseline_comparison_title: "Comparación con Baseline",
    baseline_label: "Baseline",
    preparing_print: "Preparando para imprimir...",
    baseline_no_changes: "➡️ Sin cambios significativos respecto al baseline",
    baseline_saved_at: "Baseline guardado en",
    basic_validation: "Validación Básica",
    blocked_by_guardrail: "Bloqueado por Guardrail",
    blocked_label: "Bloqueado",
    blocked_log: "BLOQUEADO",
    cannot_resolve: "No se puede resolver el hostname",
    change_language_cambiar_idioma: "Cambiar idioma / Cambiar idioma",
    chart_distribution: " (Distribución)",
    check_hostname_reachable:
      "Verifica que el hostname sea correcto y alcanzable",
    check_initialization_errors:
      "Revisa logs del servidor para errores de inicialización",
    check_protocol_version: "Verifica compatibilidad de versión de protocolo",
    check_server_load: "Verifica que el servidor pueda manejar la carga",
    check_server_running_detail: "Verifica que el servidor esté corriendo",
    check_url_correct: "Verifica que la URL sea correcta",
    ci_cd_integration: "Integración CI/CD",
    cleaning_up: "Limpiando recursos...",
    cleanup_complete: "¡Limpieza completa. Hasta luego!",
    cleanup_error: "Error durante la limpieza:",
    cli_description: "Herramienta CLI para validar y probar servidores MCP",
    cli_disclaimer_affiliation:
      "No está afiliado con Anthropic ni la organización Model Context Protocol.",
    cli_command: "Comando CLI",
    cli_disclaimer_independent:
      "Esta es una herramienta open-source independiente.",
    client_connected_sse: "Cliente conectado a Proxy SSE",
    client_disconnected_sse: "Cliente desconectado de Proxy SSE",
    clients_for: "clientes por",
    copied: "¡Copiado!",
    copy: "Copiar",
    current_label: "Actual",
    cmd_clear: "Limpiar pantalla",
    cmd_dashboard_desc: "Lanzar dashboard web interactivo",
    cmd_doctor_desc:
      "Diagnosticar problemas de conexión o verificar entorno local",
    cmd_examples_desc: "Mostrar ejemplos de uso",
    cmd_exit: "Salir",
    cmd_help: "Mostrar ayuda",
    cmd_init_desc: "Crear archivo de configuración por defecto",
    cmd_mock_desc: "Iniciar servidor MCP dummy",
    cmd_playground_desc: "Entrar al playground interactivo de herramientas",
    cmd_proxy_desc: "Iniciar gateway proxy de seguridad",
    cmd_stress_desc: "Ejecutar pruebas de carga en un servidor MCP",
    cmd_fuzz_desc: "Ejecutar fuzzing de seguridad en un servidor MCP",
    cmd_scan_config_desc:
      "Escanear archivos de configuración MCP en busca de patrones maliciosos (Block D)",
    dashboard_title: "Dashboard de MCP-Verify",
    dashboard_brand: "MCP-Verify",
    dashboard_connecting: "Conectando...",
    dashboard_traffic_inspector: "Inspector de Tráfico",
    dashboard_interactive_playground: "Playground Interactivo",
    version_author: "por Fink",
    dashboard_live_traffic: "Tráfico en Vivo",
    dashboard_clear: "Limpiar",
    dashboard_waiting_requests: "Esperando solicitudes...",
    dashboard_connect_client: "Conecta un cliente para ver el tráfico",
    dashboard_configure_request: "Configurar Solicitud",
    dashboard_tool_capability: "Herramienta/Capacidad",
    dashboard_select_tool: "Selecciona una herramienta...",
    dashboard_run_tool: "Ejecutar Herramienta",
    dashboard_response: "Respuesta",
    dashboard_results_placeholder: "Los resultados aparecerán aquí...",
    dashboard_no_arguments: "La herramienta no tiene argumentos.",
    dashboard_running: "Ejecutando...",
    dashboard_connected: "Conectado",
    dashboard_reconnecting: "Reconectando...",
    dashboard_starting: "Iniciando Dashboard...",
    dashboard_target_server: "Servidor de Destino:",
    dashboard_active_at: "Dashboard activo en",
    dashboard_connecting_server: "Conectando al servidor...",
    dashboard_connected_count:
      "¡Conectado! Se descubrieron {count} herramientas.",
    dashboard_error_connect: "Error al conectar con el servidor.",
    dashboard_mock_mode: "Usando herramientas de simulación.",
    calculator_desc: "Una herramienta de calculadora simple.",
    get_weather_desc: "Obtiene el clima para una ubicación dada.",
    dashboard_exec_failed: "La ejecución falló",
    dashboard_unknown_exec_error: "Error de ejecución desconocido",
    dashboard_mock_notice: "Esta es una respuesta de simulación.",
    executed_successfully: "{tool} ejecutado con éxito.",
    execution_failed: "La ejecución falló.",
    dashboard_closing: "Cerrando el dashboard...",
    dashboard_closed: "Dashboard cerrado.",
    cmd_validate_desc: "Validar un servidor MCP",
    cmd_fingerprint_desc: "Detectar stack (reconocimiento)",
    cmd_inspect_desc: "Listar herramientas y recursos",
    common_solutions: "Soluciones Comunes",
    comparison_saved_at: "Reporte de comparación guardado en",
    config_created: "Archivo de configuración creado:",
    config_exists: "El archivo de configuración ya existe en:",
    connected: "¡Conectado!",
    connected_to_transport: "Conectado al transporte",
    connecting: "Conectando vía",
    connecting_server: "Conectando al servidor...",
    connecting_to_server: "Conectando al servidor",
    connection_failed: "Conexión Fallida",
    connection_failed_msg: "Conexión fallida",
    crashes_detected: "CRASHES DETECTADOS",
    created_by: "Creado por:",
    deeply_nested_quantifiers: "Cuantificadores anidados profundamente",
    define_a_strict_input_schema_with_expected_types_i:
      "Define un esquema de entrada estricto con tipos esperados. Implementa validación de esquema antes de deserializar.",
    description_is_very_short: "La descripción es muy corta",
    detailed_guides: "Guías Detalladas",
    detected_runtime: "Runtime detectado",
    detected_transport: "Transporte detectado",
    diag_deno_desc:
      "Verifica si Deno está instalado (requerido para modo sandbox)",
    diag_deno_details:
      "Deno es opcional. Solo es requerido si deseas usar el modo sandbox para ejecución del servidor.",
    diag_deno_name: "Entorno Deno",
    diag_outdated: "{name} está desactualizado ({version})",
    diag_installed: "Instalado ({version})",
    diag_not_found: "{name} no encontrado",
    diag_git_desc:
      "Verifica si Git está instalado para operaciones de control de versiones",
    diag_git_name: "Cliente Git",
    diag_install_deno: "Instalar Deno: https://deno.land/",
    diag_install_git: "Instalar Git: https://git-scm.com/downloads",
    diag_install_node: "Instalar Node.js: https://nodejs.org/",
    diag_install_python: "Instalar Python: https://www.python.org/downloads/",
    diag_node_desc: "Verifica si Node.js está instalado",
    diag_node_name: "Entorno Node.js",
    diag_node_req: "mcp-verify requiere Node.js 20 o superior.",
    diag_python_desc: "Verifica si Python está instalado",
    diag_python_details:
      "Python es opcional. Solo es requerido si deseas probar servidores MCP basados en Python.",
    diag_python_name: "Entorno Python",
    diagnostic_results: "Resultados del Diagnóstico",
    direct_filesystem_access_with_dynamic_paths:
      "Acceso directo al sistema de archivos con rutas dinámicas",
    static_resource_points_to_sensitive_system_path:
      "El recurso estático apunta a una ruta sensible del sistema",
    avoid_exposing_sensitive_system_files_as_static_re:
      "Evite exponer archivos o directorios sensibles del sistema como recursos MCP estáticos. Use acceso restringido o rutas virtuales.",
    discovering: "Descubriendo herramientas y recursos...",
    discovery_failed: "Descubrimiento fallido",
    dns_error: "No se puede resolver el hostname",
    dns_resolution: "Resolución DNS",
    do_not_expose_configuration_files_keys_or_credenti:
      "No expongas archivos de configuración, claves o credenciales como recursos MCP. Usa acceso a datos específico y con alcance limitado.",
    doctor_title: "Diagnóstico del Servidor MCP",
    document_cryptographic_algorithms_aes256gcm_for_en:
      "Documente los algoritmos criptográficos: AES-256-GCM para cifrado, SHA-256+ para hashing, RSA-2048+ o ECC para asimétrico.",
    document_data_protection_1_encryption_at_rest_and:
      "Documentar la protección de datos: (1) Cifrado en reposo y en tránsito, (2) Controles de acceso, (3) Registro de auditoría, (4) Políticas de retención de datos.",
    document_password_hashing_method_use_bcrypt_argon2:
      "Documenta el método de hash de contraseña. Usa bcrypt, Argon2 o scrypt con factores de trabajo adecuados.",
    document_the_password_hashing_algorithm_used_shoul:
      "Documenta el algoritmo de hash de contraseña utilizado (debería ser bcrypt, Argon2 o scrypt con parámetros adecuados).",
    duration_ms: "Duración",
    edit_to_customize:
      "Edita este archivo para personalizar reglas de seguridad y configuración del proxy.",
    editor_error: "Error del editor",
    elevated_error_rate: "Tasa de errores elevada",
    email_label: "Correo electrónico",
    enforce_complexity_requirements_minimum_12_charact:
      "Aplicar requisitos de complejidad. Mínimo 12 caracteres, mayúsculas y minúsculas, números, símbolos.",
    enforce_minimum_256_bits_for_aes_2048_bits_for_rsa:
      "Exija un mínimo: 256 bits para AES, 2048 bits para RSA, 256 bits para ECC.",
    ensure_the_server_validates_and_sanitizes_uri_para:
      "Asegura que el servidor valide y sanitice parámetros URI. Considera usar lista blanca de rutas permitidas o implementar validación de entrada estricta.",
    enter_arguments_json: "Ingresa argumentos JSON.",
    err_auth_msg: "Acceso denegado. Por favor verifique sus credenciales.",
    err_auth_title: "Autenticación Fallida",
    err_conn_msg: "No se pudo conectar al servidor MCP{target}",
    err_dns_msg: "No se pudo resolver el nombre de host{target}",
    err_timeout_msg: "La solicitud agotó el tiempo de espera{target}",
    err_cmd_failed: "El comando '{command}' falló",
    err_conn_title: "Conexión Fallida",
    err_dns_title: "Fallo de Resolución DNS",
    err_protocol_msg:
      "La respuesta del servidor no cumple con el protocolo MCP.",
    err_protocol_title: "Error de Protocolo",
    err_timeout_title: "Tiempo de Espera Agotado",
    err_unknown_title: "Operación Fallida",
    error: "Error",
    error_command_empty: "La cadena de comando no puede estar vacía",
    error_handling_request: "Error manejando solicitud",
    error_invalid_json_response: "Respuesta JSON inválida del servidor",
    error_process_exit: "El proceso terminó con código {code}",
    error_process_not_started: "Proceso no iniciado",
    error_process_spawn: "Error al iniciar proceso: {message}",
    error_request_timeout: "Tiempo de espera agotado después de {timeout}ms",
    request_timeout: "La solicitud expiró después de {ms}ms",
    error_testing_server: "para pruebas de errores",
    error_transport_connection: "Error de conexión de transporte",
    error_unknown_jsonrpc: "Error JSON-RPC desconocido",
    errors_encountered: "Errores Encontrados",
    evidence_label: "Evidencia",
    payload: "Payload",
    payloads: "Payloads",
    evidence_redos_pattern: "Cuantificadores anidados detectados",
    evidence_redos_timeout: "Tiempo de evaluación de patrón agotado",
    evidence_redos_too_long: "Patrón demasiado largo (>500 caracteres)",
    evidence_redos_vulnerable: "Estructura de patrón vulnerable",
    export_failed: "Error al Exportar",
    export_zip: "Exportar ZIP",
    exported: "¡Exportado!",
    exporting: "Exportando...",
    even_with_prepared_statements_implement_input_vali:
      "Incluso con sentencias preparadas, implementar validación de entrada para prevenir errores lógicos.",
    example_1_desc: "Prueba protocolo, descubre herramientas, genera reporte",
    example_2_desc:
      "Incluye 4 reglas de seguridad (Path Traversal, Command Injection, SSRF, Data Leakage)",
    example_3_desc: "Prueba con 10 usuarios concurrentes por 30 segundos",
    example_4_desc:
      "Prueba herramientas interactivamente con inputs personalizados",
    example_5_desc: "Genera reporte SARIF para GitHub Code Scanning",
    example_6_desc: "Inicia servidor MCP de demostración para testing",
    example_curl_command: "   $ curl",
    example_doctor_command: "   $ mcp-verify doctor",
    example_label: "Ejemplo",
    example_ps_command: "   $ ps aux | grep tu-servidor",
    example_url: "Ejemplo: http://localhost:3000 o https://api.example.com",
    example_validate_command: "   $ mcp-verify validate",
    examples_title: "Ejemplos Rápidos",
    executing_tool: "Ejecutando Herramienta...",
    expand_description_to_at_least_20_characters_to_pr:
      "Amplía la descripción a al menos 20 caracteres para proporcionar contexto al LLM.",
    failed_connect_server: "Falló la conexión al servidor MCP",
    failed_label: "Fallido",
    failures_label: "Fallos",
    fetching_capabilities: "Obteniendo capacidades...",
    firewall_blocking: "¿Hay un firewall bloqueando la conexión?",
    fix_label: "💡 Solución: ",
    fuzz_cmd_detected_desc:
      "Inyección de comandos detectada - salida de comando del sistema en la respuesta",
    fuzz_cmd_detected_rem:
      "Nunca pase entradas de usuario a comandos del sistema. Use listas de permitidos y validación de entradas.",
    fuzz_dangerous_detected:
      "Comando peligroso detectado en la carga (chequeo de seguridad)",
    fuzz_empty_args: "Argumentos vacíos",
    fuzz_info_disclosure_desc: "Mensaje de error del servidor expuesto",
    fuzz_info_disclosure_rem:
      "Implemente un manejo de errores adecuado. No exponga errores internos a los usuarios.",
    fuzz_nosql_detected_desc: "Inyección NoSQL detectada",
    fuzz_nosql_detected_rem:
      "Sanitice los operadores. Use validación de esquemas. Evite eval() o $where.",
    fuzz_path_detected_desc:
      "Salto de directorio detectado - contenido de archivo sensible en la respuesta",
    fuzz_path_detected_rem:
      "Valide y sanitice las rutas de archivos. Use listas de permitidos. Restrinja el acceso a archivos a directorios específicos.",
    fuzz_server_error_desc: "La carga causó un error del servidor (500)",
    fuzz_server_error_rem:
      "Implemente validación de entradas y manejo de errores adecuados.",
    fuzz_sqli_detected_desc:
      "Mensaje de error de SQL detectado - potencial inyección SQL",
    fuzz_sqli_detected_rem:
      "Use sentencias preparadas con consultas parametrizadas. Nunca concatene entradas de usuario en SQL.",
    fuzz_ssrf_detected_desc:
      "Vulnerabilidad SSRF detectada - acceso a recurso interno",
    fuzz_ssrf_detected_rem:
      "Valide y use listas de permitidos para URLs. Bloquee rangos de IP internos. Use filtrado de salida (egress).",
    fuzz_stack_trace_desc: "Stack trace filtrado en la respuesta",
    fuzz_stack_trace_rem:
      "Desactive la salida de stack traces en producción. Use mensajes de error genéricos.",
    fuzz_time_sqli_desc: "Inyección ciega basada en tiempo detectada",
    fuzz_time_sqli_rem:
      "Use consultas parametrizadas. Implemente validación de entradas.",
    fuzz_time_suspicious_desc:
      "Tiempo de respuesta sospechoso para carga basada en tiempo",
    fuzz_time_suspicious_rem:
      "Investigue una potencial vulnerabilidad de inyección basada en tiempo.",
    fuzz_type_mismatch: "Discordancia de tipos",
    fuzz_unknown_props: "Propiedades desconocidas",
    fuzz_xss_detected_desc: "Potencial vulnerabilidad XSS detectada",
    fuzz_xss_detected_rem:
      "Sanitice todas las entradas de usuario antes de renderizarlas. Use Content-Security-Policy.",
    fuzz_xss_reflected_desc: "Carga de XSS reflejada sin codificación",
    fuzz_xss_reflected_rem:
      "Implemente codificación de salida. Use cabeceras Content-Security-Policy adecuadas.",
    fuzz_xxe_detected_desc: "Vulnerabilidad XXE detectada",
    fuzz_xxe_detected_rem:
      "Desactive el procesamiento de entidades externas en el analizador XML. Use librerías XML seguras.",
    fuzz_large_payload: "Payload Grande ({size})",
    fuzz_security_attack: "Ataque de Seguridad ({type}): {key}",
    fuzz_mutated_attack: "Ataque Mutado ({mutation} en {type}): {key}",
    fuzzing_label: "Fuzzing",
    generating_report: "Generando reporte...",
    gemini_api_key_not_configured:
      "Clave API de Google no configurada. Obtén clave gratis en https://aistudio.google.com/apikey",
    gemini_invalid_key_format:
      "[Gemini] Formato de clave API inválido. Esperado: AIza...",
    getting_prompt: "Obteniendo Prompt...",
    github_label: "GitHub",
    goodbye: "¡Hasta luego!",
    guardrail_https_enforcement: "  ✓ Forzar HTTPS",
    guardrail_input_sanitization:
      "  ✓ Sanitización de Entrada (SQL, XSS, Comando)",
    guardrail_auto_upgrade:
      "Se actualizaron automáticamente {count} URLs inseguras a HTTPS.",
    guardrail_insecure_detected: "Se detectaron URLs inseguras: {urls}",
    guardrail_mixed_content:
      "Contenido mixto detectado (HTTP en contexto HTTPS)",
    guardrail_pii_address: "Dirección IP detectada",
    guardrail_pii_api_key: "Clave API detectada",
    guardrail_pii_cc: "Tarjeta de crédito detectada",
    guardrail_pii_email: "Email detectado",
    guardrail_pii_phone: "Número de teléfono detectado",
    guardrail_pii_redaction: "  ✓ Redacción PII (SSN, Tarjetas, Emails)",
    guardrail_pii_ssn: "SSN detectado",
    guardrail_rate_burst:
      "Límite de ráfaga excedido: {current}/{limit} peticiones en 1s",
    guardrail_rate_hour:
      "Límite de tasa excedido: {current}/{limit} peticiones por hora",
    guardrail_rate_limiting: "  ✓ Limitación de Velocidad (60 req/min)",
    guardrail_rate_minute:
      "Límite de tasa excedido: {current}/{limit} peticiones por minuto",
    guardrail_sanitizer_path: "Caracteres de salto de directorio removidos",
    guardrail_sanitizer_shell: "Metacaracteres de shell removidos",
    guardrail_sanitizer_sql: "Caracteres de inyección SQL removidos",
    guardrail_sensitive_blocker: "  ✓ Bloqueo de Comandos Sensibles",
    guardrail_sensitive_cmd: "Patrón de comando sensible bloqueado: {pattern}",
    handshake_failed: "Handshake fallido",
    handshake_failed_log: "Handshake fallido",
    handshake_successful: "Handshake MCP exitoso",
    high_average_response_time: "Tiempo medio de respuesta alto",
    high_memory_usage: "Uso de memoria alto",
    html_label: "HTML",
    http_response: "Respuesta HTTP",
    if_the_tool_accepts_any_input_define_a_strict_inpu:
      "Si la herramienta acepta alguna entrada, definir un esquema de entrada estricto. Si solo ejecuta consultas predefinidas, documentar esto en la descripción.",
    implement_1_rate_limiting_on_login_attempts_2_acco:
      "Implementa: (1) Limitación de tasa en intentos de login, (2) Bloqueo de cuenta tras fallos, (3) Considera soporte MFA.",
    implement_complexity_requirements_uppercase_lowerc:
      "Implementa requisitos de complejidad: mayúsculas, minúsculas, números, caracteres especiales.",
    implement_log_redaction_for_sensitive_fields_never:
      "Implementar la redacción de registros para campos sensibles. Nunca registrar contraseñas, API keys, tarjetas de crédito o PII.",
    implement_strict_validation_pattern_for_this_sensi:
      "Implementar un patrón de validación estricto para este campo sensible.",
    implement_strict_validation_ssn_d3d2d4_email_rfc_5:
      "Implementar validación estricta: SSN: ^\\d{3}-\\d{2}-\\d{4}$, Email: compatible con RFC 5322",
    info_cloud_caution:
      "   Tenga precaución en infraestructura de nube (instancias AWS EC2, GCP)",
    info_direct_exec:
      "   Los comandos se ejecutarán directamente en su sistema",
    info_local_safe: "   Esto es seguro para desarrollo local",
    info_trust_only: "   Solo use servidores en los que confíe",
    initializing: "Inicializando sistema...",
    input_received: "Input recibido.",
    interactive_about_desc:
      "Herramienta enterprise de validación y testing de seguridad para servidores MCP.",
    interactive_about_desc_title: "Sobre mcp-verify",
    interactive_about_title: "Acerca de mcp-verify",
    interactive_available_commands: "Comandos Disponibles",
    interactive_available_keys: "Claves disponibles",
    interactive_available_languages: "Idiomas disponibles",
    interactive_commands: "comandos",
    interactive_config: "Configuración",
    interactive_config_title: "Configuración Actual",
    interactive_current_language: "Idioma Actual",
    interactive_did_you_mean: "¿Quisiste decir?",
    interactive_empty: "(vacío)",
    interactive_examples: "Ejemplos",
    interactive_features: "Características",
    interactive_history_title: "Historial de Comandos",
    interactive_invalid_language: "Idioma inválido",
    interactive_language_changed_to: "Idioma cambiado a",
    interactive_links: "Enlaces",
    interactive_open_github_desc: "Abrir GitHub de Fink",
    interactive_open_linkedin_desc: "Abrir LinkedIn de Fink",
    interactive_open_website_desc: "Abrir sitio web",
    interactive_playground: "Playground Interactivo",
    interactive_set_target_desc: "Configurar target por defecto",
    interactive_shell: "Terminal Interactiva",
    interactive_show_config_desc: "Ver configuración",
    cmd_target_desc: "Configurar o mostrar target actual",
    cmd_profile_desc:
      "Gestionar perfiles de seguridad (light/balanced/aggressive)",
    cmd_context_desc: "Gestionar workspace multi-contexto",
    cmd_status_desc: "Mostrar estado del workspace",
    profile_help_title: "Comandos de Perfil:",
    profile_help_set: "Cambiar a un perfil",
    profile_help_save: "Guardar configuración actual como perfil personalizado",
    profile_help_list: "Listar todos los perfiles disponibles",
    profile_help_show: "Mostrar detalles del perfil actual",
    interactive_show_history_desc: "Ver historial",
    interactive_social: "Social e Info",
    interactive_tab_hint: "Usa Tab para autocompletar comandos",
    interactive_target_example: "Ejemplo: validate node server.js",
    interactive_target_required: "Necesitas especificar un objetivo (target)",
    interactive_target_set: "Target configurado",
    interactive_to_change: "Para cambiar",
    interactive_tools: "Herramientas",
    interactive_type_help:
      'Escribe "help" para ver comandos, "exit" para salir.',
    interactive_unknown_command: "Comando desconocido",
    interactive_usage: "Uso",
    interactive_help_reference: "Referencia de Comandos",
    interactive_help_change_tab: "Cambiar Pestaña",
    interactive_help_close: "Cerrar Ayuda",
    interactive_utilities: "Utilidades",
    help_category_infra: "Infraestructura",
    invalid_command_format: "Formato de comando inválido",
    invalid_json: "El servidor devolvió JSON inválido",
    invalid_option: "Invalid option / Opción inválida\n",
    invalid_regex_pattern: "Patrón de regex inválido",
    invalid_selection: "Selección inválida.",
    invalid_url_format: "Formato de URL inválido",
    is_listening_port:
      "¿Está escuchando en el puerto correcto? (netstat -an | grep LISTEN)",
    is_process_started:
      "¿El proceso está iniciado? (ps aux | grep tu-servidor)",
    json_label: "JSON",
    jsonrpc_failed: "Fallo JSON-RPC en el método {method}",
    jsonrpc_violations: "Violaciones del Estándar JSON-RPC Detectadas:",
    label_docs: "Docs:",
    label_issues: "Issues:",
    label_run: "Ejecuta:",
    language_label: "Idioma",
    latency_avg: "Latencia (Promedio)",
    latency_distribution: "Latencia",
    latency_max: "Latencia (Máxima)",
    latency_p95: "Latencia (P95)",
    latest_stderr_output: "Última salida de error (stderr):",
    linkedin_label: "LinkedIn",
    listen_label: "Escuchar",
    llm_api_key_invalid:
      "La clave API es inválida o expiró. Verifica tus variables de entorno.",
    llm_continuing_without: "   Continuando sin análisis LLM...",
    llm_example_anthropic: "     --llm anthropic:claude-haiku-4-5-20251001",
    llm_example_ollama: "     --llm ollama:llama3.2",
    llm_example_openai: "     --llm openai:gpt-4o-mini",
    llm_examples_block:
      "Ejemplos:\n  --llm anthropic:claude-haiku-4-5-20251001  (requiere ANTHROPIC_API_KEY)\n  --llm ollama:llama3.2                      (requiere servidor Ollama)\n  --llm openai:gpt-4o-mini                   (requiere OPENAI_API_KEY)",
    llm_examples_header: "   Ejemplos:",
    llm_no_description: "No se proporcionó descripción",
    llm_no_prompts: "No se encontraron prompts",
    llm_no_provider_specified:
      "No se especificó proveedor LLM. Usa la bandera --llm para habilitar análisis de IA.",
    llm_no_resources: "No se encontraron recursos",
    llm_no_tools: "No se encontraron herramientas",
    llm_rate_limit:
      "Límite de tasa excedido. Por favor intenta de nuevo más tarde.",
    llm_request_timeout:
      "Tiempo de espera agotado para LLM. Intenta aumentar el timeout o usar un modelo más rápido.",
    llm_semantic_check_deprecated:
      "⚠️  --semantic-check está obsoleto. Usa la bandera --llm en su lugar",
    llm_analysis_using: "Análisis LLM usando {provider}",
    baseline_not_found: "Archivo de baseline no encontrado en {path}",
    baseline_not_found_tip:
      "Ejecute con --save-baseline para crearlo primero: mcp-verify validate --save-baseline {path}",
    baseline_new_critical: "¡Se detectaron {count} nuevos hallazgos CRÍTICOS!",
    baseline_new_high: "Se detectaron {count} nuevos hallazgos ALTOS.",
    baseline_findings_fixed: "¡Se corrigieron {count} hallazgos!",
    load_testing: "Pruebas de Carga",
    logs_appear_below: "Los logs aparecerán abajo (Ctrl+C para detener)",
    markdown_label: "Markdown",
    mask_or_redact_sensitive_fields_in_responses_retur:
      "Enmascarar o redactar campos sensibles en las respuestas. Devolver solo los datos necesarios. Implementar cifrado a nivel de campo si es necesario.",
    mcp_protocol: "Protocolo MCP",
    security_score_explanation:
      "Esta puntuación mide indicadores de superficie de ataque técnica, no la seguridad de lógica de negocio ni la preparación para producción.",
    md_description: "Descripción",
    md_executive_security_report: "Reporte Ejecutivo de Seguridad",
    missing_description: "Descripción faltante",
    missing_message_param:
      "Falta parámetro message (transporte SSE espera ?message=JSON)",
    mock_server: "Servidor Mock para Pruebas",
    mock_server_running: "Servidor MCP Mock corriendo en",
    mock_received: "El servidor simulado recibió la solicitud: {method}",
    multiple_consecutive_quantifiers: "Múltiples cuantificadores consecutivos",
    need_help: "¿Necesitas más ayuda?",
    nested_quantifiers_detected_eg_a:
      "Cuantificadores anidados detectados (e.g., (a+)+)",
    no_config_file_found_using_defaults:
      "No se encontró archivo de configuración, usando valores por defecto.",
    no_http_response: "Sin respuesta HTTP",
    no_input_parameters_defined: "No se definieron parámetros de entrada",
    no_tools_prompts:
      "No se encontraron herramientas o prompts en este servidor.",
    not_found: "No Encontrado",
    not_http_url: "No es una URL HTTP (¿modo stdio?)",
    openai_api_key_not_configured: "Clave API de OpenAI no configurada",
    openai_invalid_key_format:
      "[OpenAI] Formato de clave API inválido. Esperado: sk-...",
    opening: "Abriendo",
    opening_editor: "Abriendo editor... (Cierra el archivo para guardar)",
    option_allowed_score_drop_desc:
      "Permitir caída de puntuación hasta esta cantidad (por defecto: 5)",
    option_compare_baseline_desc:
      "Comparar contra un baseline y mostrar la diferencia",
    option_concurrent_users: "Usuarios concurrentes",
    option_dashboard_port: "Puerto del dashboard",
    option_enable_fuzzing: "Habilitar Fuzzing Inteligente (Pruebas de Caos)",
    option_fuzz_concurrency: "Número de solicitudes concurrentes",
    option_fuzz_timeout: "Timeout por solicitud en ms",
    option_fuzz_tool: "Nombre de la herramienta a fuzzear",
    option_fuzz_generators:
      "Generadores a usar (prompt,json-rpc,schema,classic,sqli,xss,cmd,path,ssrf,xxe,nosql,ssti,jwt,proto,time-based,all)",
    option_fuzz_detectors:
      "Detectores a usar (prompt-leak,jailbreak,protocol,path-traversal,weak-id,info,timing,all)",
    option_fuzz_format: "Formato de reporte (json, html, both)",
    option_fuzz_format_sarif: "Formato de reporte (json, html, sarif, all)",
    option_http_header:
      'Header HTTP para autenticación (ej., "Authorization: Bearer token")',
    option_fuzz_param: "Nombre del parámetro objetivo para inyectar payloads",
    option_fuzz_stop_on_first: "Parar al encontrar primera vulnerabilidad",
    option_fuzz_fingerprint:
      "Habilitar fingerprinting del servidor para desactivar generadores irrelevantes automáticamente",
    fingerprint_results: "Resultados del Fingerprint",
    fingerprinting_target:
      "Analizando servidor para optimizar selección de payloads...",
    option_env_variables: "Variables de entorno (CLAVE=VALOR)",
    option_fail_on_degradation_desc:
      "Salir con código 2 si las puntuaciones bajan respecto al baseline",
    option_generate_html: "Generar HTML",
    option_generate_md: "Generar Markdown",
    option_generate_json: "Generar JSON",
    option_json_stdout_desc:
      "Enviar JSON a stdout para tuberías (también guarda archivos en reports/)",
    option_lang_desc: "Forzar idioma (en, es)",
    option_list_only: "Solo listar capacidades y salir",
    option_llm_desc:
      "Proveedor de LLM para análisis semántico (ej., anthropic:claude-haiku-4-5-20251001, ollama:llama3.2, openai:gpt-4o-mini)",
    option_no_color_desc: "Desactivar salida con colores",
    option_output_directory: "Directorio de salida",
    option_port_listen: "Puerto en el que escuchar",
    option_proxy_timeout:
      "Detener automáticamente el proxy después de MS milisegundos",
    option_quiet_desc:
      "Suprimir spinners y mensajes informativos (mantiene errores y salida final)",
    option_scan_all_configs:
      "Escanear todos los archivos de configuración MCP del proyecto (.mcp.json, .claude/settings.json)",
    option_report_format: "Formato de reporte (json, sarif)",
    option_sandbox:
      "Ejecutar servidor en sandbox aislado (solo Node/Deno). Para Python/Go, usar --no-sandbox para análisis estático únicamente",
    option_save_baseline_desc:
      "Guardar el reporte actual como baseline para comparaciones futuras",
    option_watch_desc: "Monitorear el entorno y el servidor en tiempo real",
    option_verbose_doctor_desc: "Mostrar pasos detallados del diagnóstico",
    option_show_history_desc:
      "Mostrar historial de integridad (últimos 20 builds)",
    option_fix_integrity_desc:
      "Regenerar manifiesto de integridad sin rebuild completo",
    option_clean_history_desc:
      "Mantener solo los últimos N builds en el historial",
    option_save_scan:
      "Guardar escaneo en historial para detección de regresiones",
    option_semantic_check_desc:
      "Habilitar análisis semántico potenciado por LLM (requiere clave de API)",
    option_test_duration: "Duración de la prueba",
    option_transport_stdio_http: "Tipo de transporte (http o stdio)",
    option_transport_type: "Tipo de transporte",
    option_verbose_logging: "Habilitar logging detallado",
    overlapping_alternation_detected_eg_aab:
      "Alternancia superpuesta detectada (ej., (a|ab)+)",
    passwords_can_be_cracked_easily_with_rainbow_table:
      "Las contraseñas pueden ser descifradas fácilmente con tablas rainbow o fuerza bruta",
    path_security_output: "Ruta de salida inválida: {path}",
    path_security_baseline: "Ruta de baseline inválida: {path}",
    path_security_baseline_req:
      "Los baselines deben almacenarse dentro de su proyecto por seguridad.",
    path_security_traversal:
      "Esto podría ser un ataque de salto de directorio (path traversal). Solo se permiten rutas dentro del directorio de salida.",
    performance_report: "Reporte de Rendimiento",
    play_finding: "Probar una herramienta específica",
    playground_invalid_json: "¡JSON inválido!",
    port_check: "Verificación de Puerto",
    print: "Imprimir",
    port_not_reachable: "El puerto no es alcanzable o el servidor está caído",
    port_reachable: "El puerto {port} es accesible.",
    potential_excessive_backtracking: "Posible retroceso excesivo",
    potentially_dangerous_pattern: "Patrón potencialmente peligroso",
    press_ctrl_c: "Presiona Ctrl+C para detener el servidor",
    project_label: "Proyecto",
    prompt_label: "Solicitud",
    protocol_compliance: "Cumplimiento de Protocolo",
    protocol_error: "Error de protocolo",
    proxy_active: "Proxy MCP Activo en",
    proxy_invalid_json: "JSON Inválido",
    proxy_port_in_use: "Puerto ya en uso",
    proxy_port_tip: "Por favor usa --port para especificar un puerto diferente",
    proxy_auto_stopping: "El proxy se detendrá automáticamente en {ms}ms.",
    quality_mimetype_suggestion:
      'Añade un mimeType (ej. "text/plain") para ayudar al LLM a entender cómo leerlo.',
    quality_param_missing_desc: 'El parámetro "{param}" no tiene descripción.',
    quality_param_desc_suggestion:
      'Añada una descripción detallada para el parámetro "{param}" para mejorar la comprensión semántica.',
    quality_score: "Puntuación de Calidad",
    rate_limit_config_options: "\nOpciones de configuración:",
    rate_limit_guideline_auth:
      "- Autenticación: 5-10 intentos por minuto por IP\n- Agregue backoff exponencial tras intentos fallidos\n- Implemente bloqueo de cuenta tras 5-10 fallos",
    rate_limit_guideline_compute:
      "- Intensivo en cómputo: 10 peticiones por minuto\n- Implemente cola de trabajos para procesamiento pesado",
    rate_limit_guideline_db:
      "- Consultas de base de datos: 100 peticiones por minuto por usuario\n- Implemente caché de resultados de consulta",
    rate_limit_guideline_file:
      "- Subida de archivos: 10 archivos por hora, máx 10MB por archivo\n- Implemente cuotas de subida por usuario",
    rate_limit_guideline_net:
      "- Llamadas a APIs externas: 10-60 peticiones por minuto\n- Implemente cola de peticiones y lógica de reintento",
    rate_limit_option_docs:
      "- Documente los límites de tasa en la descripción de la herramienta",
    rate_limit_option_extension:
      "- Agregue la extensión x-rate-limit al esquema de la herramienta",
    rate_limit_option_header:
      "- Devuelva 429 Too Many Requests con el encabezado Retry-After",
    received_signal: "Señal recibida",
    recommendations: "Recomendaciones",
    redirecting_to: "Redirigiendo a",
    reduce_users: "Reduce usuarios concurrentes: --users 5",
    remediation_cmd_injection_strengthen:
      "Fortalezca la regex para excluir estrictamente metacaracteres de shell como ; & | ` $ ( ) < >",
    remediation_cmd_injection_whitelist:
      "Implemente una regex de lista blanca estricta (ej. ^[a-zA-Z0-9]+$) para prevenir la inyección de metacaracteres de shell.",
    remediation_deserialization_all:
      "Implemente: (1) Validación de esquema, (2) Listas blancas de tipos, (3) Chequeos de integridad (HMAC/firmas), (4) Evite deserializar datos no confiables cuando sea posible.",
    remediation_deserialization_encoded:
      "Valide la estructura de datos decodificada. Nunca deserialice datos decodificados en base64 sin verificación.",
    remediation_deserialization_explicit:
      "Defina el tipo explícito (cadena, objeto con propiedades) y valide contra un esquema.",
    remediation_deserialization_properties:
      "Defina las propiedades permitidas en el esquema o establezca additionalProperties: false.",
    remediation_deserialization_strict:
      "Defina un esquema de entrada estricto con tipos esperados. Implemente la validación del esquema antes de la deserialización.",
    remediation_deserialization_yaml:
      "Use yaml.safe_load() en lugar de yaml.load() o yaml.unsafe_load().",
    remediation_plain_credentials:
      'Asegúrese de que las credenciales se transmitan solo por HTTPS. Considere usar format: "password" para campos sensibles.',
    remediation_prompt_injection_limit:
      "Implemente maxLength para prevenir payloads de inyección largos.",
    remediation_prompt_injection_pattern:
      "Use un patrón de regex estricto para restringir la entrada permitida.",
    remediation_prompt_injection_prompt_args:
      "Sanitice los argumentos de prompt internamente ya que MCP no soporta esquemas para ellos.",
    remediation_rate_limit_aggressive:
      "Implemente una limitación de tasa agresiva: 5-10 intentos por minuto por IP. Agregue backoff exponencial y bloqueo de cuenta tras fallos.",
    remediation_rate_limit_file:
      "Establezca maxLength o maxSize (ej. 10MB máx). Implemente limitación de tasa en las subidas de archivos (ej. 10 archivos por hora).",
    remediation_rate_limit_generic:
      "Implemente limitación de tasa con las siguientes pautas:",
    remediation_redos_anchors:
      "Agregue anclas: ^pattern$ para asegurar la coincidencia de cadena completa y prevenir el abuso de coincidencias parciales.",
    remediation_redos_simplify:
      "Simplifique el patrón regex para evitar cuantificadores anidados y alternancias superpuestas.",
    remediation_ssrf_restrict:
      "Restrinja la entrada a dominios específicos permitidos usando un patrón regex estricto (p. ej., ^https://api.example.com/).",
    remediation_ssrf_tighten:
      "Ajuste la regex para permitir solo esquemas específicos (https) y dominios específicos.",
    remediation_path_traversal_weak_pattern:
      "El patrón de validación actual para esta ruta es débil ({pattern}). Debería ser más restrictivo para prevenir el salto de directorio.",
    remediation_user_enumeration:
      'Use mensajes de error genéricos: "Credenciales inválidas" para ambos casos. Implemente limitación de tasa.',
    remediation_xxe_critical:
      "CRÍTICO: Deshabilitar entidades externas en el analizador Y añadir validación de esquema XML.",
    remediation_xxe_disable:
      "Deshabilite las entidades externas en el analizador XML. Establezca resolve_entities=False, load_dtd=False, no_network=True.",
    remediation_xxe_pattern:
      "Agregue validación de patrones para restringir la estructura XML incluso con una configuración de analizador segura.",
    remediation_xxe_strict:
      "Defina el esquema de entrada con validación XML. Deshabilite explícitamente las entidades externas en su analizador XML.",
    remediation_xxe_svg:
      "Sanitizar las subidas de SVG volviendo a renderizar o usar una librería como DOMPurify. Deshabilitar entidades externas en el analizador XML.",
    remediation_xxe_uploads:
      "Deshabilitar entidades externas antes de analizar los archivos XML subidos. Validar el XML contra un esquema.",
    remediation_fuzzer_confirmed:
      "Esta vulnerabilidad fue CONFIRMADA mediante fuzzing dinámico. Remediación inmediata requerida. Revise la evidencia e implemente validación de entrada, sanitización de salida, o cambios arquitectónicos.",
    remediation_prompt_injection_limit_enterprise:
      "Implemente maxLength: {maxLength} para limitar el tamaño de payloads de inyección. Considere implementar límites basados en tokens para contextos LLM.",
    remediation_prompt_injection_pattern_specific:
      'Añada validación de patrón: "{pattern}" - {description}',
    remediation_prompt_injection_strengthen_pattern:
      "El patrón actual es demasiado permisivo. Use un patrón estricto que bloquee marcadores de inyección como [INST], <<SYS>>, ###, etc.",
    remediation_prompt_injection_indirect:
      "Esta herramienta obtiene contenido externo. Implemente: (1) Validación de URL/fuente, (2) Sanitización de contenido antes del procesamiento LLM, (3) Considere procesamiento de contenido en sandbox.",
    remediation_prompt_injection_chain:
      "CRÍTICO: Esta herramienta obtiene Y procesa contenido externo. Implemente: (1) Lista blanca estricta de URLs, (2) Política de seguridad de contenido, (3) Límites de entrada/salida, (4) Técnicas de aislamiento de prompts.",
    remove_weak_algorithms_from_enum_only_allow_aes256:
      "Elimine los algoritmos débiles del enum. Solo permita: AES-256, ChaCha20, SHA-256+, RSA-2048+.",
    replace_weak_hashing_with_bcrypt_argon2_or_scrypt:
      "Reemplaza hash débil con bcrypt, Argon2 o scrypt. Nunca uses MD5, SHA1 o almacenes contraseñas en texto plano.",
    replace_with_aes256gcm_chacha20poly1305_or_xchacha:
      "Reemplace con AES-256-GCM, ChaCha20-Poly1305, o XChaCha20-Poly1305.",
    replace_with_sha256_sha384_sha512_sha3_or_blake2bl:
      "Reemplace con SHA-256, SHA-384, SHA-512, SHA-3, o BLAKE2/BLAKE3.",
    req_sec: "req/seg",
    request_log: "Solicitud",
    reproducer_desc:
      "Usa este comando para reproducir exactamente la misma validación:",
    reproducer_title: "Reproducir este Escaneo",
    resolved_to: "Resuelto a",
    resource_missing_mimetype: "Recurso sin tipo MIME",
    resource_warnings_label: "Advertencias de Recursos",
    response_log: "Respuesta",
    result_label: "Resultado",
    risk_cmd_injection_unsanitized:
      "Entrada no sanitizada en un contexto potencial de ejecución de comandos",
    risk_crypto_brute_force:
      "Las claves de < 128 bits pueden ser descifradas por fuerza bruta",
    risk_crypto_predictable:
      "Los valores aleatorios predecibles pueden ser explotados para adivinar claves",
    risk_crypto_weak_selection:
      "El usuario puede seleccionar algoritmos débiles/obsoletos",
    risk_data_leakage_risky_file: "Extensión/nombre de archivo riesgoso",
    risk_deserialization_encoded:
      "Objetos serializados ocultos en cadenas codificadas",
    risk_deserialization_injection: "Inyección arbitraria de objetos",
    risk_deserialization_no_type:
      "Sin validación de tipo en objetos deserializados",
    risk_deserialization_properties:
      "Inyección de objetos con propiedades arbitrarias",
    risk_deserialization_rce:
      "Ejecución remota de código (RCE) durante la deserialización",
    risk_deserialization_yaml:
      "Ejecución arbitraria de código vía etiquetas YAML",
    risk_level_critical: "Riesgo Crítico",
    risk_level_high: "Riesgo Alto",
    risk_level_low: "Riesgo Bajo",
    risk_level_medium: "Riesgo Medio",
    risk_plain_credentials:
      "Las credenciales podrían ser registradas o filtradas si no se transmiten de forma segura",
    risk_rate_limit_brute_force:
      "Sin protección contra la fuerza bruta de contraseñas o el relleno de credenciales",
    risk_rate_limit_disk_space:
      "Las subidas de archivos ilimitadas pueden agotar el espacio en disco",
    risk_rate_limit_exhaustion:
      "Las peticiones ilimitadas pueden agotar los recursos, causar DoS o permitir ataques de fuerza bruta",
    risk_redos_evaluation:
      "La entrada maliciosa puede causar un tiempo de evaluación exponencial de la regex",
    risk_redos_partial:
      "Las coincidencias parciales pueden ser explotadas con entradas largas",
    risk_sensitive_invalid_format:
      "Formato de datos inválido podría ser aceptado",
    risk_sensitive_logging:
      "Datos sensibles en registros podrían ser expuestos",
    risk_sensitive_no_format: "Sin validación de formato para datos sensibles",
    risk_sensitive_response:
      "Datos sensibles en las respuestas podrían ser registrados o almacenados en caché",
    risk_ssrf_arbitrary: "Acceso a URL arbitraria",
    risk_user_enumeration:
      'Mensajes de error diferentes para "usuario no encontrado" vs "contraseña incorrecta" filtran información',
    risk_weak_passwords:
      'Contraseñas débiles como "password123" podrían ser aceptadas',
    risk_xxe_external_entities:
      "Entidades externas o procesamiento de DTD habilitado",
    risk_xxe_malicious_entities:
      "XML no validado puede contener entidades externas maliciosas",
    risk_xxe_svg: "Los archivos SVG pueden contener entidades XML maliciosas",
    risk_xxe_unvalidated: "Entrada XML no validada con potencial XXE",
    risk_xxe_uploads:
      "Los archivos XML subidos pueden explotar la vulnerabilidad XXE",
    risk_xxe_vulnerability:
      "Vulnerabilidad XXE: puede leer archivos arbitrarios, SSRF, DoS",
    rpc_001: "El servidor no devolvió error para método inexistente",
    rpc_002: "El servidor devolvió un error vacío",
    rpc_003: 'El servidor aceptó solicitud sin campo "jsonrpc"',
    run_basic_validation: "Ejecuta validación básica primero",
    running_fuzzer: "Ejecutando Fuzzer Inteligente (Pruebas de Caos)...",
    running_protocol_tests:
      "Ejecutando pruebas de cumplimiento de protocolo...",
    running_security_scan: "Ejecutando escaneo de seguridad",
    runtime_security_gateway: "Gateway de Seguridad en Tiempo Real",
    sandbox_active:
      "🔒 Sandbox Activo: Ejecutando servidor en entorno Deno aislado.",
    sandbox_deno_only: "⚠️  Este sandbox solo soporta servidores Node.js/Deno.",
    sandbox_future_version: "   Futuras versiones soportarán Python y Go.",
    sandbox_option_audit:
      "   1. Ejecutar con --no-sandbox (solo auditoría/análisis estático, sin ejecución):",
    sandbox_option_risky:
      "   2. Ejecutar SIN sandbox (⚠️  RIESGOSO - solo para servidores confiables):",
    sandbox_options_header: "Opciones:",
    sandbox_trust_notice:
      "⚠️  ADVERTENCIA: --no-sandbox deshabilita la ejecución. Usar solo con servidores confiables.",
    sandbox_unsupported_runtime: "   Runtime detectado: {runtime}",
    sandbox_warning_title: "⚠️  LIMITACIÓN DEL SANDBOX",
    // Mensajes de validación de entorno del sandbox
    sandbox_deno_not_found: "Binario de Deno no encontrado en PATH",
    sandbox_install_deno:
      "Instalar Deno: curl -fsSL https://deno.land/install.sh | sh",
    sandbox_alt_docker:
      "Alternativa: Usar --sandbox=docker si Docker está disponible",
    sandbox_deno_version_too_old:
      "Versión de Deno {current} está por debajo del mínimo requerido {required}",
    sandbox_update_deno: "Actualizar Deno: deno upgrade",
    sandbox_version_parse_failed: "No se pudo parsear la versión de Deno",
    sandbox_version_check_failed: "Error al verificar versión de Deno: {error}",
    sandbox_temp_not_writable:
      "El directorio temporal no es escribible: {error}",
    sandbox_check_temp_perms:
      "Verificar permisos del directorio temporal del sistema",
    sandbox_ready: "✅ Sandbox Deno listo (v{version})",
    sandbox_not_available: "⚠️  Sandbox Deno no disponible",
    sandbox_issues_header: "Problemas detectados:",
    sandbox_suggestions_header: "Sugerencias:",
    sarif_label: "SARIF",
    schema_args: "Esquema/Args",
    schema_compilation_failed: "Falló la compilación del esquema",
    schema_dos_risk:
      "Este esquema es demasiado complejo y presenta un riesgo de DoS",
    schema_invalid_type: "El esquema debe ser un objeto no nulo",
    schema_missing_desc:
      'El esquema carece de la propiedad "description" (recomendado para documentación)',
    schema_missing_keywords:
      'Al esquema le falta una propiedad requerida: debe tener "type", "$ref", o palabras clave de composición (allOf/anyOf/oneOf)',
    schema_permissive_props:
      "El esquema permite propiedades adicionales, lo que podría aceptar datos inesperados",
    schema_permissive_string:
      "El esquema de cadena (string) no tiene restricciones de patrón (pattern), formato (format) o enumeración (enum)",
    schema_remote_refs:
      "El esquema contiene $ref remotos (las URLs externas están bloqueadas por seguridad)",
    schema_compilation_took:
      "La compilación del esquema tardó {elapsed}ms (umbral: {threshold}ms)",
    schema_dangerous_html:
      "La ruta del esquema {path} permite contenido HTML peligroso.",
    schema_dangerous_sql:
      "La ruta del esquema {path} permite contenido SQL peligroso.",
    score: "Puntaje",
    sec_auth_bypass_desc:
      "Detecta herramientas que podrían permitir evadir mecanismos de autenticación.",
    sec_auth_bypass_name: "Bypass de Autenticación",
    sec_command_injection_desc:
      "Detecta herramientas que podrían ejecutar comandos del sistema sin sanitización adecuada.",
    sec_command_injection_name: "Detección de Inyección de Comandos",
    sec_data_leakage_desc:
      "Detecta exposición de datos sensibles como API keys o PII.",
    sec_data_leakage_name: "Detección de Fuga de Datos",
    sec_insecure_deserialization_desc:
      "Detecta deserialización insegura de datos no confiables.",
    sec_insecure_deserialization_name: "Deserialización Insegura",
    sec_path_traversal_desc:
      "Detecta intentos de acceder a archivos fuera del directorio permitido.",
    sec_path_traversal_name: "Detección de Path Traversal",
    sec_prompt_injection_name: "Detección de Inyección de Prompt",
    sec_prompt_injection_desc:
      "Detecta vectores potenciales de inyección de prompt en herramientas y prompts.",
    finding_path_traversal_no_pattern:
      "No se detectó patrón de validación de rutas",
    remediation_path_traversal_add_pattern:
      "Implemente validación de rutas para prevenir ataques de directory traversal",
    sec_rate_limiting_desc:
      "Verifica si existen mecanismos de limitación de tasa.",
    sec_rate_limiting_name: "Limitación de velocidad",
    sec_redos_desc:
      "Detecta vulnerabilidades de Denegación de Servicio por Expresiones Regulares.",
    sec_redos_name: "Detección de ReDoS",
    sec_sensitive_exposure_desc:
      "Detecta herramientas que exponen información sensible del sistema.",
    sec_sensitive_exposure_name: "Exposición de Datos Sensibles",
    sec_sql_injection_desc:
      "Detecta vectores potenciales de inyección SQL en herramientas de base de datos.",
    sec_sql_injection_name: "Detección de Inyección SQL",
    sec_ssrf_desc:
      "Detecta vulnerabilidades potenciales de Server-Side Request Forgery.",
    sec_ssrf_name: "Detección de SSRF",
    sec_weak_crypto_desc:
      "Detecta el uso de algoritmos criptográficos débiles.",
    sec_weak_crypto_name: "Criptografía Débil",
    sec_xxe_desc:
      "Detecta vulnerabilidades de XML External Entity en el procesamiento de entradas.",
    sec_xxe_name: "Detección de Inyección XXE",
    sec_exposed_endpoint_name: "Endpoint de Red Expuesto",
    sec_exposed_endpoint_desc:
      "Detecta servidores expuestos en interfaces de red públicas sin la protección adecuada.",
    sec_missing_auth_name: "Autenticación Faltante",
    sec_missing_auth_desc:
      "Detecta servidores y herramientas que carecen de mecanismos de autenticación.",
    // SEC-014: Hallazgos de Endpoint Expuesto
    finding_exposed_endpoint_dev_mode:
      "El servidor parece estar ejecutándose en modo desarrollo/depuración",
    finding_exposed_endpoint_public_binding:
      "La herramienta {tool} configura el servidor para enlazarse en interfaz pública (0.0.0.0 o ::)",
    finding_exposed_endpoint_no_protection:
      "La herramienta {tool} maneja configuración de red sin indicadores de protección",
    finding_exposed_endpoint_param_default:
      "El parámetro {param} tiene un valor predeterminado peligroso: {value}",
    finding_exposed_endpoint_param_allows:
      "El parámetro {param} permite valores peligrosos: {values}",
    finding_exposed_endpoint_param_no_validation:
      "El parámetro de red {param} carece de patrón de validación",
    // SEC-014: Riesgos de Endpoint Expuesto
    risk_exposed_endpoint_dev:
      "Los servidores de desarrollo a menudo tienen características de depuración y seguridad relajada",
    risk_exposed_endpoint_unauthorized_access:
      "Cualquier cliente accesible por red puede conectarse y ejecutar herramientas",
    risk_exposed_endpoint_unprotected:
      "Servidor expuesto sin firewall o protección a nivel de red",
    risk_exposed_endpoint_default_public:
      "La configuración predeterminada expone el servidor a toda la red",
    risk_exposed_endpoint_configurable:
      "El usuario puede configurar el servidor para enlazarse en interfaces públicas",
    // SEC-014: Vectores de ataque de Endpoint Expuesto
    attack_vector_direct_jsonrpc:
      "Llamadas JSON-RPC directas evitando clientes previstos",
    attack_vector_prompt_injection:
      "Inyección de prompt vía endpoints accesibles por red",
    attack_vector_tool_abuse:
      "Ejecución de herramientas no autorizada y abuso de recursos",
    // SEC-014: Remediación de Endpoint Expuesto
    remediation_exposed_endpoint_prod_config:
      "Use configuración lista para producción. Deshabilite características de depuración. Enlace a 127.0.0.1 para acceso solo local.",
    remediation_exposed_endpoint_localhost:
      "Enlace a 127.0.0.1 (localhost) en lugar de 0.0.0.0. Solo exponga en interfaces públicas si es absolutamente necesario con autenticación adecuada y reglas de firewall.",
    remediation_exposed_endpoint_add_protection:
      "Implemente protección de red: reglas de firewall, lista de IPs permitidas, requisito de VPN, o autenticación.",
    remediation_exposed_endpoint_safe_default:
      "Cambie el predeterminado a 127.0.0.1 (localhost). Documente las implicaciones de seguridad si los usuarios deben cambiarlo.",
    remediation_exposed_endpoint_restrict_enum:
      "Elimine opciones de interfaz pública del enum. Solo permita localhost (127.0.0.1) e IPs de red privada.",
    remediation_exposed_endpoint_add_validation:
      "Agregue patrón de validación para restringir a direcciones IP seguras (127.0.0.1, 10.x.x.x, 192.168.x.x).",
    // SEC-015: Hallazgos de Autenticación Faltante
    finding_missing_auth_server:
      "El servidor no implementa mecanismo de autenticación",
    finding_missing_auth_admin_tool:
      "La herramienta administrativa {tool} carece de autenticación",
    finding_missing_auth_sensitive_tool:
      "La herramienta {tool} realiza operaciones sensibles ({ops}) sin autenticación",
    finding_missing_auth_insecure_param:
      "Parámetro de autenticación {param} transmitido de forma insegura",
    finding_missing_auth_not_marked_sensitive:
      "Parámetro de autenticación {param} no marcado como sensible",
    // SEC-015: Riesgos de Autenticación Faltante
    risk_missing_auth_unauthorized_access:
      "Cualquier cliente puede conectarse y ejecutar todas las herramientas sin autenticación",
    risk_missing_auth_privilege_escalation:
      "Usuarios no autorizados pueden ejecutar operaciones administrativas",
    risk_missing_auth_data_breach:
      "Acceso sin restricciones a datos y operaciones sensibles",
    risk_missing_auth_logged_credentials:
      "Las credenciales en parámetros query/path se registran en logs del servidor y cachés de proxy",
    // SEC-015: Impactos de Autenticación Faltante
    impact_missing_auth_full_control:
      "Control completo sobre la funcionalidad del servidor por cualquier cliente accesible por red",
    // SEC-015: Remediación de Autenticación Faltante
    remediation_missing_auth_implement:
      "Implemente autenticación a nivel de servidor usando API keys, OAuth 2.0, o TLS mutuo (mTLS).",
    remediation_missing_auth_tool_level:
      "Implemente verificaciones de autenticación a nivel de herramienta. Valide permisos de usuario antes de ejecutar operaciones sensibles.",
    remediation_missing_auth_server_level:
      "Implemente autenticación a nivel de servidor para proteger todas las herramientas:",
    remediation_missing_auth_tool_specific:
      "Agregue verificaciones de autorización específicas de herramienta incluso cuando exista autenticación a nivel de servidor.",
    remediation_missing_auth_header_only:
      "Transmita credenciales de autenticación solo en encabezados HTTP (Authorization, X-API-Key), nunca en parámetros query o path.",
    remediation_missing_auth_mark_sensitive:
      'Marque parámetros de autenticación con format: "password" o agregue extensión "x-sensitive": true.',
    // SEC-015: Opciones de Autenticación Faltante
    auth_option_api_key:
      "- API Key: Requiera encabezado X-API-Key con token seguro (mín 32 bytes aleatorios)",
    auth_option_oauth:
      "- OAuth 2.0: Use autenticación Bearer token con validación JWT",
    auth_option_mtls:
      "- mTLS: TLS mutuo con validación de certificado de cliente",
    // SEC-015: Directrices de Autenticación Faltante
    auth_guideline_admin:
      "- Operaciones administrativas: Requiera control de acceso basado en roles (RBAC) con rol admin",
    auth_guideline_deletion:
      "- Eliminación de datos: Requiera confirmación explícita + permisos elevados",
    auth_guideline_modification:
      "- Modificación de datos: Valide permisos de escritura para recursos específicos",
    auth_guideline_sensitive:
      "- Acceso a datos sensibles: Implemente control de acceso a nivel de campo",
    auth_implementation_note:
      "\nImplementación: Agregue middleware de autenticación que valide credenciales antes de enrutar a manejadores de herramientas.",

    // SEC-016: Detección de Esquema URI Inseguro
    sec_insecure_uri_name: "Detección de Esquema URI Inseguro",
    sec_insecure_uri_desc:
      "Detecta uso de esquemas URI peligrosos o no cifrados en recursos.",
    finding_insecure_uri_scheme:
      "El recurso {resource} usa esquema URI inseguro: {scheme}",
    finding_insecure_uri_malformed:
      "El recurso {resource} tiene URI mal formada",
    finding_insecure_uri_file_scheme:
      "El recurso {resource} usa esquema file:// (posible path traversal)",
    finding_insecure_uri_credentials:
      "El recurso {resource} contiene credenciales en la URI",
    risk_insecure_uri_file_traversal:
      "El esquema file permite ataques de path traversal",
    risk_insecure_uri_exposed_creds:
      "Credenciales en URI quedan expuestas en logs e historial del navegador",
    remediation_insecure_uri_fix_format:
      "Corrija el formato de URI a sintaxis válida",
    remediation_insecure_uri_use_secure: "Use alternativa segura: {scheme}",
    remediation_insecure_uri_file_validate:
      "Valide rutas de archivos y restrinja acceso a directorios permitidos",
    remediation_insecure_uri_remove_creds:
      "Elimine credenciales de la URI. Use encabezados de autenticación seguros en su lugar.",

    // SEC-017: Permisos Excesivos de Herramienta
    sec_excessive_perms_name: "Permisos Excesivos de Herramienta",
    sec_excessive_perms_desc:
      "Detecta herramientas con acceso sobreprivilegiado violando el principio de mínimo privilegio.",
    finding_excessive_perms_detected:
      "La herramienta {tool} tiene permisos excesivos (puntaje de riesgo: {score})",
    finding_excessive_perms_destructive_unrestricted:
      "La herramienta {tool} combina operaciones destructivas con acceso sin restricciones",
    finding_excessive_perms_param_all:
      "El parámetro {param} en la herramienta {tool} usa nomenclatura excesivamente permisiva (all/any)",
    risk_excessive_perms_privilege_escalation:
      "Escalación de privilegios a través de herramientas sobreprivilegiadas",
    risk_excessive_perms_data_loss:
      "Operaciones destructivas sin restricciones pueden causar pérdida de datos",
    remediation_excessive_perms_least_privilege:
      "Aplique principio de mínimo privilegio: limite permisos de herramienta al mínimo requerido, implemente control de acceso basado en roles",
    remediation_excessive_perms_split_permissions:
      "Divida en herramientas separadas con permisos específicos y limitados",
    remediation_excessive_perms_specific_params:
      'Use nombres de parámetros específicos en lugar de genéricos "all" o "any"',

    // SEC-018: Datos Sensibles en Descripciones
    sec_secrets_desc_name: "Datos Sensibles en Descripciones de Herramientas",
    sec_secrets_desc_desc:
      "Detecta información sensible filtrada en descripciones de herramientas y parámetros.",
    finding_secrets_desc_detected:
      "{type} detectado en {location} para herramienta {tool}",
    finding_secrets_desc_keywords:
      "Palabras clave sensibles encontradas en {location} para herramienta {tool}",
    risk_secrets_desc_disclosure:
      "Divulgación de información al LLM y usuarios finales",
    remediation_secrets_desc_remove:
      "Elimine {type} de las descripciones. Use valores placeholder en los ejemplos.",
    remediation_secrets_desc_review:
      "Revise descripciones en busca de información sensible y reemplace con ejemplos genéricos",

    // SEC-019: Restricciones de Entrada Faltantes
    sec_missing_constraints_name: "Restricciones de Entrada Faltantes",
    sec_missing_constraints_desc:
      "Detecta parámetros sin restricciones de validación (maxLength, pattern, límites).",
    finding_missing_constraints_maxlength:
      "El parámetro {param} en la herramienta {tool} carece de restricción maxLength",
    finding_missing_constraints_pattern:
      "El parámetro {param} en la herramienta {tool} carece de validación pattern",
    finding_missing_constraints_minimum:
      "El parámetro {param} en la herramienta {tool} carece de límite mínimo",
    finding_missing_constraints_maximum:
      "El parámetro {param} en la herramienta {tool} carece de límite máximo",
    finding_missing_constraints_maxitems:
      "El parámetro array {param} en la herramienta {tool} carece de restricción maxItems",
    finding_missing_constraints_maxprops:
      "El parámetro object {param} en la herramienta {tool} carece de maxProperties o definición de properties",
    risk_missing_constraints_dos:
      "Denegación de Servicio mediante entradas extremadamente grandes",
    risk_missing_constraints_overflow:
      "Vulnerabilidades de desbordamiento de enteros",
    risk_missing_constraints_memory:
      "Agotamiento de memoria con arrays sin límite",
    remediation_missing_constraints_add_maxlength:
      "Agregue restricción maxLength (recomendado: {recommended} bytes o menos)",
    remediation_missing_constraints_add_pattern:
      "Agregue validación pattern usando expresiones regulares",
    remediation_missing_constraints_add_bounds:
      "Agregue límites mínimo y máximo para valores numéricos",
    remediation_missing_constraints_add_maxitems:
      "Agregue restricción maxItems (recomendado: {recommended} items o menos)",
    remediation_missing_constraints_define_schema:
      "Defina esquema de properties explícito o agregue límite maxProperties",

    // SEC-020: Potencial de Encadenamiento Peligroso
    sec_tool_chaining_name:
      "Potencial de Encadenamiento Peligroso de Herramientas",
    sec_tool_chaining_desc:
      "Detecta herramientas que generan código ejecutable o aceptan entrada no sanitizada de otras herramientas.",
    finding_tool_chaining_potential:
      "El servidor tiene {codeGenCount} herramientas de generación de código y {execCount} herramientas de ejecución (riesgo de encadenamiento)",
    finding_tool_chaining_codegen_no_safety:
      "La herramienta de generación de código {tool} carece de advertencias de seguridad",
    finding_tool_chaining_dynamic_gen:
      "La herramienta {tool} genera código desde entradas dinámicas: {params}",
    risk_tool_chaining_injection:
      "Encadenar generación de código con ejecución habilita ataques de inyección",
    risk_tool_chaining_unsafe_output:
      "El código generado puede contener contenido malicioso sin validación",
    risk_tool_chaining_template_injection:
      "Inyección de plantillas mediante generación dinámica de código",
    remediation_tool_chaining_validate:
      "Valide y sanitice todas las salidas de herramientas antes de pasarlas a herramientas de ejecución",
    remediation_tool_chaining_add_warning:
      'Agregue advertencia explícita en la descripción: "La salida debe ser validada antes de la ejecución"',
    remediation_tool_chaining_sanitize_input:
      "Sanitice entradas de plantillas para prevenir ataques de inyección",

    // SEC-021: Almacenamiento de Credenciales sin Cifrar
    sec_unencrypted_creds_name: "Almacenamiento de Credenciales sin Cifrar",
    sec_unencrypted_creds_desc:
      "Detecta herramientas que almacenan credenciales sin cifrado o almacenamiento seguro.",
    finding_unencrypted_creds_explicit:
      "La herramienta {tool} almacena credenciales explícitamente usando métodos inseguros: {methods}",
    finding_unencrypted_creds_no_security:
      "La herramienta {tool} almacena {credTypes} sin mencionar cifrado",
    finding_unencrypted_creds_base64:
      "La herramienta {tool} usa codificación base64 (NO cifrado) para credenciales",
    finding_unencrypted_creds_param:
      "El parámetro {param} en la herramienta {tool} almacena credenciales sin medidas de seguridad",
    risk_unencrypted_creds_plaintext:
      "Almacenamiento de credenciales en texto plano expone secretos a atacantes",
    risk_unencrypted_creds_exposure:
      "Exposición de credenciales mediante compromiso de base de datos o acceso a archivos",
    risk_unencrypted_creds_encoding_not_encryption:
      "Base64 es codificación, no cifrado - no proporciona seguridad",
    risk_unencrypted_creds_param_storage:
      "El parámetro almacena credenciales sin protección",
    remediation_unencrypted_creds_encrypt:
      "Use cifrado AES-256 o más fuerte para credenciales almacenadas",
    remediation_unencrypted_creds_implement:
      "Implemente almacenamiento seguro de credenciales: use llavero del SO, vault cifrado, o hashing (bcrypt/scrypt) para contraseñas",
    remediation_unencrypted_creds_real_encryption:
      "Reemplace codificación base64 con cifrado real (AES-256-GCM)",
    remediation_unencrypted_creds_param_secure:
      "Agregue cifrado/hashing para almacenamiento de credenciales en este parámetro",

    security_scan: "Escaneo de Seguridad",
    select_item_or_exit: 'Selecciona ítem (número) o "exit"',
    select_option: "Selecciona una opción",
    selected: "Seleccionado",
    semantic_issues: "problemas semánticos encontrados (revisar reporte)",
    server: "Servidor",
    server_no_mcp: "El servidor responde pero no soporta el protocolo MCP",
    server_not_running:
      "El servidor no está corriendo o el puerto es incorrecto",
    server_reachable_not_http:
      "El servidor es alcanzable pero no responde a HTTP",
    server_responded: "El servidor respondió con",
    server_slow: "El servidor está tardando demasiado en responder",
    set_minimum_key_length_to_256_bits_for_symmetric_e:
      "Establezca una longitud mínima de clave de 256 bits para cifrado simétrico, 2048 bits para RSA.",
    set_minlength_to_at_least_8_characters_preferably:
      "Establece minLength a al menos 8 caracteres, preferiblemente 12 o más.",
    shorten_duration: "Acorta duración de prueba: --duration 10",
    simulating_load: "Simulando carga",
    starting_stress_test: "Iniciando prueba de estrés...",
    strengthen_the_regex_to_strictly_exclude_sql_metac:
      "Fortalecer la regex para excluir estrictamente metacaracteres de SQL como '",
    stress_test_complete: "¡Prueba de estrés completa!",
    stress_test_error: "Error en Prueba de Estrés",
    stress_test_failed_msg: "Prueba de estrés fallida",
    stress_high_cpu: "USO DE CPU ALTO: Pico {peak}%, Promedio {avg}%",
    stress_high_memory:
      "USO DE MEMORIA ALTO: Pico {peak}%, Promedio {avg}% (Mínimo disponible: {avail}MB)",
    stress_low_memory:
      "MEMORIA BAJA CRÍTICA: Solo {avail}MB disponibles durante la prueba",
    editor_exited_with_code: "El editor salió con el código {code}",
    // Fuzz command
    initializing_fuzzer: "Inicializando fuzzer...",
    fuzzing_progress: "Fuzzing",
    vulnerability_found: "Vulnerabilidad encontrada",
    fuzz_session_summary: "Resumen de Sesión de Fuzz",
    vulnerabilities_detected: "Vulnerabilidades Detectadas",
    fuzz_complete_vulns_found:
      "Fuzzing completo - vulnerabilidades encontradas",
    fuzz_complete_no_vulns:
      "Fuzzing completo - sin vulnerabilidades detectadas",
    errors_during_fuzzing: "Errores durante fuzzing",
    fuzz_failed: "Fuzzing falló",
    fuzz_error: "Error de Fuzz",
    no_generators_selected: "No hay generadores seleccionados",
    no_detectors_selected: "No hay detectores seleccionados",
    connecting_to_target: "Conectando al objetivo...",
    discovering_schema: "Descubriendo schema de la herramienta...",
    starting_fuzz_session: "Iniciando sesión de fuzz",
    check_server_running: "Verifica si el servidor está corriendo",
    try_doctor_command: "Prueba el comando doctor primero",
    reduce_concurrency: "Prueba reduciendo la concurrencia",
    success_label: "Éxito",
    success_rate: "Tasa de Éxito",
    suggestions: "Sugerencias",
    system_diagnostic: "Diagnóstico del Sistema",
    target_label: "Objetivo",
    test_servers: "Servidores de Prueba",
    testing_handshake: "Probando handshake de protocolo...",
    tests_label: "pruebas",
    throughput: "Rendimiento",
    timeout_error: "Tiempo de espera agotado",
    tip_auth_creds: "Verifique las credenciales de autenticación",
    tip_check_implementation: "Verifica la implementación del servidor",
    tip_check_logs: "Revisa los logs del servidor para errores",
    tip_check_permissions:
      "Asegúrese de tener permiso para acceder a este servidor",
    tip_check_process: "Verifica si el proceso del servidor está activo",
    tip_check_process_generic:
      "Verifique si el servidor está corriendo: ps aux | grep node",
    tip_check_server: "Verifica que tu servidor esté corriendo:",
    tip_check_spelling: "Verifica la ortografía del hostname",
    tip_increase_timeout: "Aumenta el timeout con --timeout 10000",
    tip_increase_timeout_30:
      "Intente aumentar el tiempo de espera: --timeout 30000",
    tip_ping_hostname: "Verifica que el DNS funcione (ping hostname)",
    tip_protocol_mismatch:
      "El servidor podría no implementar correctamente el protocolo MCP",
    tip_run_doctor: "Ejecuta diagnósticos para análisis detallado:",
    tip_slow_server: "El servidor podría estar lento o sobrecargado",
    tip_try_transport: "Intenta usar un transporte diferente:",
    tip_use_ip: "Intente usar una dirección IP en lugar del nombre de host",
    tip_use_verbose_raw: "Usa --verbose para ver la respuesta cruda",
    tip_verbose: "Ejecuta con --verbose para más detalles",
    tip_verify_dns_generic:
      "Verifica que el host {host} sea alcanzable (ping {host})",
    tip_verify_mcp_server:
      "Verifique que el servidor sea realmente un servidor MCP (no una API HTTP)",
    tip_verify_port: "Verifica que el número de puerto sea correcto",
    tip_verify_tokens:
      "Verifique que las claves de API o tokens sean correctos",
    tip_verify_url: "Verifica que la URL sea correcta:",
    tool_label: "Herramienta",
    total_requests: "Total de Peticiones",
    troubleshooting_tips: "Consejos de Solución",
    try_different_transport: "Prueba diferente transporte: -t stdio o -t http",
    try_ping: "Intenta: ping",
    try_prefix: "Intenta:",
    try_running: "Intenta ejecutar",
    type_editor: 'Escribe ".editor" para abrir editor externo',
    type_lang_to_change: ' (escribe "lang" para cambiar)',
    type_simple_json: 'Escribe JSON simple directamente (ej. {"key": "val"})',
    unclear_if_passwords_are_stored_securely:
      "No está claro si las contraseñas se almacenan de forma segura",
    unclear_if_strong_cryptography_is_used:
      "No está claro si se utiliza criptografía fuerte",
    config_using_path: "   Usando configuración desde: {path}",
    config_using_default: "   Usando configuración por defecto (Default)",
    config_load_error:
      "⚠️  Error de carga de configuración (usando por defecto):",
    unexpected_error: "Ocurrió un error inesperado",
    unknown: "Desconocido",
    unknown_compilation_failure: "Error de compilación desconocido",
    unknown_key: "Clave desconocida",
    unsanitized_input_in_sql_query_context:
      "Entrada no sanitizada en contexto de consulta SQL",
    update_description_to_explicitly_state_that_extern:
      "Actualizar la descripción para indicar explícitamente que las entidades externas están deshabilitadas. Configurar el analizador XML con: resolve_entities=False, load_dtd=False, no_network=True.",
    update_tool_description_to_explicitly_state_use_of:
      "Actualizar la descripción de la herramienta para indicar explícitamente el uso de sentencias preparadas, ORMs o constructores de consultas. Nunca concatenar la entrada del usuario en cadenas SQL.",
    upgrade_to_aes256_or_rsa2048_minimum:
      "Actualice a AES-256 o RSA-2048+ como mínimo.",
    upgrade_to_sha256_or_stronger: "Actualiza a SHA-256 o superior.",
    upstream_error: "Error upstream",
    url_format: "Formato de URL",
    use_cryptographically_secure_random_number_generat:
      "Utilice un generador de números aleatorios criptográficamente seguro (CSPRNG): crypto.randomBytes(), módulo secrets, o /dev/urandom.",
    use_prepared_statements_with_placeholders_and_impl:
      "Usar sentencias preparadas con marcadores de posición Y implementar validación de entrada estricta (p. ej., ^[a-zA-Z0-9_]+$ para identificadores).",
    valid_label: "válido",
    valid_url: "URL Válida",
    validate_against_medical_coding_standards_icd10_sn:
      "Validar según estándares de codificación médica (ICD-10, SNOMED). Asegurar el cumplimiento de HIPAA.",
    view_evidence: "Ver Evidencia",
    validate_biometric_template_format_ensure_irrevers:
      "Validar el formato de la plantilla biométrica. Asegurar la irreversibilidad.",
    validate_card_numbers_with_luhn_algorithm_cvv_d34:
      "Validar números de tarjeta con el algoritmo de Luhn. CVV: ^\\d{3,4}$. Nunca almacenar CVV.",
    validate_date_formats_yyyymmdd_implement_age_range:
      "Validar formatos de fecha (YYYY-MM-DD). Implementar verificaciones de rango de edad.",
    validating_schema: "Validando cumplimiento de esquema...",
    validation_complete: "¡Validación completa!",
    validation_failed: "Validación Fallida",
    validation_report: "Reporte de Validación",
    verify_endpoint_path: "Verifica que la ruta del endpoint sea correcta",
    verify_mcp_server: "Verifica que esto sea realmente un servidor MCP",
    warn_dos_attempt:
      "Esto puede indicar un servidor mal configurado o malicioso intentando un ataque DoS.",
    warn_no_sandbox: "⚠️  Ejecutando sin sandbox (--no-sandbox)",
    warn_private_ip: "⚠️  Conectando a una dirección privada/interna",
    welcome_title: "Validador Automatizado para Model Context Protocol",
    working_server: "servidor funcional",

    // Doctor Pro keys
    section_binary_integrity: "Integridad del Binario",
    section_environment: "Entorno de Sistema",
    section_mcp_server: "Servidor MCP",
    section_env_audit: "Auditoría de Seguridad del Entorno",
    integrity_manifest: "Manifiesto de Integridad",
    integrity_manifest_missing:
      "Falta el archivo de manifiesto (¿no es un build de producción?)",
    integrity_manifest_parse_error: "Archivo de manifiesto corrupto",
    integrity_manifest_found: "Manifiesto encontrado",
    integrity_hash: "Checksum SHA-256",
    integrity_hash_read_error: "No se pudo leer el binario actual",
    integrity_hash_ok: "El binario es auténtico",
    integrity_hash_mismatch:
      "BRECHA DE INTEGRIDAD: ¡El binario ha sido modificado!",
    integrity_build_age: "Antigüedad del Build",
    integrity_build_stale: "El build tiene más de 30 días",
    integrity_build_fresh: "El build está actualizado",
    env_reports_dir: "Directorio de Reportes",
    env_reports_dir_writable: "El directorio es escribible",
    env_reports_dir_created: "Directorio creado exitosamente",
    env_reports_dir_not_writable: "El directorio no es escribible",
    mcp_tools: "Herramientas",
    mcp_resources: "Recursos",
    mcp_prompts: "Solicitudes",
    mcp_tools_detected: "{count} herramientas detectadas",
    mcp_resources_detected: "{count} recursos detectados",
    mcp_prompts_detected: "{count} prompts detectados",
    mcp_no_tools: "No se encontraron herramientas",
    mcp_no_resources: "No se encontraron recursos",
    audit_total_env_vars: "Variables de Entorno",
    audit_env_scanned: "Variables analizadas",
    audit_sensitive_names: "Nombres Sensibles",
    audit_no_sensitive_vars:
      "No se encontraron nombres de variables sospechosos",
    audit_sensitive_var_warning:
      "Se encontró un secreto potencial en el nombre de la variable",
    audit_file_perms: "Permisos",
    audit_file_perms_loose: "Los permisos son demasiado permisivos",
    audit_file_perms_ok: "Los permisos son seguros",
    summary_issues_found: "{count} problemas encontrados",
    summary_critical: "críticos",
    summary_warnings: "advertencias",
    summary_no_critical: "Sin problemas críticos",
    summary_all_ok: "Todos los sistemas funcionando correctamente",
    watch_live: "Monitoreo en Vivo",
    watch_next_in: "próxima actualización en {seconds}s",
    found: "encontradas",
    verbose_mode_active: "LOGS DE DIAGNÓSTICO DETALLADO ACTIVADOS",
    verbose_integrity_binary_path: "Binario en ejecución",
    verbose_integrity_manifest_path: "Manifiesto de integridad",
    verbose_integrity_manifest_found: "Archivo de manifiesto cargado con éxito",
    verbose_integrity_build_date: "Fecha de creación del build",
    verbose_integrity_computing_hash: "Calculando hash SHA-256 del binario...",
    verbose_integrity_computed: "Hash calculado",
    verbose_integrity_expected: "Hash esperado",
    verbose_env_registering_checks: "Registrando chequeos de sistema...",
    verbose_env_running_checks: "Ejecutando diagnósticos...",
    verbose_env_checking_reports_dir: "Probando acceso de escritura en",
    verbose_env_reports_dir_created:
      "El directorio no existía, creado con éxito",
    verbose_server_non_http_target:
      "El objetivo es local (stdio), saltando chequeos de red",
    verbose_server_dns_lookup: "Resolviendo DNS para",
    verbose_server_dns_resolved: "Resolución DNS exitosa",
    verbose_server_dns_failed: "Fallo en la resolución DNS",
    verbose_server_socket_opening: "Abriendo socket TCP hacia",
    verbose_server_socket_connected: "Conexión establecida",
    verbose_server_socket_closing: "cerrando socket",
    verbose_server_socket_closed: "Socket cerrado",
    verbose_server_socket_timeout: "Tiempo de espera del socket agotado",
    verbose_server_socket_error: "Error de socket",
    verbose_server_transport_type: "Transporte seleccionado",
    verbose_server_handshake_sending:
      "Enviando handshake de inicialización MCP...",
    verbose_server_handshake_ok: "Handshake aceptado por el servidor",
    verbose_server_handshake_failed: "Handshake rechazado",
    verbose_server_capabilities_raw: "JSON de capacidades crudo",
    verbose_server_inventory: "Inventario extraído",
    verbose_server_exception: "Excepción de protocolo",
    verbose_audit_scanning: "Escaneando",
    verbose_audit_env_vars: "variables de entorno",
    verbose_audit_no_sensitive_found:
      "No se detectaron patrones sensibles en los nombres de variables",
    verbose_audit_sensitive_triggered:
      "Nombres de variables sospechosos detectados",
    verbose_audit_file_perms: "Verificando permisos para",

    // Disclaimer keys
    disclaimer_title: "Aviso Importante",
    disclaimer_main_text:
      "Este informe se proporciona únicamente con fines informativos y no constituye una certificación o garantía de seguridad.",
    disclaimer_scope_title: "Lo que esta herramienta analiza:",
    disclaimer_scope_1:
      "Patrones de validación de entrada y firmas de vulnerabilidades comunes",
    disclaimer_scope_2: "Cumplimiento del protocolo MCP",
    disclaimer_scope_3: "Indicadores de vectores de ataque conocidos",
    disclaimer_scope_4: "Calidad del código y documentación",
    disclaimer_limitations_title: "Lo que esta herramienta NO analiza:",
    disclaimer_limitations_1: "Vulnerabilidades de lógica de negocio",
    disclaimer_limitations_2:
      "Correctitud de implementación de autenticación/autorización",
    disclaimer_limitations_3:
      "Comportamiento en tiempo de ejecución bajo condiciones reales",
    disclaimer_limitations_4: "Seguridad de dependencias de terceros",
    disclaimer_limitations_5: "Configuración del entorno de producción",
    disclaimer_no_warranty:
      'Esta herramienta se proporciona "TAL CUAL" sin garantía de ningún tipo. Una puntuación aprobatoria no garantiza la seguridad.',
    disclaimer_llm_notice:
      "Aviso de Análisis LLM: Los metadatos de herramientas/recursos fueron enviados a la API de {provider} para análisis semántico. No se compartieron solicitudes ni respuestas reales del servidor.",
    disclaimer_professional_audit:
      "Para despliegues en producción, se recomienda una auditoría de seguridad profesional.",

    // New HTML Generator Tailwind Design
    interactive: "Interactivo",
    intelligence_report: "Informe de Inteligencia",
    threat_landscape: "Panorama de Amenazas",
    active_findings: "Hallazgos Activos",
    recommendation: "Remediación",
    summary: "Resumen",
    scan_id: "ID de Escaneo",
    issues: "Problemas",
    critical_vulnerabilities: "Vulnerabilidades Críticas",
    high_severity: "Severidad Alta",
    medium_severity: "Severidad Media",
    low_severity: "Severidad Baja",
    click_to_zoom: "Click para ampliar e interactuar",
    settings: "Configuración",
    protocol_compliance_full: "Cumplimiento de Protocolo",
    compliance_passed: "Todas las verificaciones de protocolo pasaron",
    compliance_failed: "Validación de protocolo falló",
    mcp_version: "Versión MCP",
    evidence: "Evidencia",
    sort_severity_desc: "ORDEN: SEVERIDAD (DESC)",
    time_ago_just_now: "Justo ahora",
    time_ago_minutes: "hace {n}m",
    time_ago_hours: "hace {n}h",
    time_ago_days: "hace {n}d",
    press_q_to_exit: "Presiona [Q] para detener el proxy y guardar la sesión",
    option_proxy_log_file:
      "Guardar los registros de auditoría del proxy en un archivo de texto",
    proxy_session_ended: "Sesión de proxy finalizada.",
    proxy_save_question: "¿Deseas guardar los registros de la sesión?",
    proxy_save_none: "No guardar",
    proxy_save_txt: "Guardar como .txt (Legible)",
    proxy_save_json: "Guardar como .json (Datos estructurados)",
    proxy_save_md: "Guardar como .md (Markdown)",
    proxy_save_format_question: "Selecciona el formato de exportación:",
    proxy_filename_prompt: "Introduce el nombre del archivo:",

    // Block A: OWASP LLM Top 10 (SEC-023 to SEC-030)
    sec_023_excessive_agency:
      'La herramienta "{toolName}" parece ser una operación de solo lectura (get_/fetch_/read_) pero incluye parámetros destructivos. Viola el principio de menor privilegio - el alcance de la herramienta excede la intención semántica.',
    sec_023_recommendation:
      "Dividir herramienta en operaciones separadas de lectura y escritura. Eliminar parámetros destructivos (delete, force, recursive) de herramientas de solo lectura. Seguir principio de responsabilidad única.",
    sec_024_prompt_injection:
      'La herramienta "{toolName}" acepta parámetros no validados relacionados con prompts: {params}. Pueden explotarse para inyección de prompts directa si se pasan al contexto LLM u otras herramientas sin sanitización.',
    sec_024_recommendation:
      "Agregar restricción maxLength (≤500 caracteres), validación de patrón, o enum para parámetros relacionados con prompts. Nunca pasar entrada de usuario directamente a prompts del sistema LLM. Implementar filtrado de contenido para patrones de inyección.",
    sec_024_description_injection:
      'La descripción de la herramienta "{toolName}" contiene instrucciones imperativas que apuntan al contexto AI: "…{snippet}…". Los atacantes embeben instrucciones en metadata de herramientas para manipular el comportamiento del LLM sin tocar el código.',
    sec_024_description_recommendation:
      "Reescribir la descripción de la herramienta para describir solo la funcionalidad — no qué debe hacer la IA. Eliminar cualquier imperativo como 'when processing', 'include a summary of', 'forward all', o referencias al contexto de conversación/sesión. Tratar las descripciones de herramientas como contenido no confiable visible para el LLM.",
    sec_024_default_injection:
      'La herramienta "{toolName}" parámetro "{param}" tiene un valor predeterminado que contiene instrucciones embebidas: "{snippet}". Los valores predeterminados se interpolan en el contexto del LLM y pueden actuar como vectores de inyección encubiertos.',
    sec_024_default_recommendation:
      "Los valores predeterminados deben ser cadenas simples de solo formato (ej. 'csv', 'json', 'asc'). Nunca embeber instrucciones en lenguaje natural o cadenas de múltiples cláusulas en valores predeterminados. Mover cualquier guía operacional a documentación externa.",
    sec_024_annotation_injection:
      'El campo de anotación "{field}" de la herramienta "{toolName}" contiene contenido similar a instrucciones: "{snippet}". Los campos de anotación x-* personalizados se incluyen en el contexto de herramientas del LLM y pueden transportar cargas de inyección encubiertas.',
    sec_024_annotation_recommendation:
      "Eliminar contenido instruccional de los campos de anotación. Las anotaciones solo deben transportar sugerencias legibles por máquina (flags booleanos, valores enum). Nunca usar campos x-* para pasar directivas en lenguaje natural a la IA.",
    sec_024_resource_injection:
      'La descripción del recurso "{resourceName}" contiene instrucciones imperativas que apuntan al contexto AI: "…{snippet}…". Las descripciones de recursos son visibles para el LLM y pueden transportar cargas de inyección igual que las descripciones de herramientas.',
    sec_024_prompt_template_injection:
      'La descripción del template de prompt "{promptName}" contiene instrucciones imperativas que apuntan al contexto AI: "…{snippet}…". Los templates de prompt tienen acceso directo a la ventana de contexto del LLM — la inyección aquí es especialmente peligrosa.',
    sec_024_prompt_template_recommendation:
      "Las descripciones de templates de prompt solo deben describir el propósito del template. Eliminar cualquier lenguaje imperativo, referencias al historial de conversación, o instrucciones dirigidas al runtime de AI. Tratar las descripciones de prompts como metadata no confiable.",
    sec_024_prompt_arg_injection:
      'La descripción del argumento "{argName}" en el template de prompt "{promptName}" contiene instrucciones imperativas: "…{snippet}…". Las descripciones de argumentos se muestran al LLM para explicar cómo completar el template — la inyección aquí manipula el manejo de argumentos.',
    sec_025_unpinned_deps:
      "El servidor declara {count} dependencias con versiones sin fijar: {deps}. Permite ataques de cadena de suministro mediante actualizaciones maliciosas de paquetes (typosquatting, mantenedor comprometido).",
    sec_025_recommendation:
      "Fijar todas las dependencias a versiones exactas (eliminar ^, ~, *, latest). Usar archivos de bloqueo (package-lock.json, pnpm-lock.yaml). Implementar escaneo SCA (npm audit, Snyk, Dependabot).",
    sec_025_no_deps_declared:
      "El servidor no declara dependencias en serverInfo. Si usa paquetes externos, esto impide auditoría de cadena de suministro.",
    sec_025_declare_deps_recommendation:
      "Declarar todas las dependencias en serverInfo.dependencies con versiones fijadas para transparencia de cadena de suministro.",
    sec_026_sensitive_exposure:
      'La herramienta "{toolName}" maneja datos sensibles (PII, credenciales, información de salud) pero carece de mecanismos de redacción de salida. Falta contentEncoding, restricciones de formato, o palabras clave de redacción en descripción.',
    sec_026_recommendation:
      'Implementar filtrado de salida: agregar outputSchema con contentEncoding, o documentar redacción en descripción ("las salidas son enmascaradas/anonimizadas"). Nunca devolver PII sin procesar en respuestas de herramienta.',
    sec_027_training_poisoning:
      'La herramienta "{toolName}" acepta datos de entrenamiento/corpus sin restricciones de validación. Vulnerable a ataques de envenenamiento de datos - datos de entrenamiento maliciosos pueden inyectar puertas traseras en modelos.',
    sec_027_recommendation:
      "Agregar validación para datos de entrenamiento: restricciones maxLength, maxItems, pattern o format. Implementar seguimiento de procedencia de datos. Considerar firmas criptográficas para conjuntos de datos de entrenamiento.",
    sec_028_model_dos:
      'La herramienta "{toolName}" tiene parámetros sin límites: {params}. Puede explotarse para DoS del modelo agotando ventanas de contexto o causando bucles infinitos.',
    sec_028_recommendation:
      "Agregar restricciones: maxItems (≤100) para arrays, maxLength (≤10000) para strings. Implementar timeouts para operaciones recursivas. Agregar limitación de velocidad para herramientas costosas.",
    sec_029_insecure_plugin:
      'La herramienta "{toolName}" tiene fallas de diseño: {issues}. Viola principios de diseño seguro de plugin (falta inputSchema, sin parámetros requeridos, mezcla lectura/escritura, carece de validación).',
    sec_029_recommendation:
      "Corregir problemas de diseño: agregar inputSchema, hacer parámetros críticos requeridos, separar operaciones lectura/escritura (SRP), agregar restricciones de validación (pattern, format, enum).",
    sec_030_excessive_disclosure:
      'La herramienta "{toolName}" recupera datos sin paginación/filtrado: {reason}. Viola minimización de datos - devuelve más datos de los necesarios para tarea LLM, aumentando riesgo de fuga.',
    sec_030_recommendation:
      "Agregar parámetros de paginación (limit, offset), parámetros de filtrado (filter, where, fields). Implementar límites predeterminados (≤100 elementos). Documentar qué datos se devuelven realmente.",

    // Block B: Ataques Multi-Agente (SEC-032 to SEC-041)
    sec_032_result_tampering:
      'La herramienta "{toolName}" consume resultados de otras herramientas pero carece de verificación de integridad (firmas, hashes, HMAC). Vulnerable a ataques de agente-en-el-medio.',
    sec_032_recommendation:
      "Agregar verificación de integridad: requerir parámetro signature/hash, implementar validación HMAC, o usar canales autenticados. Documentar formato de resultado esperado con metadatos de verificación.",
    sec_033_recursive_loop:
      'La herramienta "{toolName}" tiene patrones recursivos/de bucle sin límites de profundidad. Puede explotarse para crear bucles infinitos, causando agotamiento de recursos (desbordamiento de pila, fuga de memoria).',
    sec_033_recommendation:
      "Agregar parámetros de límite de profundidad: max_depth, recursion_limit, max_iterations. Implementar seguimiento de recursión del lado del servidor. Establecer valores predeterminados razonables (≤10 profundidad).",
    sec_033_circular_chain:
      "Se detectó cadena de dependencia circular de herramientas: {chain}. Múltiples herramientas se referencian entre sí, creando potencial de bucle infinito en escenarios multi-agente.",
    sec_033_chain_recommendation:
      "Romper dependencias circulares: rediseñar interfaces de herramienta, agregar condiciones de salida explícitas, implementar seguimiento de pila de llamadas, establecer límite de recursión global.",
    sec_034_privilege_escalation:
      'La herramienta "{toolName}" permite delegación de privilegios (on_behalf_of, delegate_to) sin validación de rol. Permite a agentes de bajo privilegio escalar permisos.',
    sec_034_recommendation:
      "Agregar validación de rol: requerir parámetros agent_id + role, implementar verificaciones RBAC, validar cadenas de delegación, registrar todos los cambios de privilegio para auditoría.",
    sec_034_mixed_privileges:
      'La herramienta "{toolName}" mezcla operaciones de lectura y escritura en diferentes niveles de privilegio. Viola separación de deberes - permite ataques de confusión de privilegios.',
    sec_034_separation_recommendation:
      "Separar herramientas por nivel de privilegio: crear versiones distintas admin/usuario, implementar menor privilegio por herramienta, agregar requisitos de permiso explícitos.",
    sec_035_state_poisoning:
      'La herramienta "{toolName}" modifica estado compartido de agente sin validación o aislamiento: {issue}. Agentes maliciosos pueden corromper estado para otros agentes.',
    sec_035_recommendation:
      "Implementar aislamiento de estado: requerir agent_id para todas las operaciones de estado, agregar restricciones de validación, usar almacenamiento con namespace, implementar verificaciones de integridad de estado (hashes).",
    sec_036_agent_ddos:
      'La herramienta "{toolName}" es vulnerable a DoS de agente distribuido: {reason}. Múltiples agentes pueden coordinarse para agotar recursos (amplificación, sin límites por agente).',
    sec_036_recommendation:
      "Implementar limitación de velocidad por agente, agregar cuotas globales, rastrear agent_id para todas las operaciones, establecer límites de recursos (CPU, memoria, ancho de banda) por agente.",
    sec_037_cross_agent_injection:
      'La herramienta "{toolName}" reenvía mensajes entre agentes con parámetros vulnerables: {params}. Agente A puede inyectar prompts en el contexto del Agente B.',
    sec_037_recommendation:
      "Sanitizar todo el contenido reenviado: agregar maxLength (≤500), implementar filtros de inyección de prompts, usar formatos de mensaje estructurados (no texto libre), validar identidad del remitente.",
    sec_038_reputation_hijacking:
      'La herramienta "{toolName}" modifica puntuaciones de reputación/confianza de agente sin verificación criptográfica. Permite suplantación de reputación y ataques Sybil.',
    sec_038_recommendation:
      "Agregar firmas criptográficas a datos de reputación: requerir prueba de trabajo o certificados, implementar verificación descentralizada, usar blockchain/ledger distribuido para reputación.",
    sec_039_path_traversal_chain:
      'La herramienta "{toolName}" consume rutas de archivo de: {producers}. Carece de validación de ruta - vulnerable a ataques de recorrido de ruta cuando se encadena con herramientas productoras de rutas.',
    sec_039_recommendation:
      "Implementar validación de ruta: canonicalizar rutas, lista blanca de directorios permitidos, rechazar secuencias ../, usar path.resolve() y validar contra basedir.",
    sec_041_memory_injection:
      'La herramienta "{toolName}" escribe en memoria de agente con {issue}. Agentes maliciosos pueden inyectar instrucciones del sistema o contexto malicioso en memoria a largo plazo.',
    sec_041_recommendation:
      'Restringir tipos de memoria: usar enum para entry_type (excluir "system", "instruction"), agregar validación para contenido de memoria, implementar sandbox de memoria por agente.',
  },
};
