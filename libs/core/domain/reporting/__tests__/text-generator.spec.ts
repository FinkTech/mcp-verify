/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Unit tests for TextReportGenerator components
 *
 * Tests the component-based architecture of text-generator.ts:
 *   - Layout primitives (rep, pad, centre, wordWrap)
 *   - UI components (ScoreGauge, Table, FindingCard)
 *   - Data transformers (calculateRiskLabel, groupFindingsBySeverity, etc.)
 *
 * These tests ensure visual integrity and prevent formatting regressions.
 */

import {
  // Layout primitives
  rep,
  pad,
  centre,
  wordWrap,
  // UI components
  ScoreGauge,
  Table,
  FindingCard,
  TitleBox,
  SectionHeader,
  KeyValueRow,
  Separator,
  // Data transformers
  calculateRiskLabel,
  groupFindingsBySeverity,
  calculateFuzzPassRate,
  formatTimestamp,
  // Types
  type TableOptions,
  type FindingCardData,
} from "../text-generator";
import type {
  SecurityFinding,
  FuzzingReport,
} from "../../mcp-server/entities/validation.types";

import { translations } from "../i18n";

// ===========================================================================
// LAYOUT PRIMITIVES TESTS
// ===========================================================================

describe("Layout Primitives", () => {
  describe("rep()", () => {
    it("should repeat character N times", () => {
      expect(rep("x", 5)).toBe("xxxxx");
      expect(rep("=", 10)).toBe("==========");
      expect(rep("░", 3)).toBe("░░░");
    });

    it("should return empty string for 0 repetitions", () => {
      expect(rep("x", 0)).toBe("");
    });

    it("should return empty string for negative repetitions", () => {
      expect(rep("x", -5)).toBe("");
    });

    it("should handle multi-character strings", () => {
      expect(rep("ab", 3)).toBe("ababab");
    });
  });

  describe("pad()", () => {
    it("should pad short strings with spaces", () => {
      expect(pad("hello", 10)).toBe("hello     ");
      expect(pad("test", 8)).toBe("test    ");
    });

    it("should return exact string if already at target width", () => {
      expect(pad("exact", 5)).toBe("exact");
    });

    it("should truncate strings longer than target width", () => {
      expect(pad("verylongstring", 5)).toBe("veryl");
      expect(pad("truncate me", 8)).toBe("truncate");
    });

    it("should handle empty strings", () => {
      expect(pad("", 5)).toBe("     ");
    });

    it("should handle width of 0", () => {
      expect(pad("test", 0)).toBe("");
    });
  });

  describe("centre()", () => {
    it("should centre text with even width", () => {
      const result = centre("hello", 10);
      expect(result).toBe("  hello   "); // 2 spaces left, 3 spaces right
      expect(result.length).toBe(10);
    });

    it("should centre text with odd width", () => {
      const result = centre("hi", 7);
      expect(result).toBe("  hi   "); // 2 spaces left, 3 spaces right
      expect(result.length).toBe(7);
    });

    it("should handle exact match width", () => {
      expect(centre("exact", 5)).toBe("exact");
    });

    it("should handle text longer than width", () => {
      expect(centre("toolong", 5)).toBe("toolong");
    });

    it("should use custom fill character", () => {
      expect(centre("x", 5, "-")).toBe("--x--");
      expect(centre("test", 10, "=")).toBe("===test===");
    });

    it("should handle empty string", () => {
      const result = centre("", 8);
      expect(result).toBe("        ");
      expect(result.length).toBe(8);
    });
  });

  describe("wordWrap()", () => {
    it("should not wrap text shorter than max width", () => {
      expect(wordWrap("short text", 20)).toBe("short text");
    });

    it("should wrap long text at word boundaries", () => {
      const text =
        "This is a very long line that should be wrapped at word boundaries";
      const result = wordWrap(text, 20);
      const lines = result.split("\n");

      // Every line should be <= 20 characters
      lines.forEach((line) => {
        expect(line.length).toBeLessThanOrEqual(20);
      });

      // Should have multiple lines
      expect(lines.length).toBeGreaterThan(1);
    });

    it("should preserve single long words even if exceeding max width", () => {
      const text = "short verylongwordthatcannotbewrapped end";
      const result = wordWrap(text, 20);
      const lines = result.split("\n");

      // The long word will be on its own line (might exceed max width)
      expect(lines).toContain("verylongwordthatcannotbewrapped");
    });

    it("should apply indent to all lines", () => {
      const text = "This is a very long line that should be wrapped";
      const result = wordWrap(text, 20, "  ");
      const lines = result.split("\n");

      lines.forEach((line) => {
        expect(line.startsWith("  ")).toBe(true);
      });
    });

    it("should handle empty string", () => {
      expect(wordWrap("", 20)).toBe("");
    });

    it("should handle single word", () => {
      expect(wordWrap("word", 20)).toBe("word");
    });
  });
});

// ===========================================================================
// UI COMPONENTS TESTS
// ===========================================================================

describe("UI Components", () => {
  describe("ScoreGauge()", () => {
    it("should render 0 score with all empty blocks", () => {
      const result = ScoreGauge(0, 20);
      expect(result).toBe("░░░░░░░░░░░░░░░░░░░░  0/100");
      expect(result).toContain("0/100");
      expect(result.split("▓").length - 1).toBe(0); // No filled blocks
      expect(result.split("░").length - 1).toBe(20); // All empty blocks
    });

    it("should render 50 score with half-filled blocks", () => {
      const result = ScoreGauge(50, 20);
      expect(result).toContain("50/100");
      expect(result.split("▓").length - 1).toBe(10); // 10 filled blocks
      expect(result.split("░").length - 1).toBe(10); // 10 empty blocks
    });

    it("should render 75 score correctly", () => {
      const result = ScoreGauge(75, 20);
      expect(result).toContain("75/100");
      expect(result.split("▓").length - 1).toBe(15); // 15 filled blocks
      expect(result.split("░").length - 1).toBe(5); // 5 empty blocks
    });

    it("should render 100 score with all filled blocks", () => {
      const result = ScoreGauge(100, 20);
      expect(result).toBe("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  100/100");
      expect(result).toContain("100/100");
      expect(result.split("▓").length - 1).toBe(20); // All filled blocks
      expect(result.split("░").length - 1).toBe(0); // No empty blocks
    });

    it("should clamp values above 100 to 100", () => {
      const result = ScoreGauge(150, 20);
      expect(result).toContain("100/100");
      expect(result.split("▓").length - 1).toBe(20);
    });

    it("should clamp negative values to 0", () => {
      const result = ScoreGauge(-50, 20);
      expect(result).toContain("0/100");
      expect(result.split("░").length - 1).toBe(20);
    });

    it("should support custom width", () => {
      const result = ScoreGauge(50, 10);
      expect(result.split("▓").length - 1).toBe(5);
      expect(result.split("░").length - 1).toBe(5);
    });

    it("should default to width 20", () => {
      const result = ScoreGauge(50);
      expect(result.split("▓").length - 1).toBe(10);
      expect(result.split("░").length - 1).toBe(10);
    });
  });

  describe("Table()", () => {
    it("should render a simple 2x2 table", () => {
      const options: TableOptions = {
        headers: ["Column 1", "Column 2"],
        rows: [
          ["Row 1 Col 1", "Row 1 Col 2"],
          ["Row 2 Col 1", "Row 2 Col 2"],
        ],
        columnWidths: [15, 15],
      };

      const result = Table(options);

      // Snapshot test to capture visual structure
      expect(result).toMatchSnapshot();

      // Verify table contains headers
      expect(result).toContain("Column 1");
      expect(result).toContain("Column 2");

      // Verify table contains row data
      expect(result).toContain("Row 1 Col 1");
      expect(result).toContain("Row 2 Col 2");

      // Verify box-drawing characters
      expect(result).toContain("┌");
      expect(result).toContain("┐");
      expect(result).toContain("└");
      expect(result).toContain("┘");
      expect(result).toContain("│");
      expect(result).toContain("─");
    });

    it("should render table with title", () => {
      const options: TableOptions = {
        headers: ["Name", "Value"],
        rows: [["Test", "123"]],
        columnWidths: [10, 10],
        title: "Test Table",
      };

      const result = Table(options);

      expect(result).toContain("Test Table");
      expect(result).toMatchSnapshot();
    });

    it("should handle single row table", () => {
      const options: TableOptions = {
        headers: ["Header"],
        rows: [["Data"]],
        columnWidths: [20],
      };

      const result = Table(options);

      expect(result).toContain("Header");
      expect(result).toContain("Data");
    });

    it("should handle multiple columns", () => {
      const options: TableOptions = {
        headers: ["A", "B", "C", "D"],
        rows: [
          ["1", "2", "3", "4"],
          ["5", "6", "7", "8"],
        ],
        columnWidths: [5, 5, 5, 5],
      };

      const result = Table(options);

      expect(result).toMatchSnapshot();
    });

    it("should pad cell content to column width", () => {
      const options: TableOptions = {
        headers: ["Short", "LongHeader"],
        rows: [["x", "y"]],
        columnWidths: [10, 15],
      };

      const result = Table(options);

      // Headers and data should be padded to column widths
      expect(result).toContain("Short     "); // Padded to 10
      expect(result).toContain("LongHeader     "); // Padded to 15
    });
  });

  describe("FindingCard()", () => {
    it("should render complete finding card with all fields", () => {
      const data: FindingCardData = {
        index: 1,
        icon: "[!!!]",
        message: "SQL Injection vulnerability detected",
        count: 3,
        rule: "SEC-001",
        component: "database_query",
        cwe: "CWE-89",
        payloads: [
          "'; DROP TABLE users--",
          "' OR '1'='1",
          "' UNION SELECT * FROM passwords--",
        ],
        remediation:
          "Use parameterized queries or prepared statements to prevent SQL injection attacks.",
        labels: {
          rule: "Rule:",
          component: "Component:",
          cwe: "CWE:",
          remediation: "Remediation:",
        },
      };

      const result = FindingCard(data);

      // Verify header with count
      expect(result).toContain(
        "1. [!!!] SQL Injection vulnerability detected (x3)",
      );

      // Verify metadata
      expect(result).toContain("Rule:");
      expect(result).toContain("SEC-001");
      expect(result).toContain("Component:");
      expect(result).toContain("database_query");
      expect(result).toContain("CWE:");
      expect(result).toContain("CWE-89");

      // Verify payloads
      expect(result).toContain("'; DROP TABLE users--");
      expect(result).toContain("' OR '1'='1");

      // Verify remediation
      expect(result).toContain("Remediation:");
      expect(result).toContain("parameterized queries");

      // Verify separator
      expect(result).toContain("·");
    });

    it("should render finding without CWE", () => {
      const data: FindingCardData = {
        index: 2,
        icon: "[!! ]",
        message: "Test finding",
        count: 1,
        rule: "TEST-001",
        component: "test_component",
        payloads: [],
        labels: {
          rule: "Rule:",
          component: "Component:",
          cwe: "CWE:",
          remediation: "Remediation:",
        },
      };

      const result = FindingCard(data);

      expect(result).not.toContain("CWE:");
      expect(result).toContain("TEST-001");
    });

    it("should render finding without remediation", () => {
      const data: FindingCardData = {
        index: 3,
        icon: "[!  ]",
        message: "Medium severity issue",
        count: 1,
        rule: "SEC-005",
        component: "file_handler",
        payloads: [],
        labels: {
          rule: "Rule:",
          component: "Component:",
          cwe: "CWE:",
          remediation: "Remediation:",
        },
      };

      const result = FindingCard(data);

      expect(result).not.toContain("Remediation:");
      expect(result).toContain("SEC-005");
    });

    it("should limit payload display to 5 items", () => {
      const data: FindingCardData = {
        index: 1,
        icon: "[!!!]",
        message: "Many payloads",
        count: 10,
        rule: "SEC-001",
        component: "test",
        payloads: ["p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"],
        labels: {
          rule: "Rule:",
          component: "Component:",
          cwe: "CWE:",
          remediation: "Remediation:",
        },
      };

      const result = FindingCard(data);

      // Should show first 5
      expect(result).toContain("p1");
      expect(result).toContain("p5");

      // Should indicate more
      expect(result).toContain("and 3 more unique variants");
    });

    it("should not show count suffix for single occurrence", () => {
      const data: FindingCardData = {
        index: 1,
        icon: "[!!!]",
        message: "Single finding",
        count: 1,
        rule: "SEC-001",
        component: "test",
        payloads: [],
        labels: {
          rule: "Rule:",
          component: "Component:",
          cwe: "CWE:",
          remediation: "Remediation:",
        },
      };

      const result = FindingCard(data);

      expect(result).not.toContain("(x1)");
      expect(result).toContain("1. [!!!] Single finding");
    });
  });

  describe("TitleBox()", () => {
    it("should create title box with double borders", () => {
      const result = TitleBox("TEST TITLE");

      expect(result).toContain("╔");
      expect(result).toContain("╗");
      expect(result).toContain("╚");
      expect(result).toContain("╝");
      expect(result).toContain("║");
      expect(result).toContain("TEST TITLE");
    });
  });

  describe("SectionHeader()", () => {
    it("should create section header with brackets", () => {
      const result = SectionHeader("SECTION NAME");

      expect(result).toContain("╔");
      expect(result).toContain("╗");
      expect(result).toContain("[ SECTION NAME ]");
    });
  });

  describe("KeyValueRow()", () => {
    it("should format key-value pair with colon", () => {
      const result = KeyValueRow("Label", "Value");

      expect(result).toContain("Label:");
      expect(result).toContain("Value");
      expect(result.startsWith("  ")).toBe(true); // Default indent
    });

    it("should support custom indent", () => {
      const result = KeyValueRow("Key", "Val", "    ");

      expect(result.startsWith("    ")).toBe(true);
    });
  });

  describe("Separator", () => {
    it("should provide thin separator", () => {
      expect(Separator.thin).toContain("─");
      expect(Separator.thin.startsWith("  ")).toBe(true);
    });

    it("should provide medium separator", () => {
      expect(Separator.medium).toContain("·");
    });

    it("should provide thick separator", () => {
      expect(Separator.thick).toContain("═");
    });
  });
});

// ===========================================================================
// DATA TRANSFORMERS TESTS
// ===========================================================================

describe("Data Transformers", () => {
  const t = translations["en"];

  describe("calculateRiskLabel()", () => {
    it("should return Low Risk for score >= 90", () => {
      expect(calculateRiskLabel(90, t)).toBe("Low Risk");
      expect(calculateRiskLabel(95, t)).toBe("Low Risk");
      expect(calculateRiskLabel(100, t)).toBe("Low Risk");
    });

    it("should return Medium Risk for score 70-89", () => {
      expect(calculateRiskLabel(70, t)).toBe("Medium Risk");
      expect(calculateRiskLabel(80, t)).toBe("Medium Risk");
      expect(calculateRiskLabel(89, t)).toBe("Medium Risk");
    });

    it("should return High Risk for score 50-69", () => {
      expect(calculateRiskLabel(50, t)).toBe("High Risk");
      expect(calculateRiskLabel(60, t)).toBe("High Risk");
      expect(calculateRiskLabel(69, t)).toBe("High Risk");
    });

    it("should return Critical Risk for score < 50", () => {
      expect(calculateRiskLabel(0, t)).toBe("Critical Risk");
      expect(calculateRiskLabel(25, t)).toBe("Critical Risk");
      expect(calculateRiskLabel(49, t)).toBe("Critical Risk");
    });

    it("should handle boundary values correctly", () => {
      expect(calculateRiskLabel(89.9, t)).toBe("Medium Risk");
      expect(calculateRiskLabel(90, t)).toBe("Low Risk");
      expect(calculateRiskLabel(69.9, t)).toBe("High Risk");
      expect(calculateRiskLabel(70, t)).toBe("Medium Risk");
    });
  });

  describe("formatTimestamp()", () => {
    it("should format ISO timestamp to readable format", () => {
      const result = formatTimestamp("2024-02-25T10:30:45.123Z");
      expect(result).toBe("2024-02-25 10:30:45 UTC");
    });

    it("should handle invalid timestamps gracefully", () => {
      const invalid = "not-a-date";
      const result = formatTimestamp(invalid);
      expect(result).toBe(invalid); // Should return original on error
    });

    it("should remove milliseconds and timezone", () => {
      const result = formatTimestamp("2024-12-31T23:59:59.999Z");
      expect(result).not.toContain(".999");
      expect(result).toContain("UTC");
    });
  });

  describe("groupFindingsBySeverity()", () => {
    it("should group findings by severity correctly", () => {
      const findings: SecurityFinding[] = [
        {
          rule: "SEC-001",
          severity: "critical",
          message: "Critical issue",
          component: "comp1",
        },
        {
          rule: "SEC-002",
          severity: "high",
          message: "High issue",
          component: "comp2",
        },
        {
          rule: "SEC-003",
          severity: "critical",
          message: "Another critical",
          component: "comp3",
        },
      ];

      const result = groupFindingsBySeverity(findings);

      // Should have critical and high groups
      expect(result.has("critical")).toBe(true);
      expect(result.has("high")).toBe(true);
      expect(result.has("medium")).toBe(false);

      // Critical group should have 2 findings
      const criticalGroup = result.get("critical")!;
      expect(criticalGroup.size).toBe(2);

      // High group should have 1 finding
      const highGroup = result.get("high")!;
      expect(highGroup.size).toBe(1);
    });

    it("should deduplicate identical findings", () => {
      const findings: SecurityFinding[] = [
        {
          rule: "SEC-001",
          severity: "high",
          message: "SQL Injection",
          component: "db",
          cwe: "CWE-89",
        },
        {
          rule: "SEC-001",
          severity: "high",
          message: "SQL Injection",
          component: "db",
          cwe: "CWE-89",
        },
        {
          rule: "SEC-001",
          severity: "high",
          message: "SQL Injection",
          component: "db",
          cwe: "CWE-89",
        },
      ];

      const result = groupFindingsBySeverity(findings);
      const highGroup = result.get("high")!;

      // Should be grouped into one entry
      expect(highGroup.size).toBe(1);

      // Should have count of 3
      const entry = Array.from(highGroup.values())[0];
      expect(entry.count).toBe(3);

      // Should have all 3 payloads
      expect(entry.payloads.size).toBe(3);
      expect(entry.payloads.has("payload1")).toBe(true);
      expect(entry.payloads.has("payload2")).toBe(true);
      expect(entry.payloads.has("payload3")).toBe(true);
    });

    it("should handle empty findings array", () => {
      const result = groupFindingsBySeverity([]);
      expect(result.size).toBe(0);
    });

    it("should preserve severity order", () => {
      const findings: SecurityFinding[] = [
        { rule: "R1", severity: "low", message: "Low", component: "c1" },
        {
          rule: "R2",
          severity: "critical",
          message: "Critical",
          component: "c2",
        },
        { rule: "R3", severity: "medium", message: "Medium", component: "c3" },
        { rule: "R4", severity: "high", message: "High", component: "c4" },
      ];

      const result = groupFindingsBySeverity(findings);
      const severities = Array.from(result.keys());

      // Should be ordered: critical, high, medium, low
      expect(severities).toEqual(["critical", "high", "medium", "low"]);
    });
  });

  describe("calculateFuzzPassRate()", () => {
    it("should calculate pass rate correctly", () => {
      const fuzzing: FuzzingReport = {
        executed: true,
        totalTests: 100,
        failedTests: 25,
        crashes: 0,
        results: [],
      };

      const result = calculateFuzzPassRate(fuzzing);
      expect(result).toBe("75.0");
    });

    it("should return 0.0 for zero total tests", () => {
      const fuzzing: FuzzingReport = {
        executed: true,
        totalTests: 0,
        failedTests: 0,
        crashes: 0,
        results: [],
      };

      const result = calculateFuzzPassRate(fuzzing);
      expect(result).toBe("0.0");
    });

    it("should calculate 100% pass rate", () => {
      const fuzzing: FuzzingReport = {
        executed: true,
        totalTests: 50,
        failedTests: 0,
        crashes: 0,
        results: [],
      };

      const result = calculateFuzzPassRate(fuzzing);
      expect(result).toBe("100.0");
    });

    it("should calculate 0% pass rate", () => {
      const fuzzing: FuzzingReport = {
        executed: true,
        totalTests: 50,
        failedTests: 50,
        crashes: 0,
        results: [],
      };

      const result = calculateFuzzPassRate(fuzzing);
      expect(result).toBe("0.0");
    });

    it("should round to 1 decimal place", () => {
      const fuzzing: FuzzingReport = {
        executed: true,
        totalTests: 3,
        failedTests: 1,
        crashes: 0,
        results: [],
      };

      const result = calculateFuzzPassRate(fuzzing);
      // 2/3 = 66.666... should round to 66.7
      expect(result).toBe("66.7");
    });
  });
});
