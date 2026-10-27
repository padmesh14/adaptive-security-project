import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { classifyTable } from "./classify";

describe("browser classifier parity with the canonical Python rules", () => {
  it("matches the Python classifier for supported synthetic columns", () => {
    const columns = ["temperature", "diagnosis", "email", "bounded_count", "blank", "customer_id"];
    const rows = [
      ["20", "condition-a", "a@example.invalid", "1", "", "c1"],
      ["21", "condition-b", "b@example.invalid", "2", "", "c2"],
      ["22", "condition-c", "c@example.invalid", "3", "", "c3"],
      ["23", "condition-d", "d@example.invalid", "4", "", "c4"],
      ["24", "condition-e", "e@example.invalid", "5", "", "c5"],
      ["25", "condition-f", "f@example.invalid", "6", "", "c6"],
    ];
    const browser = classifyTable(columns, rows).map(({ column, risk_score, sensitivity_tier }) => ({ column, risk_score, sensitivity_tier }));
    const script = `import json,pandas as pd; from src.sensitivity_classifier import classify_columns; d=json.loads(${JSON.stringify(JSON.stringify({ columns, rows }))}); r=classify_columns(pd.DataFrame(d['rows'],columns=d['columns'])); print(r[['column','risk_score','sensitivity_tier']].to_json(orient='records'))`;
    const root = `${process.cwd()}/..`;
    const python = JSON.parse(execFileSync(`${root}/.venv/bin/python`, ["-c", script], { encoding: "utf8", cwd: root }));
    expect(browser).toEqual(python);
  });
});
