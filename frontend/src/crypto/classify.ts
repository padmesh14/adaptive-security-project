import rules from "../../../src/sensitivity_rules.json";
import Papa from "papaparse";

type Rules = typeof rules;
type Features = { column: string; name_keyword_score: number; name_keyword_group: string | null; pattern_match_ratio: number; uniqueness_ratio: number; is_bounded_numeric: boolean; fill_ratio: number; risk_score: number; sensitivity_tier: "Low" | "Medium" | "High" };
const patterns = Object.values(rules.patterns).map(pattern => new RegExp(pattern));

function pyRound(value: number): number { // Python's ties-to-even behavior
  const floor = Math.floor(value), frac = value - floor;
  return frac === 0.5 ? (floor % 2 === 0 ? floor : floor + 1) : Math.round(value);
}
const pyRound3 = (value: number) => pyRound(value * 1000) / 1000;

function percentile(values: number[], p: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  if (sorted.length < 2) return sorted[0] ?? 0;
  const index = (sorted.length - 1) * p, lo = Math.floor(index), hi = Math.ceil(index);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (index - lo);
}

export function classifyTable(columns: string[], rows: unknown[][]): Features[] {
  const excluded = new Set(["row_id", "record_id", "source_dataset", "id"]);
  const features: Features[] = [];
  for (let colIndex = 0; colIndex < columns.length; colIndex++) {
    const column = columns[colIndex];
    if (excluded.has(column.toLowerCase())) continue;
    const values = rows.map(row => row[colIndex]).filter(value => value !== null && value !== undefined).map(value => String(value).trim());
    const filled = values.filter(value => value !== "");
    let nameScore = 0, group: string | null = null;
    for (const [key, spec] of Object.entries(rules.name_keywords) as [string, Rules["name_keywords"][keyof Rules["name_keywords"]]][]) {
      if (spec.keywords.some(keyword => column.toLowerCase().includes(keyword)) && spec.score > nameScore) { nameScore = spec.score; group = key; }
    }
    const ratios = filled.length ? filled.filter(value => patterns.some(pattern => { pattern.lastIndex = 0; return pattern.test(value); })).length / filled.length : 0;
    const uniqueness = filled.length ? new Set(filled).size / filled.length : 0;
    const nums = filled.map(value => Number(value));
    const bounded = filled.length > 0 && nums.every(Number.isFinite) && nums.reduce((a, b) => Math.max(a, b), -Infinity) - nums.reduce((a, b) => Math.min(a, b), Infinity) < rules.bounded_numeric_range;
    const fill = values.length / Math.max(rows.length, 1);
    let score = pyRound((nameScore + ratios * 40 + Math.min(uniqueness * 25, 25) + (bounded ? rules.bounded_numeric_penalty : 0)) * fill);
    score = Math.max(0, Math.min(score, 100));
    features.push({ column, name_keyword_score: nameScore, name_keyword_group: group, pattern_match_ratio: pyRound3(ratios),
      uniqueness_ratio: pyRound3(uniqueness), is_bounded_numeric: bounded, fill_ratio: pyRound3(fill), risk_score: score, sensitivity_tier: "Low" });
  }
  const scores = features.map(f => f.risk_score);
  let low = 25, medium = 55;
  const mean = scores.reduce((a, b) => a + b, 0) / Math.max(scores.length, 1);
  const std = Math.sqrt(scores.reduce((sum, v) => sum + (v - mean) ** 2, 0) / Math.max(scores.length, 1));
  if (scores.length >= 5 && std >= 1e-6) { low = pyRound(percentile(scores, .4) * 10) / 10; medium = pyRound(percentile(scores, .75) * 10) / 10; if (medium <= low) medium = low + 1; }
  for (const f of features) {
    f.sensitivity_tier = f.risk_score <= low ? "Low" : f.risk_score <= medium ? "Medium" : "High";
    if (["identifier", "biometric"].includes(f.name_keyword_group ?? "") && f.fill_ratio > .05) { f.sensitivity_tier = "High"; f.risk_score = Math.max(f.risk_score, medium + 1); }
  }
  return features;
}

export async function classifyCsv(file: File): Promise<Features[]> {
  if (file.size > 5 * 1024 * 1024) throw new Error("Classification preview supports CSV files up to 5 MiB");
  const parsed = Papa.parse<string[]>(await file.text(), { header: false, skipEmptyLines: false, dynamicTyping: false });
  if (parsed.errors.length || parsed.data.length < 2) throw new Error("Could not parse this CSV for local classification");
  const [columns, ...rows] = parsed.data;
  return classifyTable(columns, rows);
}
