import { analyzeContent } from "./contentHeuristics.js";
import { analyzePageUrls } from "./url_heuristics.js";
import type { ExtractedPageData, Verdict } from "../types/heuristics.js";

export interface PageAnalysisResult {
  score: number;
  verdict: Verdict;
  explanation: string;
  contentScore: number;
  urlScore: number;
  findings: string[];
}

function roundScore(score: number): number {
  return Math.round(score * 10) / 10;
}

function verdictFromScore(score: number): Verdict {
  if (score <= 3) {
    return "Safe";
  }
  if (score <= 6) {
    return "Uncertain";
  }
  return "Scam";
}

export function analyzePage(pageData: ExtractedPageData): PageAnalysisResult {
  const contentResult = analyzeContent(pageData);
  const urlResult = analyzePageUrls(pageData);

  const score = roundScore((contentResult.score + urlResult.score) / 2);
  const verdict = verdictFromScore(score);

  const explanation =
    `Combined score ${score}/10 ` +
    `(content: ${contentResult.score}/10, URL: ${urlResult.score}/10). ` +
    `${contentResult.explanation} ${urlResult.explanation}`;

  const findings = [
    ...contentResult.findings.map((finding) => `[Content] ${finding}`),
    ...urlResult.findings.map((finding) => `[URL] ${finding}`),
  ];

  return {
    score,
    verdict,
    explanation,
    contentScore: contentResult.score,
    urlScore: urlResult.score,
    findings,
  };
}
