import { ExtractedPageData, HeuristicResult, Link, Verdict } from "../types/heuristics.js";

const URL_HEURISTIC_CATEGORY_COUNT = 8;
const MIN_SCORE = 1;
const MAX_SCORE = 10;

function roundScore(score: number): number {
  return Math.round(score * 10) / 10;
}

function categoryScore(flagged: boolean): number {
  return flagged ? MAX_SCORE : MIN_SCORE;
}

function typosquatCategoryScore(flagged: boolean, reasonCount: number): number {
  if (!flagged) {
    return MIN_SCORE;
  }
  return Math.min(MAX_SCORE, MIN_SCORE + reasonCount * 2);
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

/**
 * URL-based scam detection heuristics
 * Analyzes links for suspicious characteristics that indicate phishing/scam behavior
 */

// Known favicon URLs for popular brands (for mismatch detection)
const BRAND_FAVICONS: Record<string, string[]> = {
  amazon: ["https://www.amazon.com/favicon.ico", "https://m.media-amazon.com/images/favicon"],
  apple: ["https://www.apple.com/favicon.ico", "https://www.apple.com/assets/"],
  google: ["https://www.google.com/favicon.ico"],
  facebook: ["https://www.facebook.com/favicon.ico"],
  paypal: ["https://www.paypal.com/favicon.ico"],
  github: ["https://github.com/favicon.ico"],
  microsoft: ["https://www.microsoft.com/favicon.ico"],
  linkedin: ["https://www.linkedin.com/favicon.ico"],
};

// Common misspellings and typosquatting patterns (homoglyphs and common mistakes)
const COMMON_TYPOSQUATTING_PATTERNS: Record<string, string[]> = {
  google: ["googl", "gogle", "goog1e", "g00gle", "g0ogle"],
  amazon: ["amazo", "amaz0n", "amaZon", "am4zon"],
  facebook: ["facebok", "faceb00k", "f4cebook", "faceboo"],
  paypal: ["p4yp4l", "paypa1", "p@ypal"],
  apple: ["4pple", "@pple", "appie"],
  microsoft: ["microsof", "micr0soft", "m1cr0s0ft"],
  twitter: ["twiter", "tw1tter", "twitter1"],
  instagram: ["instag4m", "insta9ram", "inst4gram"],
  github: ["g1thub", "gihub"],
  linkedin: ["link3d1n", "1inkedin"],
};

// Numbers that look like letters (homoglyphs)
const HOMOGLYPH_MAP: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "8": "b",
  "9": "g",
};

/**
 * Check if domain length exceeds 45 characters (suspicious)
 */
function checkExcessiveLength(url: string): { flagged: boolean; reason: string } {
  const domain = extractDomain(url);
  if (domain.length > 45) {
    return {
      flagged: true,
      reason: `Domain name is ${domain.length} characters (exceeds 45 char limit)`,
    };
  }
  return { flagged: false, reason: "" };
}

/**
 * Check if domain is under 6 characters (suspicious - too short)
 */
function checkInsufficientLength(url: string): { flagged: boolean; reason: string } {
  const domain = extractDomain(url);
  // Remove TLD for length check
  const domainWithoutTLD = domain.split(".").slice(0, -1).join(".");

  if (domainWithoutTLD.length < 6 && domainWithoutTLD.length > 0) {
    return {
      flagged: true,
      reason: `Domain name is only ${domainWithoutTLD.length} characters (under 6 char minimum)`,
    };
  }
  return { flagged: false, reason: "" };
}

/**
 * Check if URL points to an IP address (instead of domain)
 */
function checkIPAddressLink(url: string): { flagged: boolean; reason: string } {
  const ipv4Regex = /^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}/;
  const ipv6Regex = /^(?:https?:\/\/)?\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?/;

  if (ipv4Regex.test(url)) {
    return {
      flagged: true,
      reason: "URL uses IP address instead of domain name (IPv4)",
    };
  }

  if (ipv6Regex.test(url)) {
    return {
      flagged: true,
      reason: "URL uses IP address instead of domain name (IPv6)",
    };
  }

  return { flagged: false, reason: "" };
}

/**
 * Check for typosquatting and homoglyphs
 * Detects common misspellings and number-for-letter substitutions
 */
function checkTyposquattingAndHomoglyphs(url: string): { flagged: boolean; reasons: string[] } {
  const domain = extractDomain(url).toLowerCase();
  const reasons: string[] = [];

  // Check for known typosquatting patterns
  for (const [legitimate, misspellings] of Object.entries(COMMON_TYPOSQUATTING_PATTERNS)) {
    for (const misspelling of misspellings) {
      if (domain.includes(misspelling)) {
        reasons.push(`Possible typosquatting: "${misspelling}" resembles legitimate brand "${legitimate}"`);
      }
    }
  }

  // Check for homoglyph substitutions (numbers looking like letters)
  let hasHomoglyphs = false;
  for (const [number, letter] of Object.entries(HOMOGLYPH_MAP)) {
    if (domain.includes(number)) {
      const withoutNumber = domain.replace(new RegExp(number, "g"), letter);
      // Check if the letter version matches common domains
      for (const brand of Object.keys(COMMON_TYPOSQUATTING_PATTERNS)) {
        if (withoutNumber.includes(brand)) {
          hasHomoglyphs = true;
          reasons.push(
            `Homoglyph detected: "${number}" used instead of "${letter}" (resembles "${brand}")`
          );
        }
      }
    }
  }

  // Check for unusual character patterns
  if (/[0-9]{2,}/.test(domain)) {
    // Multiple consecutive numbers can be suspicious
    const numberSequences = domain.match(/[0-9]{2,}/g);
    if (numberSequences) {
      reasons.push(
        `Multiple consecutive numbers detected: ${numberSequences.join(", ")}`
      );
    }
  }

  return {
    flagged: reasons.length > 0,
    reasons,
  };
}

/**
 * Extract domain from URL
 */
function extractDomain(url: string): string {
  try {
    // Handle URLs without protocol
    const urlWithProtocol = url.startsWith("http") ? url : `http://${url}`;
    const urlObj = new URL(urlWithProtocol);
    return urlObj.hostname || "";
  } catch {
    // Fallback parsing
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/?#]+)/);
    return match ? match[1] : "";
  }
}

/**
 * Check if domain is a zero-day domain (registered very recently)
 * Returns true if domain appears to be newly registered
 */
function checkZeroDayDomain(url: string): { flagged: boolean; reason: string } {
  const domain = extractDomain(url);
  
  // Common characteristics of zero-day domains:
  // 1. Random string patterns
  // 2. Excessive hyphens
  // 3. Unusual TLD combinations
  
  const hyphenCount = (domain.match(/-/g) || []).length;
  const parts = domain.split(".");
  const domainName = parts.slice(0, -1).join(".");
  
  // Flag if domain has excessive hyphens (>2) - often used to disguise domains
  if (hyphenCount > 2) {
    return {
      flagged: true,
      reason: `Excessive hyphens in domain (${hyphenCount}), typical of zero-day/newly registered domains`,
    };
  }
  
  // Check for random character sequences (no vowels, all consonants, etc.)
  const hasOnlyConsonants = /^[bcdfghjklmnpqrstvwxyz\-]+$/.test(domainName);
  if (domainName.length > 5 && hasOnlyConsonants) {
    return {
      flagged: true,
      reason: "Domain name pattern suggests zero-day/randomly generated domain (mostly consonants)",
    };
  }
  
  // Check for rare/suspicious TLDs
  const tld = parts[parts.length - 1].toLowerCase();
  const rareTLDs = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "download", "review"];
  if (rareTLDs.includes(tld)) {
    return {
      flagged: true,
      reason: `Rare/suspicious TLD (.${tld}), commonly used for phishing domains`,
    };
  }
  
  return { flagged: false, reason: "" };
}

/**
 * Check if URL uses HTTPS protocol (secure connection)
 * Missing HTTPS is a red flag for phishing
 */
function checkHTTPSUsage(url: string): { flagged: boolean; reason: string } {
  const urlLower = url.toLowerCase();
  
  if (!urlLower.startsWith("https://")) {
    if (urlLower.startsWith("http://")) {
      return {
        flagged: true,
        reason: "URL uses HTTP instead of HTTPS (no encryption)",
      };
    }
    
    // If no protocol specified, also flag it
    return {
      flagged: true,
      reason: "URL lacks HTTPS protocol (no secure connection)",
    };
  }
  
  return { flagged: false, reason: "" };
}

/**
 * Check for @ symbol in URL (credential injection attack)
 * @ symbol can hide the actual domain from users
 * e.g., https://paypal.com@attacker.com redirects to attacker.com
 */
function checkAtSymbolInURL(url: string): { flagged: boolean; reason: string } {
  if (url.includes("@")) {
    // Extract what comes before and after @
    const parts = url.split("@");
    const beforeAt = parts[0];
    const afterAt = parts[1];
    
    return {
      flagged: true,
      reason: `URL contains @ symbol (credential injection risk). Text before @: "${beforeAt}", actual domain: "${afterAt}"`,
    };
  }
  
  return { flagged: false, reason: "" };
}

/**
 * Check for favicon mismatch
 * Compares expected favicon of legitimate domain with actual link
 * This is a simplified check - in production, would need actual favicon fetching
 */
function checkFaviconMismatch(url: string, expectedFaviconBrand?: string): { flagged: boolean; reason: string } {
  const domain = extractDomain(url).toLowerCase();
  
  // Detect if link claims to be from a major brand but doesn't match
  for (const [brand, faviconUrls] of Object.entries(BRAND_FAVICONS)) {
    const isBrandDomain = domain.includes(brand);
    
    // Check if URL text contains brand name but domain doesn't
    // (This is a heuristic - actual implementation would fetch favicons)
    if (!isBrandDomain && expectedFaviconBrand) {
      if (expectedFaviconBrand.toLowerCase().includes(brand)) {
        return {
          flagged: true,
          reason: `Favicon mismatch: Link text suggests "${brand}" but domain is "${domain}"`,
        };
      }
    }
  }
  
  return { flagged: false, reason: "" };
}

/**
 * Main heuristic function for link analysis
 * Combines all URL-based scam detection methods
 */
export function analyzeLink(link: Link): HeuristicResult {
  const findings: string[] = [];

  const lengthCheck = checkExcessiveLength(link.href);
  if (lengthCheck.flagged) {
    findings.push(`⚠️ ${lengthCheck.reason}`);
  }

  const insufficientCheck = checkInsufficientLength(link.href);
  if (insufficientCheck.flagged) {
    findings.push(`⚠️ ${insufficientCheck.reason}`);
  }

  const ipCheck = checkIPAddressLink(link.href);
  if (ipCheck.flagged) {
    findings.push(`⚠️ ${ipCheck.reason}`);
  }

  const typosquatCheck = checkTyposquattingAndHomoglyphs(link.href);
  if (typosquatCheck.flagged) {
    for (const reason of typosquatCheck.reasons) {
      findings.push(`⚠️ ${reason}`);
    }
  }

  const zeroDayCheck = checkZeroDayDomain(link.href);
  if (zeroDayCheck.flagged) {
    findings.push(`⚠️ ${zeroDayCheck.reason}`);
  }

  const httpsCheck = checkHTTPSUsage(link.href);
  if (httpsCheck.flagged) {
    findings.push(`⚠️ ${httpsCheck.reason}`);
  }

  const atSymbolCheck = checkAtSymbolInURL(link.href);
  if (atSymbolCheck.flagged) {
    findings.push(`⚠️ ${atSymbolCheck.reason}`);
  }

  const faviconCheck = checkFaviconMismatch(link.href, link.text);
  if (faviconCheck.flagged) {
    findings.push(`⚠️ ${faviconCheck.reason}`);
  }

  const categoryScores = [
    categoryScore(lengthCheck.flagged),
    categoryScore(insufficientCheck.flagged),
    categoryScore(ipCheck.flagged),
    typosquatCategoryScore(typosquatCheck.flagged, typosquatCheck.reasons.length),
    categoryScore(zeroDayCheck.flagged),
    categoryScore(httpsCheck.flagged),
    categoryScore(atSymbolCheck.flagged),
    categoryScore(faviconCheck.flagged),
  ];

  const score = roundScore(
    categoryScores.reduce((sum, value) => sum + value, 0) / URL_HEURISTIC_CATEGORY_COUNT
  );
  const verdict = verdictFromScore(score);

  return {
    score,
    verdict,
    explanation: `URL analysis score ${score}/10 across ${URL_HEURISTIC_CATEGORY_COUNT} checks (${findings.length} findings).`,
    findings,
    source: "url",
  };
}

/**
 * Analyze multiple links from a page
 */
export function analyzeLinks(links: Link[]): HeuristicResult {
  if (links.length === 0) {
    return {
      score: MIN_SCORE,
      verdict: "Safe",
      explanation: "No URLs to analyze",
      findings: [],
      source: "url",
    };
  }

  const results = links.map(analyzeLink);
  const score = roundScore(
    results.reduce((sum, result) => sum + result.score, 0) / results.length
  );
  const verdict = verdictFromScore(score);
  const suspiciousCount = results.filter((result) => result.verdict !== "Safe").length;

  const findings = results
    .filter((result) => result.findings.length > 0)
    .map(
      (result, index) =>
        `Link ${index + 1} (${links[index].text || links[index].href}): ${result.findings.join("; ")}`
    );

  return {
    score,
    verdict,
    explanation: `Analyzed ${links.length} URLs with average score ${score}/10. ${suspiciousCount} URL(s) flagged.`,
    findings,
    source: "url",
  };
}

/**
 * Analyze the page URL plus all extracted links.
 */
export function analyzePageUrls(pageData: ExtractedPageData): HeuristicResult {
  const urlsToAnalyze: Link[] = [];

  if (pageData.url.length > 0) {
    urlsToAnalyze.push({
      text: pageData.title,
      href: pageData.url,
    });
  }

  urlsToAnalyze.push(...pageData.links);
  return analyzeLinks(urlsToAnalyze);
}
