//(1) typescript interfaces for structured data
import { analyzePage } from "../heuristics/combinedHeuristics.js";
import type { ExtractedPageData } from "../types/heuristics.js";

interface WebsiteInfo {
  domainAge: string;
  country: string;
  registrar: string;
  popularity: string;
}

interface AnalysisResult {
  score: number;
  verdict: string;
  explanation: string;
  websiteInfo: WebsiteInfo;
}

//(2) grab references to HTML elements - DO THIS FIRST
const scanButton = document.getElementById("scan-button") as HTMLButtonElement;
const resultsDiv = document.getElementById("results") as HTMLDivElement;
const scoreCircle = document.getElementById("score-circle") as HTMLDivElement;
const scoreNumber = document.getElementById("score-number") as HTMLSpanElement;
const verdictText = document.getElementById("verdict-text") as HTMLParagraphElement;
const verdictUrl = document.getElementById("verdict-url") as HTMLParagraphElement;
const explanationText = document.getElementById("explanation-text") as HTMLParagraphElement;
const errorDiv = document.getElementById("error") as HTMLDivElement;
const errorMessage = document.getElementById("error-message") as HTMLParagraphElement;

//Website info elements
const infoAge = document.getElementById("info-age") as HTMLSpanElement;
const infoCountry = document.getElementById("info-country") as HTMLSpanElement;
const infoRegistrar = document.getElementById("info-registrar") as HTMLSpanElement;
const infoPopularity = document.getElementById("info-popularity") as HTMLSpanElement;

//(1.5) Toggle Button Setup - wrapped in DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  const scanToggle = document.getElementById('scan-toggle') as HTMLInputElement;
  const llmToggle = document.getElementById('llm-toggle') as HTMLInputElement;
  const scanKnobSwitch = document.querySelectorAll('.knob-switch')[0] as HTMLElement;
  const llmKnobSwitch = document.querySelectorAll('.knob-switch')[1] as HTMLElement;

  // Verify elements exist
  if (!scanToggle) {
    console.error('[Beacon] Scan toggle checkbox not found');
    return;
  } else {
    console.log('[Beacon] Scan toggle found, initializing...');
  }

  if (!llmToggle) {
    console.error('[Beacon] LLM toggle checkbox not found');
    return;
  } else {
    console.log('[Beacon] LLM toggle found, initializing...');
  }

  // Make scan knob clickable
  if (scanKnobSwitch) {
    scanKnobSwitch.addEventListener('click', () => {
      scanToggle.checked = !scanToggle.checked;
      scanToggle.dispatchEvent(new Event('change', { bubbles: true }));
    });
  }

  // Make LLM knob clickable
  if (llmKnobSwitch) {
    llmKnobSwitch.addEventListener('click', () => {
      llmToggle.checked = !llmToggle.checked;
      llmToggle.dispatchEvent(new Event('change', { bubbles: true }));
    });
  }

  // Load scan toggle state from Chrome storage
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['scanningEnabled'], (result) => {
      const isEnabled = result.scanningEnabled !== false;
      scanToggle.checked = isEnabled;
      updateScanButtonState(isEnabled);
      console.log('[Beacon] Scan toggle initialized:', isEnabled);
    });

    // Load LLM toggle state from Chrome storage
    chrome.storage.local.get(['llmEnabled'], (result) => {
      const isEnabled = result.llmEnabled !== false;
      llmToggle.checked = isEnabled;
      console.log('[Beacon] LLM toggle initialized:', isEnabled);
    });
  } else {
    console.warn('[Beacon] chrome.storage not available, using default state');
    scanToggle.checked = true;
    llmToggle.checked = true;
    updateScanButtonState(true);
  }

  // Listen for scan toggle changes
  scanToggle.addEventListener('change', (event) => {
    const isEnabled = (event.target as HTMLInputElement).checked;
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ scanningEnabled: isEnabled });
    }
    updateScanButtonState(isEnabled);
    console.log('[Beacon] Scan toggle changed:', isEnabled);
  });

  // Listen for LLM toggle changes
  llmToggle.addEventListener('change', (event) => {
    const isEnabled = (event.target as HTMLInputElement).checked;
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ llmEnabled: isEnabled });
    }
    console.log('[Beacon] LLM toggle changed:', isEnabled);
  });
});

// Update the scan button's disabled state based on toggle
function updateScanButtonState(isEnabled: boolean): void {
  scanButton.disabled = !isEnabled;
  if (!isEnabled) {
    scanButton.textContent = 'Scanning disabled';
  } else {
    scanButton.textContent = 'Check this page';
  }
}

//(2.5) helper to extract domain from URL

function getDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return url;
  }
}

function buildWebsiteInfo(url: string): WebsiteInfo {
  const domain = getDomain(url);
  return {
    domainAge: "Not available",
    country: "Not available",
    registrar: "Not available",
    popularity: domain ? `Heuristic scan for ${domain}` : "Not available",
  };
}

function runHeuristicAnalysis(pageData: ExtractedPageData): AnalysisResult {
  const result = analyzePage(pageData);

  return {
    score: result.score,
    verdict: result.verdict,
    explanation: result.explanation,
    websiteInfo: buildWebsiteInfo(pageData.url),
  };
}

//(4) Determine verdict level from score
// Returns "safe", "uncertain", or "scam" based on the score
//Using this to pick the right CSS color classes.
//0-3 = safe, 4-6 = uncertain, 7-10 = scam

function getVerdictLevel(score: number): string {
    if (score <= 3) {
        return "safe";
    } else if (score <= 6) {
        return "uncertain";
    } else {
        return "scam";
    }
}

//(5) Show Error msg

function showError(message: string): void {
    resultsDiv.classList.add("hidden");
    errorDiv.classList.remove("hidden");
    errorMessage.textContent = message;
}

//(6) Display Scan results
//takes an AnalysisResult and a URL, then updates all the
//HTML elements to show the score, verdict, and explanation with  correct colors.

function showResults(result: AnalysisResult, url: string): void {
    errorDiv.classList.add("hidden");
    resultsDiv.classList.remove("hidden");

    scoreNumber.textContent = Math.round(result.score).toString(); // Update score number inside circle
    verdictText.textContent = result.verdict; // Update verdict text and URL
    const shortUrl: string = url.length > 50 //shortens URL 
    ? url.substring(0, 50) + "..."
    : url;
    verdictUrl.textContent = shortUrl;

    explanationText.textContent = result.explanation; // Update explanation text

    //update website info section
    infoAge.textContent = result.websiteInfo.domainAge;
    infoCountry.textContent = result.websiteInfo.country;
    infoRegistrar.textContent = result.websiteInfo.registrar;
    infoPopularity.textContent = result.websiteInfo.popularity;

    const level: string = getVerdictLevel(result.score);
    
    scoreCircle.classList.remove("score-safe", "score-uncertain", "score-scam"); // Remove old classes
    scoreCircle.classList.add("score-" + level);

    verdictText.classList.remove("verdict-safe", "verdict-uncertain", "verdict-scam"); // Remove old classes
    verdictText.classList.add("verdict-" + level);
}

//(7) Handle Button Click

scanButton.addEventListener("click", () => {
    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    chrome.tabs.query(
        { active: true, currentWindow: true },
        (tabs: chrome.tabs.Tab[]) => {
            
            const tab = tabs[0];
            if (!tab || tab.id === undefined) {
                showError("Could not find the current tab. Please try again.");
                scanButton.disabled = false;
                scanButton.textContent = "Check this page";
                return;
            }

            const tabId: number = tab.id;

            chrome.tabs.sendMessage(
                tab.id,
                { action: "scanPage" },
                (response: ExtractedPageData) => {
                    
                    if (chrome.runtime.lastError) {
                        showError(
                            "Could not scan this page. Try refreshing first."
                        );
                    } else if (response) {
                        const result: AnalysisResult = runHeuristicAnalysis(response);
                        showResults(result, response.url);
                    } else {
                        showError("No response from the page.");
                    }
                    
                    scanButton.disabled = false;
                    scanButton.textContent = "Check this page";
                }
            );
        }
    );
});