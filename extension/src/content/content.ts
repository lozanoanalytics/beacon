// CONTENT SCRIPT
//file runs auto on every web page user visits
//(1) extracts structured data (URL, title, text, links, etc)
//(2) listens for messages from popup and respond with the data
//(3) logs extracted data to the page console for debugging

// Local type declarations
// Content scripts cannot use ES module imports,
// so we redeclare the shapes here. Keep in sync
// with extension/src/types/heuristics.ts.

interface Link {
    text: string;
    href: string;
}

interface ExtractedPageData {
    url: string;
    title: string;
    metaDescription: string;
    textContent: string;
    links: Link[];
}

function extractPageData(): ExtractedPageData {
    //get current page URL
    const url = window.location.href;
    //title of page
    const title: string = document.title;
    //meta description used by sites to summarize content, useful for detection and often contains scammy language
    const metaDescription: string =
        document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
    // Try to find main content area using common tags, fallback to body text
    const mainElement: HTMLElement | null = 
        document.querySelector("main") ||
        document.querySelector("article") ||
        document.querySelector<HTMLElement>('[role ="main"]');
    //get visible text content from page, prioritizing main/article/role=main if available
    const rawText: string = mainElement
        ? mainElement.innerText
        : document.body.innerText || "";
    //limit text content to 5000 chars
    const textContent: string = rawText.trim().substring(0, 5000);
    //extract links from page (visible text and href)
    //limit to first 100 links with http/https protocols to prevent large payloads
    const linkElements = document.querySelectorAll("a[href]");
    const links: Link[] = Array.from(linkElements)
        .map((element) => {
            const text = (element.textContent || "").trim();
            const href = element.getAttribute("href") || "";
            return { text: text, href: href };
        })
        .filter((link) => {
            const isValidProtocol = link.href.startsWith("http://") || link.href.startsWith("https://");
            return link.text.length > 0 && isValidProtocol;
        })
        .slice(0, 100);
    
    return {
        url: url,
        title: title,
        metaDescription: metaDescription,
        textContent: textContent,
        links: links
    };
}

// Helper: print extracted page data to the page console in a readable way
// 'label' lets us know what triggered the log (page load vs popup scan)

function logExtractedData(label: string, data: ExtractedPageData): void {
    console.group(`[Beacon] Extracted page data (${label})`);
    console.log("URL:", data.url);
    console.log("Title:", data.title);
    console.log("Meta description:", data.metaDescription);
    console.log("Text content length:", data.textContent.length, "chars");
    console.log("Text content preview:", data.textContent.substring(0, 200) + "...");
    console.log("Links found:", data.links.length);
    console.table(data.links.slice(0, 10)); //show first 10 links as a table
    console.groupEnd();
}

// Run extraction once when the page loads, so we can verify in DevTools
// that Beacon is seeing the page correctly without needing to open the popup.
const initialData = extractPageData();
logExtractedData("page load", initialData);

// Listen for messages from the popup script
// chrome.runtime.onMessage is Chrome's messaging system.
// When the popup sends a message, this listener receives it

//listener receives:
//message = data sent by popup
//sender = info about who sent message
//sendResponse = function to send a reply back to the popup

chrome.runtime.onMessage.addListener(
   (
     message: { action: string },
     sender: chrome.runtime.MessageSender,
     sendResponse: (response:ExtractedPageData) => void
   ) => {
     if (message.action === "scanPage") {
        const pageData = extractPageData();
        logExtractedData("popup scan", pageData);
        sendResponse(pageData);
     }
     return true;
 } 
);

