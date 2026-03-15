"""Site Crawler - Deep crawls websites to discover and fetch all pages and sub-pages."""

import re
from urllib.parse import urlparse, urljoin, urldefrag

import requests
from bs4 import BeautifulSoup


class SiteCrawler:
    """Crawls a website to discover and fetch all internal pages.

    Prioritizes compliance-relevant pages (contact, grievance, about, legal,
    privacy, terms) and crawls all discoverable internal links up to a
    configurable depth and page limit.
    """

    # Pages most likely to contain compliance-relevant information
    PRIORITY_PATHS = [
        "/contact", "/contact-us", "/contactus",
        "/grievance", "/grievance-redressal", "/grievance-officer",
        "/grievances", "/investor-grievance",
        "/about", "/about-us", "/aboutus", "/about-company",
        "/legal", "/legal-information",
        "/privacy", "/privacy-policy", "/privacypolicy",
        "/terms", "/terms-of-service", "/terms-and-conditions", "/tos",
        "/disclaimer", "/disclosures", "/disclosure",
        "/compliance", "/regulatory", "/regulation",
        "/investor-charter", "/investor-relations",
        "/refund", "/refund-policy", "/cancellation-policy",
        "/kyc", "/kyc-policy",
        "/data-protection", "/data-privacy",
        "/cookie-policy", "/cookies",
        "/security", "/security-policy",
        "/help", "/support", "/faq", "/faqs",
        "/careers", "/team",
        "/sitemap", "/sitemap.xml",
    ]

    # Keywords in link text or href that indicate compliance-relevant pages
    PRIORITY_KEYWORDS = [
        "grievance", "grievances", "complaint", "complaints",
        "nodal officer", "compliance officer", "data protection",
        "privacy", "legal", "terms", "disclaimer",
        "contact", "about", "support", "help",
        "investor", "regulatory", "disclosure",
        "refund", "cancellation", "kyc",
        "cookie", "security", "policy", "policies",
    ]

    # App store URL patterns
    PLAY_STORE_PATTERN = re.compile(
        r"https?://play\.google\.com/store/apps/details\?[^\s\"'<>]*",
        re.IGNORECASE,
    )
    APP_STORE_PATTERN = re.compile(
        r"https?://(?:apps\.apple\.com|itunes\.apple\.com)/[^\s\"'<>]*",
        re.IGNORECASE,
    )

    def __init__(self, url: str, timeout: int = 15, max_pages: int = 50,
                 max_depth: int = 3):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.base_url = url
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.parsed_base = urlparse(url)
        self.base_domain = self.parsed_base.hostname
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "FinTechThreatAgent/1.0 (Security Audit)",
        })

        # State
        self.visited_urls = set()
        self.discovered_urls = set()
        self.pages = {}  # url -> {html, soup, text, status_code}
        self.app_store_links = {"play_store": set(), "app_store": set()}
        self.crawl_errors = []

    def crawl(self) -> dict:
        """Crawl the website and return aggregated results.

        Returns dict with:
            - pages: dict of url -> page data
            - aggregated_text: all page text combined
            - aggregated_html: all page HTML combined
            - aggregated_soup: BeautifulSoup of combined HTML
            - app_store_links: detected Play Store / App Store URLs
            - crawl_stats: crawl metrics
        """
        # Phase 1: Fetch homepage and discover links
        self._fetch_page(self.base_url, depth=0)

        # Phase 2: Generate priority URLs from known paths
        self._add_priority_urls()

        # Phase 3: Crawl discovered URLs (BFS by priority)
        self._crawl_discovered()

        # Phase 4: Aggregate results
        return self._build_results()

    def _fetch_page(self, url: str, depth: int) -> bool:
        """Fetch a single page, extract links, and store content."""
        # Normalize URL
        url = self._normalize_url(url)
        if not url or url in self.visited_urls:
            return False
        if len(self.visited_urls) >= self.max_pages:
            return False
        if not self._is_same_domain(url):
            return False

        self.visited_urls.add(url)

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
            )

            # Only process HTML content
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return False

            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
            page_text = soup.get_text(" ", strip=True)

            self.pages[url] = {
                "html": html,
                "soup": soup,
                "text": page_text,
                "status_code": resp.status_code,
                "title": soup.title.string.strip() if soup.title and soup.title.string else "",
            }

            # Extract links for further crawling
            if depth < self.max_depth:
                self._extract_links(soup, url, depth)

            # Detect app store links in HTML
            self._detect_app_store_links(html)

            return True

        except requests.RequestException as e:
            self.crawl_errors.append({"url": url, "error": str(e)})
            return False

    def _extract_links(self, soup: BeautifulSoup, page_url: str, current_depth: int):
        """Extract all internal links from a page."""
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            # Resolve relative URLs
            full_url = urljoin(page_url, href)
            full_url = self._normalize_url(full_url)

            if not full_url or full_url in self.visited_urls:
                continue

            if self._is_same_domain(full_url):
                link_text = a_tag.get_text(" ", strip=True).lower()
                is_priority = self._is_priority_link(full_url, link_text)
                self.discovered_urls.add((full_url, current_depth + 1, is_priority))

            # Check for app store links in external hrefs
            self._check_app_store_url(full_url)

    def _add_priority_urls(self):
        """Add known compliance-relevant paths to the crawl queue."""
        base = f"{self.parsed_base.scheme}://{self.parsed_base.hostname}"
        for path in self.PRIORITY_PATHS:
            url = base + path
            if url not in self.visited_urls:
                self.discovered_urls.add((url, 1, True))

    def _crawl_discovered(self):
        """Crawl all discovered URLs, prioritizing compliance-relevant pages."""
        # Sort: priority pages first, then by depth
        queue = sorted(self.discovered_urls, key=lambda x: (not x[2], x[1]))

        for url, depth, _is_priority in queue:
            if len(self.visited_urls) >= self.max_pages:
                break
            if url in self.visited_urls:
                continue
            self._fetch_page(url, depth)

    def _normalize_url(self, url: str) -> str | None:
        """Normalize URL: remove fragments, trailing slashes, etc."""
        if not url:
            return None
        url, _ = urldefrag(url)
        # Remove trailing slash for consistency (except root)
        parsed = urlparse(url)
        if parsed.path and parsed.path != "/" and parsed.path.endswith("/"):
            url = url.rstrip("/")
        # Skip non-http schemes
        if not url.startswith(("http://", "https://")):
            return None
        # Skip file extensions that aren't pages
        path_lower = parsed.path.lower()
        skip_extensions = (
            ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
            ".zip", ".rar", ".tar", ".gz", ".mp4", ".mp3", ".avi",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        )
        if any(path_lower.endswith(ext) for ext in skip_extensions):
            return None
        return url

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain (including subdomains)."""
        parsed = urlparse(url)
        if not parsed.hostname:
            return False
        # Allow same domain and subdomains
        return (
            parsed.hostname == self.base_domain
            or parsed.hostname.endswith("." + self.base_domain)
        )

    def _is_priority_link(self, url: str, link_text: str) -> bool:
        """Check if a link is likely compliance-relevant."""
        url_lower = url.lower()
        combined = url_lower + " " + link_text
        return any(kw in combined for kw in self.PRIORITY_KEYWORDS)

    def _detect_app_store_links(self, html: str):
        """Detect Play Store and App Store links in page HTML."""
        for match in self.PLAY_STORE_PATTERN.finditer(html):
            self.app_store_links["play_store"].add(match.group(0))
        for match in self.APP_STORE_PATTERN.finditer(html):
            self.app_store_links["app_store"].add(match.group(0))

    def _check_app_store_url(self, url: str):
        """Check if a URL is an app store link."""
        if self.PLAY_STORE_PATTERN.match(url):
            self.app_store_links["play_store"].add(url)
        elif self.APP_STORE_PATTERN.match(url):
            self.app_store_links["app_store"].add(url)

    def _build_results(self) -> dict:
        """Build aggregated crawl results."""
        # Combine all page text and HTML
        all_texts = []
        all_htmls = []
        all_links = []

        for url, page_data in self.pages.items():
            all_texts.append(page_data["text"])
            all_htmls.append(page_data["html"])
            # Extract links from each page's soup
            for a_tag in page_data["soup"].find_all("a", href=True):
                href = a_tag.get("href", "").lower()
                text = a_tag.get_text(" ", strip=True).lower()
                all_links.append((href, text))

        aggregated_text = "\n\n".join(all_texts)
        aggregated_html = "\n\n".join(all_htmls)
        aggregated_soup = BeautifulSoup(
            "<html><body>" + aggregated_html + "</body></html>",
            "html.parser",
        )

        # Deduplicate app store links
        app_links = {
            "play_store": sorted(self.app_store_links["play_store"]),
            "app_store": sorted(self.app_store_links["app_store"]),
        }

        pages_fetched = len(self.pages)
        pages_with_content = [
            url for url, data in self.pages.items()
            if data["status_code"] == 200 and len(data["text"]) > 100
        ]

        return {
            "pages": self.pages,
            "pages_fetched": pages_fetched,
            "pages_with_content": len(pages_with_content),
            "urls_discovered": len(self.discovered_urls),
            "aggregated_text": aggregated_text,
            "aggregated_html": aggregated_html,
            "aggregated_soup": aggregated_soup,
            "aggregated_links": all_links,
            "app_store_links": app_links,
            "crawl_errors": self.crawl_errors,
            "crawl_stats": {
                "pages_fetched": pages_fetched,
                "pages_with_content": len(pages_with_content),
                "urls_discovered": len(self.discovered_urls) + len(self.visited_urls),
                "errors": len(self.crawl_errors),
                "pages_list": [
                    {"url": url, "title": data["title"], "status": data["status_code"]}
                    for url, data in self.pages.items()
                ],
            },
        }
