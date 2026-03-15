"""App Store Scanner - Scrapes metadata from Google Play Store and Apple App Store listings."""

import re
import json
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup


class AppStoreScanner:
    """Scrapes and analyzes app metadata from Play Store and App Store pages.

    Google Play Store pages are heavily JS-rendered, so this scanner extracts
    data from the embedded AF_initDataCallback scripts and meta tags rather
    than relying on the visible DOM.
    """

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    def __init__(self, url: str, timeout: int = 20):
        self.url = url
        self.timeout = timeout

    def scan(self) -> dict:
        """Scrape the app store page and return structured metadata."""
        parsed = urlparse(self.url)
        hostname = parsed.hostname or ""

        if hostname == "play.google.com":
            return self._scan_play_store()
        elif hostname in ("apps.apple.com", "itunes.apple.com"):
            return self._scan_app_store()
        return {"error": "Not a recognized app store URL", "store": "unknown"}

    # ── Google Play Store ────────────────────────────────────────────────

    def _scan_play_store(self) -> dict:
        """Scrape Google Play Store listing page.

        Extracts data from:
        1. <title> and <meta> tags (always present in raw HTML)
        2. AF_initDataCallback scripts (contain structured app data)
        3. JSON-LD structured data (when available)
        """
        app_id = self._extract_play_store_id()
        result = {
            "store": "Google Play Store",
            "url": self.url,
            "app_id": app_id,
            "app_name": "",
            "developer": "",
            "rating": None,
            "rating_count": None,
            "installs": "",
            "last_updated": "",
            "requires_android": "",
            "content_rating": "",
            "description": "",
            "permissions_summary": [],
            "data_safety": [],
            "website_url": "",
            "privacy_policy_url": "",
            "category": "",
            "contains_ads": False,
            "in_app_purchases": False,
            "errors": [],
        }

        # Add hl=en to ensure English content
        url = self.url
        if "hl=" not in url:
            separator = "&" if "?" in url else "?"
            url = url + separator + "hl=en"

        try:
            resp = requests.get(url, headers=self.HEADERS, timeout=self.timeout)
            if resp.status_code != 200:
                result["errors"].append(f"HTTP {resp.status_code}")
                return result

            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            # Strategy 1: Extract from <title> and <meta> tags (most reliable)
            self._extract_from_meta(soup, result)

            # Strategy 2: Extract from AF_initDataCallback embedded data
            self._extract_from_af_data(html, result)

            # Strategy 3: Extract from JSON-LD structured data
            self._extract_from_jsonld(soup, result)

            # Strategy 4: Extract from visible DOM elements (less reliable)
            self._extract_from_dom(soup, html, result)

        except requests.RequestException as e:
            result["errors"].append(str(e))

        return result

    def _extract_play_store_id(self) -> str:
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return params.get("id", [""])[0]

    def _extract_from_meta(self, soup, result):
        """Extract data from meta tags — always present in raw Play Store HTML."""
        # Title: "App Name - Apps on Google Play"
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
            # Remove " - Apps on Google Play" suffix
            for suffix in [" - Apps on Google Play", " - Google Play のアプリ",
                           " – Apps on Google Play", " - Apps bei Google Play"]:
                if title.endswith(suffix):
                    title = title[:-len(suffix)]
                    break
            if title and not result["app_name"]:
                result["app_name"] = title

        # Description from meta
        desc_meta = soup.find("meta", attrs={"name": "description"})
        if desc_meta and desc_meta.get("content"):
            result["description"] = desc_meta["content"][:500]

        # OG tags
        og_title = soup.find("meta", attrs={"property": "og:title"})
        if og_title and og_title.get("content") and not result["app_name"]:
            result["app_name"] = og_title["content"].split(" - ")[0].strip()

        og_desc = soup.find("meta", attrs={"property": "og:description"})
        if og_desc and og_desc.get("content") and not result["description"]:
            result["description"] = og_desc["content"][:500]

    def _extract_from_af_data(self, html, result):
        """Extract structured data from AF_initDataCallback scripts.

        Play Store embeds app metadata in AF_initDataCallback JavaScript
        calls within the HTML. These contain nested arrays with all app data.
        """
        # Find all AF_initDataCallback blocks
        af_pattern = re.compile(
            r"AF_initDataCallback\(\s*\{[^}]*data:\s*(.*?)\}\s*\)\s*;",
            re.DOTALL
        )

        for match in af_pattern.finditer(html):
            try:
                data_str = match.group(1).strip()
                # Try to find the developer info, website, and privacy policy
                self._parse_af_block(data_str, result)
            except Exception:
                continue

        # Also try to find URLs directly from script content
        self._extract_urls_from_scripts(html, result)

    def _parse_af_block(self, data_str, result):
        """Parse a single AF_initDataCallback data block for useful info."""
        # Developer website - look for patterns like ["Visit website","url"]
        website_patterns = [
            re.compile(r'"(https?://(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}[^"]*)"[^"]*"[Vv]isit\s+[Ww]ebsite"'),
            re.compile(r'"[Vv]isit\s+[Ww]ebsite"[^"]*"(https?://(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}[^"]*)"'),
        ]
        for pat in website_patterns:
            m = pat.search(data_str)
            if m and not result["website_url"]:
                url = m.group(1)
                if "google.com" not in url and "apple.com" not in url:
                    result["website_url"] = url

        # Privacy policy URL
        privacy_patterns = [
            re.compile(r'"(https?://[^"]+)"[^"]*"[Pp]rivacy\s+[Pp]olicy"'),
            re.compile(r'"[Pp]rivacy\s+[Pp]olicy"[^"]*"(https?://[^"]+)"'),
        ]
        for pat in privacy_patterns:
            m = pat.search(data_str)
            if m and not result["privacy_policy_url"]:
                result["privacy_policy_url"] = m.group(1)

        # Developer name — often near /store/apps/dev?id=
        dev_pattern = re.compile(
            r'/store/apps/dev\?id=[^"]*"[,\]\s]*"([^"]{2,50})"'
        )
        m = dev_pattern.search(data_str)
        if m and not result["developer"]:
            result["developer"] = m.group(1)

        # Rating — look for numeric rating value near review context
        rating_pattern = re.compile(r'\[(\d\.\d{1,2})\]')
        for m in rating_pattern.finditer(data_str):
            try:
                val = float(m.group(1))
                if 1.0 <= val <= 5.0 and result["rating"] is None:
                    result["rating"] = round(val, 1)
                    break
            except ValueError:
                pass

        # Installs
        install_patterns = [
            re.compile(r'"(\d[\d,]*\d\+?)\s*(?:downloads|installs)"', re.IGNORECASE),
            re.compile(r'"(\d+[KMB+]+\+?)\s*(?:downloads|installs)"', re.IGNORECASE),
            re.compile(r'"(\d[\d,]+\+)"'),
        ]
        for pat in install_patterns:
            m = pat.search(data_str)
            if m and not result["installs"]:
                result["installs"] = m.group(1)

        # Data safety keywords
        safety_keywords = [
            "shared with third parties", "data collected",
            "encrypted in transit", "can.{0,5}deleted",
            "not encrypted", "cannot.{0,5}deleted",
            "no data shared", "no data collected",
        ]
        for kw in safety_keywords:
            if re.search(kw, data_str, re.IGNORECASE):
                clean_kw = re.sub(r'\.{.*?}', ' ', kw).replace('.', ' ').strip()
                if clean_kw not in result["data_safety"]:
                    result["data_safety"].append(clean_kw)

    def _extract_urls_from_scripts(self, html, result):
        """Extract developer website and privacy policy URLs from script tags."""
        # Look for website URLs near "Visit website" text anywhere in HTML
        visit_web_patterns = [
            re.compile(
                r'(?:href|url)["\s:=]*["\']?(https?://(?!play\.google\.com|accounts\.google)'
                r'[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}[^"\'<>\s]*)["\']?'
                r'[^>]{0,200}?(?:visit\s*website|developer\s*website|web)',
                re.IGNORECASE
            ),
            re.compile(
                r'(?:visit\s*website|developer\s*website|web)[^"]{0,200}?'
                r'["\s:=]*["\']?(https?://(?!play\.google\.com|accounts\.google)'
                r'[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}[^"\'<>\s]*)',
                re.IGNORECASE
            ),
        ]
        for pat in visit_web_patterns:
            m = pat.search(html)
            if m and not result["website_url"]:
                url = m.group(1).rstrip('",')
                if len(url) < 200:
                    result["website_url"] = url

        # Look for privacy policy URLs
        privacy_url_patterns = [
            re.compile(
                r'(https?://[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-/]*privacy[a-zA-Z0-9.\-/]*)',
                re.IGNORECASE
            ),
        ]
        for pat in privacy_url_patterns:
            for m in pat.finditer(html):
                url = m.group(1)
                if "google.com" not in url and "apple.com" not in url:
                    if not result["privacy_policy_url"]:
                        result["privacy_policy_url"] = url
                    break

        # Try extracting developer from meta or title
        if not result["developer"]:
            # Check for developer links in the DOM
            dev_link_pattern = re.compile(
                r'/store/apps/dev(?:eloper)?\?id=[^"]*"[^>]*>([^<]+)<',
                re.IGNORECASE,
            )
            m = dev_link_pattern.search(html)
            if m:
                result["developer"] = m.group(1).strip()

    def _extract_from_jsonld(self, soup, result):
        """Extract from JSON-LD structured data (when available)."""
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string or "")
                if not isinstance(data, dict):
                    continue
                if data.get("@type") == "SoftwareApplication":
                    result["app_name"] = result["app_name"] or data.get("name", "")
                    result["category"] = result["category"] or data.get(
                        "applicationCategory", ""
                    )
                    result["requires_android"] = result["requires_android"] or data.get(
                        "operatingSystem", ""
                    )
                    agg = data.get("aggregateRating", {})
                    if agg:
                        if result["rating"] is None:
                            try:
                                result["rating"] = round(float(agg.get("ratingValue", 0)), 1)
                            except (ValueError, TypeError):
                                pass
                        if result["rating_count"] is None:
                            try:
                                result["rating_count"] = int(agg.get("ratingCount", 0))
                            except (ValueError, TypeError):
                                pass
            except (json.JSONDecodeError, TypeError):
                pass

    def _extract_from_dom(self, soup, html, result):
        """Extract from visible DOM elements (fallback)."""
        # App name from h1
        if not result["app_name"]:
            h1 = soup.find("h1")
            if h1:
                result["app_name"] = h1.get_text(strip=True)

        # Developer from dev links
        if not result["developer"]:
            dev_links = soup.find_all("a", href=re.compile(r"/store/apps/dev"))
            if dev_links:
                result["developer"] = dev_links[0].get_text(strip=True)

        # Category from category links
        if not result["category"]:
            cat_el = soup.find("a", href=re.compile(r"/store/apps/category/"))
            if cat_el:
                result["category"] = cat_el.get_text(strip=True)

        # Contains ads / in-app purchases from page text
        page_text = soup.get_text(" ", strip=True).lower()
        if "contains ads" in page_text:
            result["contains_ads"] = True
        if "in-app purchases" in page_text:
            result["in_app_purchases"] = True

        # Data types collected (from data safety section)
        data_types = [
            "location", "personal info", "financial info", "contacts",
            "photos", "videos", "app activity", "device info",
            "messages", "health info", "app info and performance",
        ]
        for dt in data_types:
            if dt in page_text and f"Collects: {dt}" not in result["data_safety"]:
                result["data_safety"].append(f"Collects: {dt}")

        # Developer links from <a> tags
        if not result["website_url"]:
            for a in soup.find_all("a", href=True):
                href = a["href"]
                text = a.get_text(" ", strip=True).lower()
                if any(kw in text for kw in ("website", "visit website", "developer website")):
                    if href.startswith("http") and "google.com" not in href:
                        result["website_url"] = href
                        break

            # Google wraps outgoing URLs
            if not result["website_url"]:
                for a in soup.find_all("a", href=re.compile(r"google\.com/url\?")):
                    href = a["href"]
                    params = parse_qs(urlparse(href).query)
                    actual_url = params.get("q", params.get("url", [""]))[0]
                    if actual_url and "google.com" not in actual_url:
                        result["website_url"] = actual_url
                        break

        # Privacy policy from links
        if not result["privacy_policy_url"]:
            for a in soup.find_all("a", href=True):
                text = a.get_text(" ", strip=True).lower()
                if "privacy" in text:
                    href = a["href"]
                    if href.startswith("http"):
                        result["privacy_policy_url"] = href
                        break

    # ── Apple App Store ──────────────────────────────────────────────────

    def _scan_app_store(self) -> dict:
        """Scrape Apple App Store listing page."""
        result = {
            "store": "Apple App Store",
            "url": self.url,
            "app_id": self._extract_app_store_id(),
            "app_name": "",
            "developer": "",
            "rating": None,
            "rating_count": None,
            "size": "",
            "age_rating": "",
            "price": "",
            "description": "",
            "permissions_summary": [],
            "privacy_details": [],
            "website_url": "",
            "privacy_policy_url": "",
            "category": "",
            "in_app_purchases": False,
            "errors": [],
        }

        try:
            resp = requests.get(
                self.url, headers=self.HEADERS, timeout=self.timeout
            )
            if resp.status_code != 200:
                result["errors"].append(f"HTTP {resp.status_code}")
                return result

            soup = BeautifulSoup(resp.text, "html.parser")
            page_text = soup.get_text(" ", strip=True).lower()

            # App name
            h1 = soup.find("h1", class_=re.compile(r"product-header__title|app-header__title"))
            if h1:
                result["app_name"] = h1.get_text(strip=True)
            elif soup.title:
                title = soup.title.string or ""
                result["app_name"] = title.split(" on the")[0].strip()

            # Developer
            dev_el = soup.find("h2", class_=re.compile(r"product-header__identity"))
            if dev_el:
                result["developer"] = dev_el.get_text(strip=True)
            else:
                dev_link = soup.find("a", href=re.compile(r"/developer/"))
                if dev_link:
                    result["developer"] = dev_link.get_text(strip=True)

            # JSON-LD structured data
            for script in soup.find_all("script", type="application/ld+json"):
                try:
                    data = json.loads(script.string or "")
                    if isinstance(data, dict) and data.get("@type") == "SoftwareApplication":
                        result["app_name"] = result["app_name"] or data.get("name", "")
                        result["category"] = data.get("applicationCategory", "")
                        result["price"] = data.get("offers", {}).get("price", "")
                        agg = data.get("aggregateRating", {})
                        if agg:
                            try:
                                result["rating"] = round(float(agg.get("ratingValue", 0)), 1)
                            except (ValueError, TypeError):
                                pass
                            try:
                                result["rating_count"] = int(agg.get("ratingCount", 0))
                            except (ValueError, TypeError):
                                pass
                except (json.JSONDecodeError, TypeError):
                    pass

            # Description
            desc_meta = soup.find("meta", attrs={"name": "description"})
            if desc_meta and desc_meta.get("content"):
                result["description"] = desc_meta["content"][:500]

            # Age rating
            age_el = soup.find("span", class_=re.compile(r"badge--product-title"))
            if age_el:
                result["age_rating"] = age_el.get_text(strip=True)

            # In-app purchases
            if "in-app purchases" in page_text:
                result["in_app_purchases"] = True

            # Privacy details
            privacy_types = [
                "data used to track you", "data linked to you",
                "data not linked to you", "no data collected",
            ]
            for pt in privacy_types:
                if pt in page_text:
                    result["privacy_details"].append(pt)

            data_types = [
                "contact info", "identifiers", "usage data", "diagnostics",
                "financial info", "location", "purchases", "browsing history",
                "search history", "user content", "health & fitness",
                "sensitive info",
            ]
            for dt in data_types:
                if dt in page_text:
                    result["privacy_details"].append(f"Collects: {dt}")

            # Developer links
            for a in soup.find_all("a", href=True):
                href = a["href"]
                text = a.get_text(" ", strip=True).lower()
                if "privacy policy" in text and href.startswith("http"):
                    if not result["privacy_policy_url"]:
                        result["privacy_policy_url"] = href
                elif any(kw in text for kw in ("developer website", "website")):
                    if href.startswith("http") and "apple.com" not in href:
                        if not result["website_url"]:
                            result["website_url"] = href

        except requests.RequestException as e:
            result["errors"].append(str(e))

        return result

    def _extract_app_store_id(self) -> str:
        parsed = urlparse(self.url)
        match = re.search(r"/id(\d+)", parsed.path)
        return match.group(1) if match else ""
