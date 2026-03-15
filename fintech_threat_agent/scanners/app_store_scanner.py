"""App Store Scanner - Scrapes metadata from Google Play Store and Apple App Store listings."""

import re
import json
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup


class AppStoreScanner:
    """Scrapes and analyzes app metadata from Play Store and App Store pages."""

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
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
        return {"error": "Not a recognized app store URL"}

    # ── Google Play Store ────────────────────────────────────────────────

    def _scan_play_store(self) -> dict:
        """Scrape Google Play Store listing page."""
        result = {
            "store": "Google Play Store",
            "url": self.url,
            "app_id": self._extract_play_store_id(),
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

        try:
            resp = requests.get(
                self.url, headers=self.HEADERS, timeout=self.timeout
            )
            if resp.status_code != 200:
                result["errors"].append(f"HTTP {resp.status_code}")
                return result

            soup = BeautifulSoup(resp.text, "html.parser")
            html = resp.text

            # App name - from <h1> or title
            h1 = soup.find("h1")
            if h1:
                result["app_name"] = h1.get_text(strip=True)
            elif soup.title:
                title_text = soup.title.string or ""
                result["app_name"] = title_text.split(" - ")[0].strip()

            # Developer name
            dev_links = soup.find_all("a", href=re.compile(r"/store/apps/dev"))
            if dev_links:
                result["developer"] = dev_links[0].get_text(strip=True)

            # Rating
            rating_el = soup.find("div", class_=re.compile(r"jILTFe|BHMmbe"))
            if rating_el:
                rating_text = rating_el.get_text(strip=True)
                try:
                    result["rating"] = float(rating_text[:3])
                except (ValueError, IndexError):
                    pass
            # Fallback: look for itemprop="ratingValue"
            if result["rating"] is None:
                rating_meta = soup.find(attrs={"itemprop": "ratingValue"})
                if rating_meta:
                    try:
                        result["rating"] = float(rating_meta.get("content", "0"))
                    except ValueError:
                        pass

            # Rating count
            rating_count_el = soup.find(attrs={"itemprop": "ratingCount"})
            if rating_count_el:
                try:
                    result["rating_count"] = int(
                        rating_count_el.get("content", "0").replace(",", "")
                    )
                except ValueError:
                    pass

            # Category
            cat_el = soup.find("a", href=re.compile(r"/store/apps/category/"))
            if cat_el:
                result["category"] = cat_el.get_text(strip=True)

            # Description
            desc_meta = soup.find("meta", attrs={"name": "description"})
            if desc_meta:
                result["description"] = desc_meta.get("content", "")[:500]

            # Installs, last updated, requires, content rating from metadata
            self._parse_play_store_metadata(soup, html, result)

            # Contains ads / in-app purchases
            page_text = soup.get_text(" ", strip=True).lower()
            if "contains ads" in page_text:
                result["contains_ads"] = True
            if "in-app purchases" in page_text:
                result["in_app_purchases"] = True

            # Data safety section
            self._parse_data_safety(soup, page_text, result)

            # Developer links (website, privacy policy)
            self._parse_developer_links(soup, html, result)

        except requests.RequestException as e:
            result["errors"].append(str(e))

        return result

    def _extract_play_store_id(self) -> str:
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return params.get("id", [""])[0]

    def _parse_play_store_metadata(self, soup, html, result):
        """Extract metadata fields from Play Store page."""
        # Look for structured data in JSON-LD
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string or "")
                if isinstance(data, dict):
                    if data.get("@type") == "SoftwareApplication":
                        result["rating"] = result["rating"] or data.get(
                            "aggregateRating", {}
                        ).get("ratingValue")
                        result["rating_count"] = result["rating_count"] or data.get(
                            "aggregateRating", {}
                        ).get("ratingCount")
                        result["category"] = result["category"] or data.get(
                            "applicationCategory", ""
                        )
                        result["requires_android"] = data.get(
                            "operatingSystem", ""
                        )
            except (json.JSONDecodeError, TypeError):
                pass

        # Additional info from info rows
        info_divs = soup.find_all("div", class_=re.compile(r"hAyfc|bARER"))
        for div in info_divs:
            text = div.get_text(" ", strip=True)
            if "Updated" in text:
                result["last_updated"] = text.split("Updated")[-1].strip()
            elif "Installs" in text:
                result["installs"] = text.split("Installs")[-1].strip()
            elif "Content Rating" in text:
                result["content_rating"] = text.split("Content Rating")[-1].strip()

    def _parse_data_safety(self, soup, page_text, result):
        """Extract data safety information from Play Store."""
        safety_keywords = [
            "data shared with third parties",
            "data collected",
            "data is encrypted in transit",
            "data can be deleted",
            "data is not encrypted",
            "data cannot be deleted",
            "no data shared with third parties",
            "no data collected",
        ]
        for kw in safety_keywords:
            if kw in page_text:
                result["data_safety"].append(kw)

        # Also check for specific data types collected
        data_types = [
            "location", "personal info", "financial info", "contacts",
            "photos", "videos", "files", "app activity", "device info",
            "messages", "health info",
        ]
        for dt in data_types:
            if dt in page_text:
                result["data_safety"].append(f"Collects: {dt}")

    def _parse_developer_links(self, soup, html, result):
        """Extract developer website and privacy policy links."""
        # Privacy policy link
        for a in soup.find_all("a", href=True):
            href = a["href"]
            text = a.get_text(" ", strip=True).lower()
            if "privacy" in text or "privacy" in href.lower():
                if href.startswith("http"):
                    result["privacy_policy_url"] = href
                    break

        # Developer website
        for a in soup.find_all("a", href=True):
            href = a["href"]
            text = a.get_text(" ", strip=True).lower()
            if any(kw in text for kw in ("website", "visit website", "developer website")):
                if href.startswith("http"):
                    result["website_url"] = href
                    break

        # Fallback: find website from outgoing links
        if not result["website_url"]:
            # Google Play sometimes wraps outgoing URLs
            for a in soup.find_all("a", href=re.compile(r"google\.com/url\?")):
                href = a["href"]
                params = parse_qs(urlparse(href).query)
                actual_url = params.get("q", params.get("url", [""]))[0]
                if actual_url and "google.com" not in actual_url and "apple.com" not in actual_url:
                    text = a.get_text(" ", strip=True).lower()
                    if any(kw in text for kw in ("website", "visit", "web")):
                        result["website_url"] = actual_url
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
                # Fallback
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
                            result["rating"] = agg.get("ratingValue")
                            result["rating_count"] = agg.get("ratingCount")
                except (json.JSONDecodeError, TypeError):
                    pass

            # Description
            desc_meta = soup.find("meta", attrs={"name": "description"})
            if desc_meta:
                result["description"] = desc_meta.get("content", "")[:500]

            # Age rating
            age_el = soup.find("span", class_=re.compile(r"badge--product-title"))
            if age_el:
                result["age_rating"] = age_el.get_text(strip=True)

            # In-app purchases
            if "in-app purchases" in page_text:
                result["in_app_purchases"] = True

            # Privacy details - Apple's App Privacy section
            self._parse_apple_privacy(soup, page_text, result)

            # Developer links
            for a in soup.find_all("a", href=True):
                href = a["href"]
                text = a.get_text(" ", strip=True).lower()
                if "privacy policy" in text and href.startswith("http"):
                    result["privacy_policy_url"] = href
                elif any(kw in text for kw in ("developer website", "website")) and href.startswith("http"):
                    if "apple.com" not in href:
                        result["website_url"] = href

        except requests.RequestException as e:
            result["errors"].append(str(e))

        return result

    def _extract_app_store_id(self) -> str:
        parsed = urlparse(self.url)
        # App Store IDs are in the path: /app/name/id12345
        match = re.search(r"/id(\d+)", parsed.path)
        return match.group(1) if match else ""

    def _parse_apple_privacy(self, soup, page_text, result):
        """Extract Apple App Privacy details."""
        privacy_types = [
            "data used to track you",
            "data linked to you",
            "data not linked to you",
            "no data collected",
        ]
        for pt in privacy_types:
            if pt in page_text:
                result["privacy_details"].append(pt)

        # Specific data types
        data_types = [
            "contact info", "identifiers", "usage data", "diagnostics",
            "financial info", "location", "purchases", "browsing history",
            "search history", "user content", "health & fitness",
            "sensitive info",
        ]
        for dt in data_types:
            if dt in page_text:
                result["privacy_details"].append(f"Collects: {dt}")
