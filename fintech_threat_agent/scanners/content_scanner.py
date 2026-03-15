"""Content Scanner - Analyzes page content for security indicators."""

import re
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup


class ContentScanner:
    """Scans webpage content for security-relevant patterns.

    Supports both single-page scanning and deep multi-page scanning
    using pre-crawled site data from SiteCrawler.
    """

    SENSITIVE_PATTERNS = {
        "api_key_exposure": re.compile(
            r"""(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\s]*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
            re.IGNORECASE,
        ),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "private_ip": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "phone_india": re.compile(r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b"),
        "aadhaar_number": re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),
        "pan_number": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "upi_id": re.compile(r"\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b"),
    }

    RISKY_JS_PATTERNS = {
        "eval_usage": re.compile(r"\beval\s*\("),
        "document_write": re.compile(r"\bdocument\.write\s*\("),
        "inner_html": re.compile(r"\.innerHTML\s*="),
        "local_storage_sensitive": re.compile(
            r"""localStorage\.setItem\s*\(\s*['"](?:token|password|secret|key|auth)['"]""",
            re.IGNORECASE,
        ),
    }

    def __init__(self, url: str, timeout: int = 15):
        self.url = url
        self.timeout = timeout

    def scan(self, crawl_data: dict | None = None) -> dict:
        """Scan page content for security issues.

        Args:
            crawl_data: Optional pre-crawled site data from SiteCrawler.
                        When provided, scans all crawled pages instead of
                        just the homepage.
        """
        result = {
            "data_exposure": [],
            "form_security": [],
            "external_resources": [],
            "javascript_risks": [],
            "mixed_content": [],
            "privacy_compliance": {},
            "app_store_links": {},
            "issues": [],
        }

        if crawl_data and crawl_data.get("pages"):
            # Deep scan mode: use pre-crawled multi-page data
            html = crawl_data["aggregated_html"]
            soup = crawl_data["aggregated_soup"]
            all_links = crawl_data.get("aggregated_links", [])
            result["app_store_links"] = crawl_data.get("app_store_links", {})
        else:
            # Fallback: single-page scan (original behavior)
            try:
                resp = requests.get(
                    self.url,
                    timeout=self.timeout,
                    headers={"User-Agent": "FinTechThreatAgent/1.0 (Security Audit)"},
                )
                html = resp.text
                soup = BeautifulSoup(html, "html.parser")
                all_links = None
            except requests.RequestException as e:
                result["issues"].append(f"Failed to fetch content: {e}")
                return result

        result["data_exposure"] = self._check_data_exposure(html)
        result["form_security"] = self._check_forms(soup)
        result["external_resources"] = self._check_external_resources(soup)
        result["javascript_risks"] = self._check_javascript(html, soup)
        result["mixed_content"] = self._check_mixed_content(soup)
        result["sri_issues"] = self._check_subresource_integrity(soup)
        result["inline_script_analysis"] = self._analyze_inline_scripts(soup)
        result["meta_security"] = self._check_meta_tags(soup)
        result["privacy_compliance"] = self._check_privacy_compliance(
            soup, html, precomputed_links=all_links,
        )

        # Summarize issues
        if result["data_exposure"]:
            result["issues"].append(
                f"Found {len(result['data_exposure'])} potential data exposure(s) in page content"
            )
        if result["form_security"]:
            result["issues"].append(
                f"Found {len(result['form_security'])} form security issue(s)"
            )
        if result["mixed_content"]:
            result["issues"].append(
                f"Found {len(result['mixed_content'])} mixed content resource(s)"
            )

        return result

    def _check_data_exposure(self, html: str) -> list:
        """Check for sensitive data patterns in page source."""
        findings = []
        for name, pattern in self.SENSITIVE_PATTERNS.items():
            matches = pattern.findall(html)
            if matches:
                # Don't include actual sensitive values in the report
                findings.append(
                    {
                        "type": name,
                        "count": len(matches),
                        "severity": "HIGH"
                        if name
                        in ("api_key_exposure", "aws_key", "aadhaar_number", "pan_number")
                        else "MEDIUM",
                    }
                )
        return findings

    def _check_forms(self, soup: BeautifulSoup) -> list:
        """Analyze forms for security issues."""
        issues = []
        forms = soup.find_all("form")

        for i, form in enumerate(forms):
            form_issues = []
            action = form.get("action", "")
            method = form.get("method", "get").lower()

            # Check if form submits over HTTP
            if action.startswith("http://"):
                form_issues.append("Form submits data over insecure HTTP")

            # Check for password fields without autocomplete=off
            password_fields = form.find_all("input", {"type": "password"})
            for pf in password_fields:
                if pf.get("autocomplete") != "off":
                    form_issues.append(
                        "Password field without autocomplete=off"
                    )

            # Check for CSRF token
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            csrf_names = {"csrf", "token", "_token", "csrfmiddlewaretoken", "authenticity_token"}
            has_csrf = any(
                inp.get("name", "").lower() in csrf_names
                or "csrf" in inp.get("name", "").lower()
                for inp in hidden_inputs
            )
            if method == "post" and not has_csrf:
                form_issues.append("POST form may lack CSRF protection")

            # Check for sensitive input fields
            sensitive_inputs = form.find_all(
                "input",
                {"name": re.compile(r"aadhaar|pan|account|ifsc|upi", re.IGNORECASE)},
            )
            for si in sensitive_inputs:
                if si.get("type") != "password" and not si.get("autocomplete") == "off":
                    form_issues.append(
                        f"Sensitive field '{si.get('name')}' may be cached by browser"
                    )

            if form_issues:
                issues.append({"form_index": i, "action": action or "(self)", "issues": form_issues})

        return issues

    def _check_external_resources(self, soup: BeautifulSoup) -> list:
        """Identify external scripts and resources."""
        externals = []
        parsed_base = urlparse(self.url)

        for script in soup.find_all("script", src=True):
            src = script["src"]
            parsed_src = urlparse(urljoin(self.url, src))
            if parsed_src.hostname and parsed_src.hostname != parsed_base.hostname:
                externals.append({"type": "script", "src": src, "domain": parsed_src.hostname})

        for link in soup.find_all("link", href=True):
            href = link["href"]
            parsed_href = urlparse(urljoin(self.url, href))
            if parsed_href.hostname and parsed_href.hostname != parsed_base.hostname:
                externals.append({"type": "stylesheet/link", "src": href, "domain": parsed_href.hostname})

        return externals

    def _check_javascript(self, html: str, soup: BeautifulSoup) -> list:
        """Check for risky JavaScript patterns."""
        risks = []
        inline_scripts = soup.find_all("script", src=False)
        all_js = "\n".join(s.string or "" for s in inline_scripts)

        for name, pattern in self.RISKY_JS_PATTERNS.items():
            if pattern.search(all_js):
                risks.append({"pattern": name, "location": "inline_script"})

        return risks

    def _check_mixed_content(self, soup: BeautifulSoup) -> list:
        """Check for mixed content (HTTP resources on HTTPS page)."""
        if not self.url.startswith("https://"):
            return []

        mixed = []
        for tag, attr in [("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")]:
            for el in soup.find_all(tag, {attr: True}):
                val = el[attr]
                if val.startswith("http://"):
                    mixed.append({"tag": tag, "attribute": attr, "url": val})

        return mixed

    def _check_subresource_integrity(self, soup: BeautifulSoup) -> list:
        """Check external scripts and stylesheets for SRI (integrity attribute)."""
        issues = []
        parsed_base = urlparse(self.url)

        for script in soup.find_all("script", src=True):
            src = script["src"]
            parsed_src = urlparse(urljoin(self.url, src))
            # Only flag external scripts (CDNs, third-party)
            if parsed_src.hostname and parsed_src.hostname != parsed_base.hostname:
                if not script.get("integrity"):
                    issues.append({
                        "tag": "script",
                        "src": src,
                        "domain": parsed_src.hostname,
                        "has_integrity": False,
                    })

        for link in soup.find_all("link", rel="stylesheet", href=True):
            href = link["href"]
            parsed_href = urlparse(urljoin(self.url, href))
            if parsed_href.hostname and parsed_href.hostname != parsed_base.hostname:
                if not link.get("integrity"):
                    issues.append({
                        "tag": "link",
                        "src": href,
                        "domain": parsed_href.hostname,
                        "has_integrity": False,
                    })

        return issues

    def _analyze_inline_scripts(self, soup: BeautifulSoup) -> dict:
        """Analyze inline scripts for security concerns."""
        inline_scripts = soup.find_all("script", src=False)
        total_inline = len(inline_scripts)
        total_chars = 0
        nonce_count = 0
        event_handler_count = 0

        for script in inline_scripts:
            code = script.string or ""
            total_chars += len(code)
            if script.get("nonce"):
                nonce_count += 1

        # Count inline event handlers (onclick, onerror, onload, etc.)
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.lower().startswith("on"):
                    event_handler_count += 1

        return {
            "inline_script_count": total_inline,
            "inline_script_chars": total_chars,
            "scripts_with_nonce": nonce_count,
            "event_handler_count": event_handler_count,
        }

    def _check_meta_tags(self, soup: BeautifulSoup) -> dict:
        """Check for security-relevant meta tags."""
        result = {
            "has_charset": False,
            "has_viewport": False,
            "has_x_ua_compatible": False,
            "has_csp_meta": False,
            "has_referrer_meta": False,
            "robots_noindex": False,
            "sensitive_meta_content": [],
        }

        for meta in soup.find_all("meta"):
            charset = meta.get("charset")
            if charset:
                result["has_charset"] = True

            name = (meta.get("name") or "").lower()
            http_equiv = (meta.get("http-equiv") or "").lower()
            content = meta.get("content", "")

            if name == "viewport":
                result["has_viewport"] = True
            if http_equiv == "x-ua-compatible":
                result["has_x_ua_compatible"] = True
            if http_equiv == "content-security-policy":
                result["has_csp_meta"] = True
            if name == "referrer":
                result["has_referrer_meta"] = True
            if name == "robots" and "noindex" in content.lower():
                result["robots_noindex"] = True

            # Check for sensitive data in meta content
            if content:
                for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                    if pattern.search(content):
                        result["sensitive_meta_content"].append({
                            "type": pattern_name,
                            "meta_name": name or http_equiv,
                        })

        return result

    def _check_privacy_compliance(self, soup: BeautifulSoup, html: str,
                                   precomputed_links: list | None = None) -> dict:
        """Check for GDPR/DPDP privacy compliance indicators across all pages.

        Args:
            soup: BeautifulSoup of page(s) HTML
            html: Raw HTML string (may be aggregated from multiple pages)
            precomputed_links: Optional pre-extracted (href, text) pairs from crawler
        """
        html_lower = html.lower()
        all_text = soup.get_text(" ", strip=True).lower()

        if precomputed_links is not None:
            all_links = precomputed_links
        else:
            all_links = [
                (a.get("href", "").lower(), a.get_text(" ", strip=True).lower())
                for a in soup.find_all("a", href=True)
            ]

        result = {
            "has_privacy_policy": False,
            "has_cookie_consent": False,
            "has_terms_of_service": False,
            "has_data_processing_notice": False,
            "has_grievance_officer": False,
            "has_opt_out_mechanism": False,
            "has_data_retention_info": False,
            "has_third_party_disclosure": False,
            "has_right_to_erasure_info": False,
            "has_dpo_contact": False,
            "grievance_officer_details": {},
        }

        # Privacy policy link
        privacy_keywords = ["privacy policy", "privacy notice", "data protection",
                            "privacy statement", "privacy-policy", "privacypolicy"]
        for href, text in all_links:
            combined = href + " " + text
            if any(kw in combined for kw in privacy_keywords):
                result["has_privacy_policy"] = True
                break

        # Cookie consent banner / mechanism
        cookie_indicators = [
            "cookie consent", "cookie policy", "cookie banner", "accept cookies",
            "cookie preferences", "manage cookies", "cookie-consent", "cookieconsent",
            "cookie_consent", "gdpr-cookie", "cookie-notice", "cc-banner",
            "cookie-law", "onetrust", "cookiebot", "trustarc",
        ]
        if any(kw in html_lower for kw in cookie_indicators):
            result["has_cookie_consent"] = True

        # Terms of service
        tos_keywords = ["terms of service", "terms and conditions", "terms of use",
                        "terms-of-service", "terms-and-conditions", "user agreement"]
        for href, text in all_links:
            combined = href + " " + text
            if any(kw in combined for kw in tos_keywords):
                result["has_terms_of_service"] = True
                break

        # Data processing / lawful basis notice
        dp_keywords = ["data processing", "lawful basis", "legitimate interest",
                       "consent for processing", "purpose of collection",
                       "data we collect", "information we collect"]
        if any(kw in all_text for kw in dp_keywords):
            result["has_data_processing_notice"] = True

        # Grievance officer (Indian regulation - DPDP / IT Act)
        # Comprehensive detection across all pages
        grievance_keywords = [
            "grievance officer", "grievance redressal", "grievance redressal officer",
            "nodal officer", "compliance officer", "investor grievance",
            "grievance.officer", "grievance@", "grievances@",
            "redressal of grievance", "redressal officer",
            "grievance redressal mechanism", "investor complaint",
            "complaint officer", "complaints officer",
            "designated officer", "appellate authority",
            "compliance nodal", "investor relations officer",
        ]
        if any(kw in all_text or kw in html_lower for kw in grievance_keywords):
            result["has_grievance_officer"] = True
            # Try to extract details
            result["grievance_officer_details"] = self._extract_grievance_details(
                all_text, html_lower
            )

        # Also check link text/href for grievance pages
        if not result["has_grievance_officer"]:
            grievance_link_keywords = [
                "grievance", "complaint", "redressal", "nodal officer",
                "investor-grievance", "grievance-officer", "complaints",
            ]
            for href, text in all_links:
                combined = href + " " + text
                if any(kw in combined for kw in grievance_link_keywords):
                    result["has_grievance_officer"] = True
                    break

        # Opt-out / unsubscribe mechanism
        optout_keywords = ["opt out", "opt-out", "unsubscribe", "withdraw consent",
                           "revoke consent", "do not sell"]
        if any(kw in all_text for kw in optout_keywords):
            result["has_opt_out_mechanism"] = True

        # Data retention info
        retention_keywords = ["data retention", "retention period", "how long we keep",
                              "retention policy", "data storage period"]
        if any(kw in all_text for kw in retention_keywords):
            result["has_data_retention_info"] = True

        # Third-party data sharing disclosure
        tp_keywords = ["third party", "third-party", "data sharing", "share your data",
                       "share your information", "partners and affiliates"]
        if any(kw in all_text for kw in tp_keywords):
            result["has_third_party_disclosure"] = True

        # Right to erasure / deletion
        erasure_keywords = ["right to erasure", "right to deletion", "delete your data",
                            "delete my account", "data deletion", "right to be forgotten",
                            "erase your data"]
        if any(kw in all_text for kw in erasure_keywords):
            result["has_right_to_erasure_info"] = True

        # DPO / data protection officer contact
        dpo_keywords = ["data protection officer", "dpo@", "dpo contact",
                        "privacy@", "privacy officer"]
        if any(kw in all_text or kw in html_lower for kw in dpo_keywords):
            result["has_dpo_contact"] = True

        return result

    def _extract_grievance_details(self, all_text: str, html_lower: str) -> dict:
        """Extract grievance officer contact details from page text."""
        details = {}

        # Try to extract grievance officer name
        name_pattern = re.compile(
            r"(?:grievance\s+(?:redressal\s+)?officer|nodal\s+officer|compliance\s+officer)"
            r"[\s:–\-]*(?:mr\.?|ms\.?|mrs\.?|dr\.?|shri|smt)?\s*"
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
            re.IGNORECASE,
        )
        name_match = name_pattern.search(all_text)
        if not name_match:
            # Also search in HTML for structured content
            name_match = name_pattern.search(html_lower)
        if name_match:
            details["name"] = name_match.group(1).strip()

        # Extract email associated with grievance
        email_pattern = re.compile(
            r"(?:grievance|complaint|redressal|nodal|compliance)[^\n]{0,100}?"
            r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            re.IGNORECASE,
        )
        email_match = email_pattern.search(all_text)
        if not email_match:
            email_match = email_pattern.search(html_lower)
        if email_match:
            details["email"] = email_match.group(1)

        # Extract phone near grievance context
        phone_pattern = re.compile(
            r"(?:grievance|complaint|redressal|nodal|compliance)[^\n]{0,100}?"
            r"(\+?91[\s-]?\d{10}|\d{10,11})",
            re.IGNORECASE,
        )
        phone_match = phone_pattern.search(all_text)
        if phone_match:
            details["phone"] = phone_match.group(1)

        return details
