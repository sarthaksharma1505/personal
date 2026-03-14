"""Content Scanner - Analyzes page content for security indicators."""

import re
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup


class ContentScanner:
    """Scans webpage content for security-relevant patterns."""

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

    def scan(self) -> dict:
        """Scan page content for security issues."""
        result = {
            "data_exposure": [],
            "form_security": [],
            "external_resources": [],
            "javascript_risks": [],
            "mixed_content": [],
            "issues": [],
        }

        try:
            resp = requests.get(
                self.url,
                timeout=self.timeout,
                headers={"User-Agent": "FinTechThreatAgent/1.0 (Security Audit)"},
            )
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
        except requests.RequestException as e:
            result["issues"].append(f"Failed to fetch content: {e}")
            return result

        result["data_exposure"] = self._check_data_exposure(html)
        result["form_security"] = self._check_forms(soup)
        result["external_resources"] = self._check_external_resources(soup)
        result["javascript_risks"] = self._check_javascript(html, soup)
        result["mixed_content"] = self._check_mixed_content(soup)

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
