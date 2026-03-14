"""URL Scanner - Performs HTTP, SSL, header, and DNS analysis on target URLs."""

import socket
import ssl
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import dns.resolver


class URLScanner:
    """Scans a target URL for security-relevant information."""

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
    ]

    RISKY_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    ]

    def __init__(self, url: str, timeout: int = 15):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.url = url
        self.parsed = urlparse(url)
        self.hostname = self.parsed.hostname
        self.timeout = timeout

    def scan_all(self) -> dict:
        """Run all scans and return consolidated results."""
        results = {
            "url": self.url,
            "hostname": self.hostname,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "http": self._scan_http(),
            "ssl": self._scan_ssl(),
            "dns": self._scan_dns(),
            "headers": self._scan_headers(),
        }
        return results

    def _scan_http(self) -> dict:
        """Check HTTP response, redirects, and basic connectivity."""
        result = {
            "reachable": False,
            "status_code": None,
            "redirect_chain": [],
            "uses_https": self.parsed.scheme == "https",
            "http_to_https_redirect": False,
            "response_time_ms": None,
            "errors": [],
        }

        try:
            resp = requests.get(
                self.url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "FinTechThreatAgent/1.0 (Security Audit)"},
            )
            result["reachable"] = True
            result["status_code"] = resp.status_code
            result["response_time_ms"] = round(resp.elapsed.total_seconds() * 1000)
            result["redirect_chain"] = [r.url for r in resp.history]

            # Check HTTP -> HTTPS redirect
            if not result["uses_https"]:
                http_url = self.url.replace("https://", "http://", 1)
                try:
                    http_resp = requests.get(
                        http_url, timeout=self.timeout, allow_redirects=False
                    )
                    if http_resp.status_code in (301, 302, 307, 308):
                        location = http_resp.headers.get("Location", "")
                        if location.startswith("https://"):
                            result["http_to_https_redirect"] = True
                except requests.RequestException:
                    pass

        except requests.ConnectionError as e:
            result["errors"].append(f"Connection failed: {e}")
        except requests.Timeout:
            result["errors"].append("Request timed out")
        except requests.RequestException as e:
            result["errors"].append(f"Request error: {e}")

        return result

    def _scan_ssl(self) -> dict:
        """Analyze SSL/TLS certificate and configuration."""
        result = {
            "has_ssl": False,
            "certificate": {},
            "protocol_version": None,
            "cipher_suite": None,
            "issues": [],
        }

        if not self.hostname:
            result["issues"].append("No hostname to check SSL")
            return result

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                (self.hostname, 443), timeout=self.timeout
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    result["has_ssl"] = True
                    result["protocol_version"] = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        result["cipher_suite"] = cipher[0]

                    cert = ssock.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        not_after = cert.get("notAfter", "")

                        result["certificate"] = {
                            "subject_cn": subject.get("commonName", ""),
                            "issuer_org": issuer.get("organizationName", ""),
                            "expires": not_after,
                            "san": [
                                v
                                for t, v in cert.get("subjectAltName", ())
                                if t == "DNS"
                            ],
                        }

                        # Check expiry
                        if not_after:
                            try:
                                exp_date = datetime.strptime(
                                    not_after, "%b %d %H:%M:%S %Y %Z"
                                )
                                days_left = (exp_date - datetime.utcnow()).days
                                result["certificate"]["days_until_expiry"] = days_left
                                if days_left < 0:
                                    result["issues"].append("Certificate has EXPIRED")
                                elif days_left < 30:
                                    result["issues"].append(
                                        f"Certificate expires in {days_left} days"
                                    )
                            except ValueError:
                                pass

                    # Check for weak protocols
                    if result["protocol_version"] in ("TLSv1", "TLSv1.1"):
                        result["issues"].append(
                            f"Weak TLS version: {result['protocol_version']}"
                        )

        except ssl.SSLCertVerificationError as e:
            result["issues"].append(f"SSL certificate verification failed: {e}")
        except ssl.SSLError as e:
            result["issues"].append(f"SSL error: {e}")
        except (socket.timeout, socket.error) as e:
            result["issues"].append(f"Connection error during SSL check: {e}")

        return result

    def _scan_dns(self) -> dict:
        """Analyze DNS records for the domain."""
        result = {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "has_spf": False,
            "has_dmarc": False,
            "has_dnssec": False,
            "issues": [],
        }

        if not self.hostname:
            return result

        domain = self.hostname
        # Get base domain for MX/TXT checks
        parts = domain.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) > 2 else domain

        for record_type, key in [
            ("A", "a_records"),
            ("MX", "mx_records"),
            ("NS", "ns_records"),
        ]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[key] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass

        # TXT records (check on base domain)
        try:
            answers = dns.resolver.resolve(base_domain, "TXT")
            for r in answers:
                txt = str(r).strip('"')
                result["txt_records"].append(txt)
                if txt.startswith("v=spf1"):
                    result["has_spf"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass

        # DMARC check
        try:
            dmarc_domain = f"_dmarc.{base_domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for r in answers:
                if "v=DMARC1" in str(r):
                    result["has_dmarc"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass

        # Flag missing email security
        if not result["has_spf"]:
            result["issues"].append("No SPF record found - vulnerable to email spoofing")
        if not result["has_dmarc"]:
            result["issues"].append(
                "No DMARC record found - email domain not protected"
            )

        return result

    def _scan_headers(self) -> dict:
        """Analyze HTTP security headers."""
        result = {
            "present": {},
            "missing": [],
            "information_disclosure": [],
            "cookie_issues": [],
            "issues": [],
        }

        try:
            resp = requests.get(
                self.url,
                timeout=self.timeout,
                headers={"User-Agent": "FinTechThreatAgent/1.0 (Security Audit)"},
            )
        except requests.RequestException:
            result["issues"].append("Could not fetch headers")
            return result

        headers = resp.headers

        # Check security headers
        for h in self.SECURITY_HEADERS:
            val = headers.get(h)
            if val:
                result["present"][h] = val
            else:
                result["missing"].append(h)

        # Check information disclosure
        for h in self.RISKY_HEADERS:
            val = headers.get(h)
            if val:
                result["information_disclosure"].append({"header": h, "value": val})

        # Cookie security
        for cookie_header in resp.headers.get("Set-Cookie", "").split(","):
            if not cookie_header.strip():
                continue
            cookie_lower = cookie_header.lower()
            issues = []
            if "secure" not in cookie_lower:
                issues.append("Missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite attribute")
            if issues:
                name = cookie_header.split("=")[0].strip()
                result["cookie_issues"].append({"cookie": name, "issues": issues})

        # Generate issues
        critical_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
        ]
        for h in critical_headers:
            if h in result["missing"]:
                result["issues"].append(f"Missing critical security header: {h}")

        if result["information_disclosure"]:
            result["issues"].append(
                "Server version information disclosed via headers"
            )

        return result
