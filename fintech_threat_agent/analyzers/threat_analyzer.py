"""Threat Analyzer - Evaluates scan results and identifies security threats."""

from dataclasses import dataclass, field


@dataclass
class Threat:
    """Represents a detected security threat."""
    category: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    recommendation: str
    references: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "references": self.references,
        }


class ThreatAnalyzer:
    """Analyzes scan results to identify and classify threats."""

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def analyze(self, scan_results: dict, content_results: dict) -> list[Threat]:
        """Analyze all scan results and return a list of threats."""
        threats = []
        threats.extend(self._analyze_ssl(scan_results.get("ssl", {})))
        threats.extend(self._analyze_headers(scan_results.get("headers", {})))
        threats.extend(self._analyze_header_quality(scan_results.get("headers", {})))
        threats.extend(self._analyze_http(scan_results.get("http", {})))
        threats.extend(self._analyze_dns(scan_results.get("dns", {})))
        threats.extend(self._analyze_content(content_results))
        threats.extend(self._analyze_sri(content_results))
        threats.extend(self._analyze_inline_scripts(content_results))
        threats.extend(self._analyze_external_resources(content_results))
        threats.extend(self._analyze_header_coverage(scan_results.get("headers", {})))
        threats.extend(self._analyze_cookie_security(scan_results.get("headers", {})))
        threats.extend(self._analyze_redirect_chain(scan_results.get("http", {})))
        threats.extend(self._analyze_certificate_strength(scan_results.get("ssl", {})))

        # Sort by severity
        threats.sort(key=lambda t: self.SEVERITY_ORDER.get(t.severity, 5))
        return threats

    def _analyze_ssl(self, ssl_data: dict) -> list[Threat]:
        threats = []

        if not ssl_data.get("has_ssl"):
            threats.append(Threat(
                category="Encryption",
                title="No SSL/TLS Encryption",
                description="The application does not use SSL/TLS encryption. All data including financial transactions, credentials, and personal information is transmitted in plaintext.",
                severity="CRITICAL",
                recommendation="Immediately implement SSL/TLS with a valid certificate. Use TLS 1.2 or higher. This is mandatory under RBI guidelines for digital payments.",
                references=["RBI Master Direction on Digital Payment Security Controls", "CERT-In Guidelines"],
            ))

        for issue in ssl_data.get("issues", []):
            if "EXPIRED" in issue:
                threats.append(Threat(
                    category="Encryption",
                    title="Expired SSL Certificate",
                    description="The SSL certificate has expired, causing browser security warnings and leaving the connection vulnerable to MITM attacks.",
                    severity="CRITICAL",
                    recommendation="Renew the SSL certificate immediately. Set up automated certificate renewal.",
                    references=["RBI Cyber Security Framework"],
                ))
            elif "Weak TLS" in issue:
                threats.append(Threat(
                    category="Encryption",
                    title="Weak TLS Version",
                    description=f"The server supports {issue}. TLS 1.0 and 1.1 have known vulnerabilities.",
                    severity="HIGH",
                    recommendation="Disable TLS 1.0 and TLS 1.1. Use only TLS 1.2 and TLS 1.3.",
                    references=["PCI DSS v4.0 Requirement 4.2.1"],
                ))
            elif "verification failed" in issue:
                threats.append(Threat(
                    category="Encryption",
                    title="SSL Certificate Verification Failure",
                    description="The SSL certificate could not be verified. This may indicate a self-signed certificate, certificate chain issue, or potential MITM attack.",
                    severity="HIGH",
                    recommendation="Use a certificate from a trusted Certificate Authority. Ensure the full certificate chain is properly configured.",
                    references=["OWASP Transport Layer Security Cheat Sheet"],
                ))

        return threats

    def _analyze_headers(self, header_data: dict) -> list[Threat]:
        threats = []
        missing = header_data.get("missing", [])

        if "Strict-Transport-Security" in missing:
            threats.append(Threat(
                category="Transport Security",
                title="Missing HSTS Header",
                description="HTTP Strict Transport Security header is not set. Users can be downgraded to HTTP via MITM attacks (SSL stripping).",
                severity="HIGH",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
                references=["OWASP Secure Headers Project"],
            ))

        if "Content-Security-Policy" in missing:
            threats.append(Threat(
                category="Injection Protection",
                title="Missing Content Security Policy",
                description="No CSP header found. The application is more vulnerable to XSS attacks, which could steal financial data, session tokens, or inject malicious payment forms.",
                severity="HIGH",
                recommendation="Implement a strict Content-Security-Policy header. Start with a report-only policy and tighten progressively.",
                references=["OWASP CSP Cheat Sheet"],
            ))

        if "X-Frame-Options" in missing:
            threats.append(Threat(
                category="UI Security",
                title="Missing X-Frame-Options / Clickjacking Protection",
                description="The application can be embedded in iframes, making it vulnerable to clickjacking attacks. Attackers could trick users into making unintended financial transactions.",
                severity="MEDIUM",
                recommendation="Add 'X-Frame-Options: DENY' or use CSP frame-ancestors directive.",
                references=["OWASP Clickjacking Defense Cheat Sheet"],
            ))

        if "X-Content-Type-Options" in missing:
            threats.append(Threat(
                category="Injection Protection",
                title="Missing X-Content-Type-Options",
                description="Without this header, browsers may MIME-sniff responses, potentially executing uploaded malicious files as scripts.",
                severity="MEDIUM",
                recommendation="Add 'X-Content-Type-Options: nosniff' header.",
                references=["OWASP Secure Headers"],
            ))

        # Information disclosure
        for disclosure in header_data.get("information_disclosure", []):
            threats.append(Threat(
                category="Information Disclosure",
                title=f"Server Information Leaked via {disclosure['header']}",
                description=f"The header '{disclosure['header']}: {disclosure['value']}' reveals server technology details. Attackers can use this to find known vulnerabilities for that specific version.",
                severity="LOW",
                recommendation=f"Remove or obfuscate the {disclosure['header']} header.",
                references=["OWASP Information Disclosure"],
            ))

        return threats

    def _analyze_http(self, http_data: dict) -> list[Threat]:
        threats = []

        if not http_data.get("uses_https"):
            threats.append(Threat(
                category="Transport Security",
                title="Application Not Using HTTPS",
                description="The application is served over HTTP. All financial data, credentials, and personal information is exposed to network eavesdropping.",
                severity="CRITICAL",
                recommendation="Migrate entirely to HTTPS. Redirect all HTTP traffic to HTTPS. This is mandatory for fintech applications under RBI guidelines.",
                references=["RBI Master Direction on Digital Payment Security Controls"],
            ))

        if not http_data.get("reachable"):
            threats.append(Threat(
                category="Availability",
                title="Application Unreachable",
                description="The application could not be reached. This may indicate downtime, network issues, or IP-based access controls.",
                severity="INFO",
                recommendation="Verify the URL is correct and the application is running.",
                references=[],
            ))

        response_time = http_data.get("response_time_ms")
        if response_time and response_time > 5000:
            threats.append(Threat(
                category="Availability",
                title="Slow Response Time",
                description=f"Response time is {response_time}ms. Slow responses may indicate performance issues and potential susceptibility to denial-of-service attacks.",
                severity="LOW",
                recommendation="Investigate server performance. Consider CDN, caching, and DDoS protection.",
                references=[],
            ))

        return threats

    def _analyze_dns(self, dns_data: dict) -> list[Threat]:
        threats = []

        if not dns_data.get("has_spf"):
            threats.append(Threat(
                category="Email Security",
                title="Missing SPF Record",
                description="No SPF record found for the domain. Attackers can send spoofed emails appearing to come from your domain, facilitating phishing attacks against customers.",
                severity="MEDIUM",
                recommendation="Configure an SPF record to specify authorized mail servers. Example: 'v=spf1 include:_spf.google.com ~all'",
                references=["CERT-In Advisory on Email Security"],
            ))

        if not dns_data.get("has_dmarc"):
            threats.append(Threat(
                category="Email Security",
                title="Missing DMARC Record",
                description="No DMARC record found. Without DMARC, there is no policy to handle emails that fail SPF/DKIM checks, making phishing attacks more effective.",
                severity="MEDIUM",
                recommendation="Implement DMARC with at least 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'",
                references=["RBI Phishing Guidelines"],
            ))

        return threats

    def _analyze_content(self, content_data: dict) -> list[Threat]:
        threats = []

        for exposure in content_data.get("data_exposure", []):
            threats.append(Threat(
                category="Data Exposure",
                title=f"Potential {exposure['type'].replace('_', ' ').title()} in Page Source",
                description=f"Found {exposure['count']} instance(s) of potential {exposure['type'].replace('_', ' ')} in the page source code. For fintech applications, any data leakage is a compliance violation.",
                severity=exposure.get("severity", "MEDIUM"),
                recommendation="Remove sensitive data from client-side code. Use server-side processing for all sensitive operations.",
                references=["RBI Data Localization Guidelines", "IT Act 2000 Section 43A"],
            ))

        for form_issue in content_data.get("form_security", []):
            for issue in form_issue.get("issues", []):
                severity = "HIGH" if "CSRF" in issue or "insecure HTTP" in issue else "MEDIUM"
                threats.append(Threat(
                    category="Form Security",
                    title=issue,
                    description=f"Form (action: {form_issue['action']}) has security issue: {issue}. In fintech applications, form vulnerabilities can lead to unauthorized transactions.",
                    severity=severity,
                    recommendation="Implement CSRF tokens, use HTTPS for form submissions, and set appropriate autocomplete attributes for sensitive fields.",
                    references=["OWASP CSRF Prevention Cheat Sheet"],
                ))

        for mixed in content_data.get("mixed_content", []):
            threats.append(Threat(
                category="Mixed Content",
                title=f"HTTP Resource Loaded on HTTPS Page",
                description=f"An HTTP {mixed['tag']} resource is loaded on an HTTPS page: {mixed['url']}. This compromises the security of the entire page.",
                severity="HIGH",
                recommendation="Load all resources over HTTPS. Update resource URLs or use protocol-relative URLs.",
                references=["OWASP Mixed Content"],
            ))

        for js_risk in content_data.get("javascript_risks", []):
            threats.append(Threat(
                category="JavaScript Security",
                title=f"Risky JavaScript Pattern: {js_risk['pattern']}",
                description=f"Found usage of {js_risk['pattern']} in {js_risk['location']}. This pattern is associated with XSS vulnerabilities.",
                severity="MEDIUM",
                recommendation="Avoid eval(), document.write(), and innerHTML. Use safer DOM manipulation methods.",
                references=["OWASP DOM Based XSS Prevention"],
            ))

        return threats

    def _analyze_header_quality(self, header_data: dict) -> list[Threat]:
        """Generate threats from header quality analysis (weak configs)."""
        threats = []
        quality = header_data.get("quality", {})

        # HSTS quality issues
        hsts_q = quality.get("hsts", {})
        for issue in hsts_q.get("issues", []):
            severity = "HIGH" if "dangerously short" in issue else "MEDIUM"
            threats.append(Threat(
                category="Transport Security",
                title=f"HSTS Configuration Issue: {issue}",
                description=f"HSTS header is present but misconfigured: {issue}. "
                            "Weak HSTS reduces protection against SSL stripping attacks.",
                severity=severity,
                recommendation="Set HSTS with max-age of at least 1 year (31536000), "
                               "include includeSubDomains and preload directives.",
                references=["OWASP HTTP Strict Transport Security Cheat Sheet"],
            ))

        # CSP quality issues
        csp_q = quality.get("csp", {})
        for issue in csp_q.get("issues", []):
            severity = "HIGH" if "unsafe-eval" in issue or "Wildcard" in issue else "MEDIUM"
            threats.append(Threat(
                category="Injection Protection",
                title=f"CSP Weakness: {issue}",
                description=f"Content-Security-Policy is present but weak: {issue}. "
                            "A permissive CSP may not effectively prevent XSS attacks.",
                severity=severity,
                recommendation="Tighten CSP by removing 'unsafe-inline' and 'unsafe-eval'. "
                               "Use nonces or hashes for inline scripts. Configure report-uri.",
                references=["OWASP CSP Cheat Sheet", "CSP Evaluator"],
            ))

        # Referrer-Policy quality
        ref_q = quality.get("referrer_policy", {})
        for issue in ref_q.get("issues", []):
            threats.append(Threat(
                category="Information Disclosure",
                title=f"Weak Referrer Policy",
                description=f"Referrer-Policy is set but uses a weak value: {ref_q.get('value', '')}. "
                            "Full URLs may be leaked to third-party sites.",
                severity="LOW",
                recommendation="Use 'strict-origin-when-cross-origin' or 'no-referrer' for sensitive pages.",
                references=["MDN Referrer-Policy"],
            ))

        # Permissions-Policy quality
        pp_q = quality.get("permissions_policy", {})
        for issue in pp_q.get("issues", []):
            threats.append(Threat(
                category="Privacy",
                title="Insufficient Permissions-Policy",
                description=f"Permissions-Policy is present but {issue}. "
                            "Sensitive browser features may still be accessible to embedded content.",
                severity="LOW",
                recommendation="Restrict camera, microphone, geolocation, and payment features "
                               "in Permissions-Policy header.",
                references=["W3C Permissions Policy"],
            ))

        return threats

    def _analyze_sri(self, content_data: dict) -> list[Threat]:
        """Generate threats for missing Subresource Integrity on external resources."""
        threats = []
        sri_issues = content_data.get("sri_issues", [])

        if sri_issues:
            # Group by domain for cleaner reporting
            domains = set(i["domain"] for i in sri_issues)
            count = len(sri_issues)
            threats.append(Threat(
                category="Supply Chain Security",
                title=f"Missing Subresource Integrity ({count} external resource{'s' if count > 1 else ''})",
                description=f"Found {count} external script(s)/stylesheet(s) from "
                            f"{', '.join(sorted(domains))} loaded without integrity "
                            f"attributes. If these CDNs are compromised, malicious code "
                            f"could be injected into the application.",
                severity="MEDIUM",
                recommendation="Add integrity attributes (SRI) to all external scripts and "
                               "stylesheets. Use tools like srihash.org to generate hashes.",
                references=["MDN Subresource Integrity", "OWASP Supply Chain Security"],
            ))

        return threats

    def _analyze_inline_scripts(self, content_data: dict) -> list[Threat]:
        """Generate threats from inline script analysis."""
        threats = []
        analysis = content_data.get("inline_script_analysis", {})

        event_handlers = analysis.get("event_handler_count", 0)
        if event_handlers > 10:
            threats.append(Threat(
                category="JavaScript Security",
                title=f"Excessive Inline Event Handlers ({event_handlers} found)",
                description=f"Found {event_handlers} inline event handlers (onclick, onerror, "
                            f"onload, etc.) in the HTML. Inline event handlers bypass CSP and "
                            f"increase the attack surface for XSS.",
                severity="LOW",
                recommendation="Move event handlers to external JavaScript files. "
                               "Use addEventListener() instead of inline handlers.",
                references=["OWASP XSS Prevention"],
            ))

        inline_count = analysis.get("inline_script_count", 0)
        nonce_count = analysis.get("scripts_with_nonce", 0)
        if inline_count > 0 and nonce_count == 0:
            threats.append(Threat(
                category="Injection Protection",
                title=f"Inline Scripts Without Nonces ({inline_count} scripts)",
                description=f"Found {inline_count} inline script(s) without nonce attributes. "
                            f"Without nonces, a strict CSP cannot distinguish legitimate inline "
                            f"scripts from injected ones.",
                severity="LOW",
                recommendation="Add nonce attributes to inline scripts and configure CSP "
                               "to require matching nonces.",
                references=["OWASP CSP Cheat Sheet"],
            ))

        return threats

    def _analyze_external_resources(self, content_data: dict) -> list[Threat]:
        """Analyze third-party resource loading — varies significantly per site."""
        threats = []
        externals = content_data.get("external_resources", [])

        if not externals:
            return threats

        # Count unique external domains
        ext_domains = set(r.get("domain", "") for r in externals)
        script_domains = set(
            r.get("domain", "") for r in externals if r.get("type") == "script"
        )

        if len(script_domains) > 5:
            threats.append(Threat(
                category="Supply Chain Security",
                title=f"Excessive Third-Party Scripts ({len(script_domains)} domains)",
                description=f"The application loads scripts from {len(script_domains)} "
                            f"external domains: {', '.join(sorted(script_domains)[:8])}. "
                            f"Each external script is a potential supply chain attack vector.",
                severity="MEDIUM",
                recommendation="Minimize third-party script dependencies. Host critical "
                               "scripts locally. Use SRI hashes for external scripts.",
                references=["OWASP Third-Party JavaScript Management"],
            ))
        elif len(script_domains) > 2:
            threats.append(Threat(
                category="Supply Chain Security",
                title=f"Multiple Third-Party Scripts ({len(script_domains)} domains)",
                description=f"Scripts loaded from {len(script_domains)} external domains: "
                            f"{', '.join(sorted(script_domains))}. Each is a supply chain risk.",
                severity="LOW",
                recommendation="Review third-party scripts regularly. Use SRI for integrity.",
                references=["OWASP Third-Party JavaScript Management"],
            ))

        if len(ext_domains) > 10:
            threats.append(Threat(
                category="Privacy",
                title=f"High Third-Party Dependency ({len(ext_domains)} external domains)",
                description=f"Resources loaded from {len(ext_domains)} different external "
                            f"domains. High third-party dependency increases data leakage "
                            f"surface and privacy exposure for users.",
                severity="LOW",
                recommendation="Audit all third-party integrations. Consider self-hosting "
                               "critical resources. Implement Permissions-Policy header.",
                references=["DPDP Act 2023 - Third-party Data Sharing"],
            ))

        return threats

    def _analyze_header_coverage(self, header_data: dict) -> list[Threat]:
        """Evaluate overall security header coverage — score varies per site."""
        threats = []
        present = header_data.get("present", {})
        missing = header_data.get("missing", [])

        total = len(present) + len(missing)
        if total == 0:
            return threats

        coverage_pct = len(present) / total * 100
        missing_count = len(missing)

        # These headers are commonly missing; only flag if coverage is poor
        if missing_count >= 7:
            threats.append(Threat(
                category="Security Posture",
                title=f"Very Poor Header Coverage ({len(present)}/{total} headers)",
                description=f"Only {len(present)} of {total} recommended security headers "
                            f"are configured ({coverage_pct:.0f}% coverage). Missing: "
                            f"{', '.join(missing[:5])}{'...' if missing_count > 5 else ''}.",
                severity="HIGH",
                recommendation="Implement missing security headers. Priority: "
                               "HSTS, CSP, X-Content-Type-Options, X-Frame-Options.",
                references=["OWASP Secure Headers Project"],
            ))
        elif missing_count >= 5:
            threats.append(Threat(
                category="Security Posture",
                title=f"Low Header Coverage ({len(present)}/{total} headers)",
                description=f"Only {coverage_pct:.0f}% of recommended security headers "
                            f"are configured. Missing: {', '.join(missing)}.",
                severity="MEDIUM",
                recommendation="Add missing security headers to improve defense-in-depth.",
                references=["OWASP Secure Headers Project"],
            ))

        # Missing Permissions-Policy specifically (for fintech privacy)
        if "Permissions-Policy" in missing:
            threats.append(Threat(
                category="Privacy",
                title="Missing Permissions-Policy Header",
                description="No Permissions-Policy header. Browser features like camera, "
                            "microphone, geolocation, and payment API access are unrestricted "
                            "for embedded third-party content.",
                severity="MEDIUM",
                recommendation="Add Permissions-Policy to restrict sensitive browser APIs: "
                               "camera=(), microphone=(), geolocation=(), payment=(self).",
                references=["W3C Permissions Policy", "DPDP Act 2023"],
            ))

        return threats

    def _analyze_cookie_security(self, header_data: dict) -> list[Threat]:
        """Detailed cookie analysis — counts and specific flag issues vary per site."""
        threats = []
        cookie_issues = header_data.get("cookie_issues", [])

        if not cookie_issues:
            return threats

        # Count specific flag types missing
        insecure_count = 0
        no_httponly_count = 0
        no_samesite_count = 0

        for ci in cookie_issues:
            for iss in ci.get("issues", []):
                if "Secure" in iss:
                    insecure_count += 1
                if "HttpOnly" in iss:
                    no_httponly_count += 1
                if "SameSite" in iss:
                    no_samesite_count += 1

        total_cookies = len(cookie_issues)

        if insecure_count > 0:
            threats.append(Threat(
                category="Session Security",
                title=f"Cookies Without Secure Flag ({insecure_count} of {total_cookies})",
                description=f"{insecure_count} cookie(s) lack the Secure flag. These cookies "
                            f"can be transmitted over unencrypted HTTP, exposing session tokens "
                            f"and user data to network eavesdroppers.",
                severity="HIGH",
                recommendation="Add the Secure flag to all cookies, especially session cookies.",
                references=["OWASP Session Management Cheat Sheet"],
            ))

        if no_httponly_count > 0:
            threats.append(Threat(
                category="Session Security",
                title=f"Cookies Without HttpOnly ({no_httponly_count} of {total_cookies})",
                description=f"{no_httponly_count} cookie(s) lack HttpOnly. JavaScript can "
                            f"access these cookies, making them vulnerable to XSS-based "
                            f"session theft.",
                severity="MEDIUM",
                recommendation="Add HttpOnly flag to all session and authentication cookies.",
                references=["OWASP Session Management Cheat Sheet"],
            ))

        if no_samesite_count > 0:
            threats.append(Threat(
                category="Session Security",
                title=f"Cookies Without SameSite ({no_samesite_count} of {total_cookies})",
                description=f"{no_samesite_count} cookie(s) lack SameSite attribute. "
                            f"These are vulnerable to CSRF attacks.",
                severity="MEDIUM",
                recommendation="Set SameSite=Strict or SameSite=Lax on all cookies.",
                references=["OWASP CSRF Prevention"],
            ))

        return threats

    def _analyze_redirect_chain(self, http_data: dict) -> list[Threat]:
        """Analyze redirect behavior — varies per site."""
        threats = []
        chain = http_data.get("redirect_chain", [])

        if len(chain) > 3:
            threats.append(Threat(
                category="Security Posture",
                title=f"Excessive Redirect Chain ({len(chain)} hops)",
                description=f"The URL goes through {len(chain)} redirects before reaching "
                            f"the final page. Long redirect chains can be exploited for "
                            f"open redirect attacks and degrade security analysis.",
                severity="LOW",
                recommendation="Minimize redirects. Ensure no open redirect vulnerabilities.",
                references=["OWASP Unvalidated Redirects"],
            ))

        # Check for mixed-scheme redirects (HTTPS → HTTP at any point)
        for i, redirect_url in enumerate(chain):
            if redirect_url.startswith("http://") and i > 0:
                prev_url = chain[i - 1] if i > 0 else ""
                if prev_url.startswith("https://"):
                    threats.append(Threat(
                        category="Transport Security",
                        title="HTTPS to HTTP Downgrade in Redirect Chain",
                        description=f"Redirect chain includes a downgrade from HTTPS to HTTP: "
                                    f"{redirect_url}. This exposes data during the redirect.",
                        severity="HIGH",
                        recommendation="Ensure all redirects stay on HTTPS throughout the chain.",
                        references=["OWASP Transport Layer Security"],
                    ))
                    break

        return threats

    def _analyze_certificate_strength(self, ssl_data: dict) -> list[Threat]:
        """Analyze certificate details — issuer, expiry, SANs vary per site."""
        threats = []
        cert = ssl_data.get("certificate", {})

        if not cert:
            return threats

        # Certificate nearing expiry (30-90 days)
        days_left = cert.get("days_until_expiry")
        if days_left is not None:
            if 0 < days_left <= 30:
                threats.append(Threat(
                    category="Encryption",
                    title=f"Certificate Expiring Soon ({days_left} days)",
                    description=f"SSL certificate expires in {days_left} days. "
                                f"Expired certificates cause browser warnings and break "
                                f"user trust for fintech applications.",
                    severity="HIGH",
                    recommendation="Renew the certificate immediately. Set up automated renewal.",
                    references=["RBI Cyber Security Framework"],
                ))
            elif 30 < days_left <= 90:
                threats.append(Threat(
                    category="Encryption",
                    title=f"Certificate Expiry Warning ({days_left} days left)",
                    description=f"SSL certificate expires in {days_left} days. Plan renewal.",
                    severity="LOW",
                    recommendation="Schedule certificate renewal before expiry.",
                    references=[],
                ))

        # Wildcard certificate check
        san_list = cert.get("san", [])
        wildcards = [s for s in san_list if s.startswith("*.")]
        if wildcards:
            threats.append(Threat(
                category="Encryption",
                title="Wildcard SSL Certificate in Use",
                description=f"Certificate uses wildcard domain(s): {', '.join(wildcards)}. "
                            f"If the private key is compromised, all subdomains are affected.",
                severity="LOW",
                recommendation="Consider using specific certificates per subdomain for "
                               "critical fintech services.",
                references=["NIST SP 800-52"],
            ))

        # Cipher suite strength
        cipher = ssl_data.get("cipher_suite", "")
        if cipher:
            weak_ciphers = ("RC4", "DES", "3DES", "MD5", "SHA1")
            for wc in weak_ciphers:
                if wc in cipher.upper():
                    threats.append(Threat(
                        category="Encryption",
                        title=f"Weak Cipher Suite: {cipher}",
                        description=f"The server negotiated cipher suite '{cipher}' which "
                                    f"uses {wc}. This is considered cryptographically weak.",
                        severity="HIGH",
                        recommendation="Configure the server to use strong cipher suites only "
                                       "(AES-GCM, ChaCha20-Poly1305).",
                        references=["PCI DSS v4.0 Requirement 4"],
                    ))
                    break

        return threats
