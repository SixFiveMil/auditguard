"""
AuditGuard Tech-Stack Tailored Remediation Code Generator.
Generates copy-pasteable, production-ready configuration and code patches
for developers and engineering teams based on detected vulnerabilities and tech stacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class RemediationSnippet:
    """Represents a concrete developer code patch."""
    language: str
    code: str
    target_framework: str
    description: str


class RemediationSnippetGenerator:
    """Maps diagnostic findings and tech markers to framework-specific remediation snippets."""

    @classmethod
    def get_snippet(
        cls,
        cwe_id: str,
        title: str = "",
        tech_markers: Optional[List[str]] = None,
    ) -> Optional[RemediationSnippet]:
        """Generates the most relevant remediation code snippet."""
        cwe = (cwe_id or "").lower().strip()
        title_lower = (title or "").lower()
        tech_list = [t.lower() for t in (tech_markers or [])]

        is_nginx = any("nginx" in t for t in tech_list)
        is_angular = any("angular" in t for t in tech_list)
        is_node = any(t in tech_list for t in ("express", "node", "nodejs")) or True  # default to modern JS/Node

        # 1. CORS Misconfiguration (CWE-942)
        if "cwe-942" in cwe or "cors" in title_lower:
            if is_nginx:
                code = (
                    "# Restrict CORS headers to authorized origins in nginx.conf\n"
                    "map $http_origin $cors_origin {\n"
                    "    default \"\";\n"
                    "    \"~^https?://(app|trusted)\\.example\\.com$\" \"$http_origin\";\n"
                    "}\n\n"
                    "server {\n"
                    "    add_header Access-Control-Allow-Origin $cors_origin always;\n"
                    "    add_header Access-Control-Allow-Credentials \"true\" always;\n"
                    "    add_header Access-Control-Allow-Methods \"GET, POST, OPTIONS\" always;\n"
                    "}"
                )
                return RemediationSnippet(
                    language="nginx",
                    code=code,
                    target_framework="Nginx",
                    description="Configure an explicit origin map rather than wildcard reflection.",
                )
            else:
                code = (
                    "const cors = require('cors');\n\n"
                    "const whitelist = ['https://app.example.com', 'https://trusted.example.com'];\n"
                    "const corsOptions = {\n"
                    "  origin: (origin, callback) => {\n"
                    "    if (!origin || whitelist.indexOf(origin) !== -1) {\n"
                    "      callback(null, true);\n"
                    "    } else {\n"
                    "      callback(new Error('Disallowed by CORS policy'));\n"
                    "    }\n"
                    "  },\n"
                    "  credentials: true,\n"
                    "  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']\n"
                    "};\n\n"
                    "app.use(cors(corsOptions));"
                )
                return RemediationSnippet(
                    language="javascript",
                    code=code,
                    target_framework="Express / Node.js",
                    description="Use explicit origin whitelist filtering with the cors package.",
                )

        # 2. Sensitive Cache Hygiene (CWE-524, CWE-525)
        if "cwe-524" in cwe or "cwe-525" in cwe or "cache" in title_lower:
            if is_nginx:
                code = (
                    "# Prevent caching of sensitive and authenticated routes\n"
                    "location ~* ^/(admin|accounting|profile|api)/ {\n"
                    "    add_header Cache-Control \"no-store, no-cache, must-revalidate, max-age=0\" always;\n"
                    "    add_header Pragma \"no-cache\" always;\n"
                    "    expires -1;\n"
                    "}"
                )
                return RemediationSnippet(
                    language="nginx",
                    code=code,
                    target_framework="Nginx",
                    description="Enforce no-store cache control on sensitive path blocks.",
                )
            else:
                code = (
                    "// Middleware enforcing strict no-store caching on sensitive endpoints\n"
                    "app.use('/admin', (req, res, next) => {\n"
                    "  res.set({\n"
                    "    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',\n"
                    "    'Pragma': 'no-cache',\n"
                    "    'Expires': '0'\n"
                    "  });\n"
                    "  next();\n"
                    "});"
                )
                return RemediationSnippet(
                    language="javascript",
                    code=code,
                    target_framework="Express / Node.js",
                    description="Set HTTP no-store headers on sensitive routes to prevent intermediate and disk caching.",
                )

        # 3. Content Security Policy & Clickjacking (CWE-1021)
        if "cwe-1021" in cwe or "csp" in title_lower or "clickjacking" in title_lower:
            if is_nginx:
                code = (
                    "# Enforce restrictive CSP and anti-clickjacking headers\n"
                    "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none'; object-src 'none';\" always;\n"
                    "add_header X-Frame-Options \"DENY\" always;\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;"
                )
                return RemediationSnippet(
                    language="nginx",
                    code=code,
                    target_framework="Nginx",
                    description="Add Content-Security-Policy and X-Frame-Options server response directives.",
                )
            else:
                code = (
                    "const helmet = require('helmet');\n\n"
                    "app.use(helmet.contentSecurityPolicy({\n"
                    "  directives: {\n"
                    "    defaultSrc: [\"'self'\"],\n"
                    "    scriptSrc: [\"'self'\"],\n"
                    "    frameAncestors: [\"'none'\"],\n"
                    "    objectSrc: [\"'none'\"]\n"
                    "  }\n"
                    "}));\n"
                    "app.use(helmet.frameguard({ action: 'deny' }));"
                )
                return RemediationSnippet(
                    language="javascript",
                    code=code,
                    target_framework="Express / Helmet",
                    description="Configure Helmet middleware for Content-Security-Policy and Clickjacking prevention.",
                )

        # 4. Broken Access Control / Unauthenticated Admin (CWE-306, CWE-284, CWE-639)
        if "cwe-306" in cwe or "cwe-284" in cwe or "cwe-639" in cwe or "access control" in title_lower:
            if is_angular:
                code = (
                    "import { Injectable } from '@angular/core';\n"
                    "import { CanActivate, Router } from '@angular/router';\n"
                    "import { AuthService } from './auth.service';\n\n"
                    "@Injectable({ providedIn: 'root' })\n"
                    "export class AdminGuard implements CanActivate {\n"
                    "  constructor(private auth: AuthService, private router: Router) {}\n\n"
                    "  canActivate(): boolean {\n"
                    "    if (!this.auth.isAuthenticated() || !this.auth.hasRole('admin')) {\n"
                    "      this.router.navigate(['/login']);\n"
                    "      return false;\n"
                    "    }\n"
                    "    return true;\n"
                    "  }\n"
                    "}"
                )
                return RemediationSnippet(
                    language="typescript",
                    code=code,
                    target_framework="Angular",
                    description="Implement an Angular route guard to block unauthenticated client-side state navigation.",
                )
            else:
                code = (
                    "// Role-based access control (RBAC) guard middleware\n"
                    "function requireAdmin(req, res, next) {\n"
                    "  if (!req.session?.user || req.session.user.role !== 'admin') {\n"
                    "    return res.status(403).json({ error: 'Access forbidden: Admin credentials required' });\n"
                    "  }\n"
                    "  next();\n"
                    "}\n\n"
                    "app.use('/administration', requireAdmin);"
                )
                return RemediationSnippet(
                    language="javascript",
                    code=code,
                    target_framework="Express / Node.js",
                    description="Guard sensitive routes with server-side authentication and role validation middleware.",
                )

        # 5. Dangerous HTTP Methods / Verb Tampering (CWE-650)
        if "cwe-650" in cwe or "verb tampering" in title_lower or "methods" in title_lower:
            code = (
                "// Restrict incoming HTTP verbs to safe whitelist\n"
                "const allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'];\n\n"
                "app.use((req, res, next) => {\n"
                "  if (!allowedMethods.includes(req.method)) {\n"
                "    return res.status(405).set('Allow', allowedMethods.join(', ')).send('Method Not Allowed');\n"
                "  }\n"
                "  next();\n"
                "});"
            )
            return RemediationSnippet(
                language="javascript",
                code=code,
                target_framework="Express / Node.js",
                description="Reject non-permitted HTTP methods (PUT, DELETE) with HTTP 405 Method Not Allowed.",
            )

        # 6. Information Disclosure & Banners (CWE-200, CWE-209, CWE-16)
        if "cwe-200" in cwe or "cwe-209" in cwe or "cwe-16" in cwe or "leak" in title_lower:
            code = (
                "// Disable technology fingerprint headers & generic error handler\n"
                "app.disable('x-powered-by');\n\n"
                "app.use((err, req, res, next) => {\n"
                "  console.error(err); // Log internally\n"
                "  res.status(500).json({ error: 'An unexpected internal error occurred' });\n"
                "});"
            )
            return RemediationSnippet(
                language="javascript",
                code=code,
                target_framework="Express / Node.js",
                description="Disable Express header disclosures and suppress stack traces in production responses.",
            )

        return None
