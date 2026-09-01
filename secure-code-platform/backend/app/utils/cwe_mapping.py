"""
Shared vulnerability knowledge base.

CodeQL, the AI auditor, and the ML classifier all need to translate a raw
finding into the same normalized vocabulary (CWE id, OWASP Top 10 2021
category, severity, a generic suggested fix). Centralizing that mapping here
means all three engines describe the "same" vulnerability class identically,
which is what lets the verdict engine and results UI merge/compare findings
across engines in the first place.
"""

CWE_OWASP_MAP: dict[str, dict] = {
    "CWE-89": {
        "title": "SQL Injection",
        "owasp": "A03:2021 - Injection",
        "severity": "critical",
        "risk_score": 9.8,
        "fix": "Use parameterized queries / prepared statements instead of building SQL with string "
               "concatenation or f-strings. Never interpolate user input directly into a query string.",
        "secure_example": (
            "# Vulnerable\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
            "# Secure\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
        ),
    },
    "CWE-78": {
        "title": "OS Command Injection",
        "owasp": "A03:2021 - Injection",
        "severity": "critical",
        "risk_score": 9.6,
        "fix": "Avoid shell=True and string-built shell commands. Pass arguments as a list to subprocess "
               "and validate/allowlist any user-controlled input used in the command.",
        "secure_example": (
            "# Vulnerable\n"
            "os.system(f\"ping {host}\")\n\n"
            "# Secure\n"
            "subprocess.run([\"ping\", \"-c\", \"4\", host], shell=False, check=True)"
        ),
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 - Injection",
        "severity": "high",
        "risk_score": 8.2,
        "fix": "Escape/encode all user-controlled output before rendering it as HTML, and prefer "
               "templating engines with autoescaping enabled. Never use innerHTML with raw user input.",
        "secure_example": (
            "// Vulnerable\n"
            "el.innerHTML = userInput;\n\n"
            "// Secure\n"
            "el.textContent = userInput; // or sanitize with DOMPurify before innerHTML"
        ),
    },
    "CWE-798": {
        "title": "Hardcoded Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "high",
        "risk_score": 8.0,
        "fix": "Move secrets out of source code into environment variables or a secrets manager "
               "(e.g. AWS Secrets Manager, HashiCorp Vault). Rotate any credential that was committed.",
        "secure_example": (
            "# Vulnerable\n"
            "API_KEY = \"sk-live-abc123...\"\n\n"
            "# Secure\n"
            "import os\nAPI_KEY = os.environ[\"API_KEY\"]"
        ),
    },
    "CWE-327": {
        "title": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "medium",
        "risk_score": 6.5,
        "fix": "Replace MD5/SHA1/DES with a modern algorithm: SHA-256+ for hashing, bcrypt/argon2 for "
               "passwords, AES-256-GCM for symmetric encryption.",
        "secure_example": (
            "# Vulnerable\n"
            "hashlib.md5(password.encode()).hexdigest()\n\n"
            "# Secure\n"
            "from passlib.hash import bcrypt\nbcrypt.hash(password)"
        ),
    },
    "CWE-502": {
        "title": "Deserialization of Untrusted Data",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "severity": "critical",
        "risk_score": 9.1,
        "fix": "Never unpickle/deserialize data from an untrusted source. Use a safe format like JSON "
               "and validate the schema after parsing.",
        "secure_example": (
            "# Vulnerable\n"
            "data = pickle.loads(request_body)\n\n"
            "# Secure\n"
            "data = json.loads(request_body)  # then validate with a schema (e.g. Pydantic)"
        ),
    },
    "CWE-22": {
        "title": "Path Traversal",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "high",
        "risk_score": 7.5,
        "fix": "Resolve and validate the final path stays within an allowed base directory before "
               "opening it; reject paths containing '..' segments.",
        "secure_example": (
            "# Vulnerable\n"
            "open(os.path.join(base_dir, user_filename))\n\n"
            "# Secure\n"
            "safe_path = (base_dir / user_filename).resolve()\n"
            "if not str(safe_path).startswith(str(base_dir.resolve())):\n"
            "    raise ValueError(\"Invalid path\")"
        ),
    },
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF)",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "severity": "high",
        "risk_score": 8.6,
        "fix": "Validate and allowlist destination hosts before making server-side requests to a "
               "user-supplied URL; block requests to internal/private IP ranges.",
        "secure_example": (
            "# Vulnerable\n"
            "requests.get(user_supplied_url)\n\n"
            "# Secure\n"
            "if not is_allowlisted_host(urlparse(user_supplied_url).hostname):\n"
            "    raise ValueError(\"Host not allowed\")\n"
            "requests.get(user_supplied_url, timeout=5)"
        ),
    },
    "CWE-862": {
        "title": "Missing Authorization",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "high",
        "risk_score": 7.8,
        "fix": "Add an explicit authorization check (ownership / role check) before performing the "
               "action, rather than relying on the resource id being hard to guess.",
        "secure_example": (
            "# Vulnerable\n"
            "@app.delete(\"/scans/{scan_id}\")\n"
            "def delete_scan(scan_id: str): ...\n\n"
            "# Secure\n"
            "@app.delete(\"/scans/{scan_id}\")\n"
            "def delete_scan(scan_id: str, user: User = Depends(get_current_user)):\n"
            "    scan = get_owned_scan_or_404(scan_id, user.id)"
        ),
    },
    "CWE-95": {
        "title": "Code Injection (eval/exec)",
        "owasp": "A03:2021 - Injection",
        "severity": "critical",
        "risk_score": 9.4,
        "fix": "Never call eval()/exec() on data that originates from user input. Use a safe parser "
               "(ast.literal_eval for literals, a real expression evaluator library for formulas).",
        "secure_example": (
            "# Vulnerable\n"
            "eval(user_expression)\n\n"
            "# Secure\n"
            "import ast\nast.literal_eval(user_expression)  # only literals, never arbitrary code"
        ),
    },
    "CWE-330": {
        "title": "Use of Insufficiently Random Values",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "medium",
        "risk_score": 5.9,
        "fix": "Use the `secrets` module (Python) or `crypto.randomBytes` (Node) for tokens, session "
               "ids, and password-reset codes — never `random`/`Math.random`.",
        "secure_example": (
            "# Vulnerable\n"
            "token = str(random.randint(100000, 999999))\n\n"
            "# Secure\n"
            "import secrets\ntoken = secrets.token_urlsafe(32)"
        ),
    },
    "CWE-611": {
        "title": "XML External Entity (XXE) Injection",
        "owasp": "A05:2021 - Security Misconfiguration",
        "severity": "high",
        "risk_score": 8.0,
        "fix": "Disable external entity resolution and DTD processing in the XML parser before "
               "parsing any untrusted document.",
        "secure_example": (
            "# Vulnerable\n"
            "etree.parse(untrusted_xml)\n\n"
            "# Secure\n"
            "parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
            "etree.parse(untrusted_xml, parser)"
        ),
    },
}


def lookup(cwe_id: str) -> dict:
    return CWE_OWASP_MAP.get(cwe_id, {
        "title": "Potential Security Issue",
        "owasp": "A04:2021 - Insecure Design",
        "severity": "medium",
        "risk_score": 5.0,
        "fix": "Review this code path for adherence to secure coding best practices.",
        "secure_example": "",
    })


def detect_language(filename: str) -> str:
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
        ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
        ".c": "c", ".cpp": "cpp", ".cs": "csharp", ".html": "html", ".sql": "sql",
    }
    lower = filename.lower()
    for ext, lang in ext_map.items():
        if lower.endswith(ext):
            return lang
    return "unknown"
