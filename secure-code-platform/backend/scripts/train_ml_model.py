"""
Trains Engine 3's ML vulnerability classifier.

Run once with `python scripts/train_ml_model.py` (also runs automatically,
on first use, if the artifacts are missing — see `MLEngine._ensure_model`).

Approach: TF-IDF over code token n-grams + Logistic Regression. This is a
deliberately lightweight, fast, explainable model appropriate for a college
project — it is trained here on a programmatically generated but realistic
labeled dataset (vulnerable snippet / hardened-equivalent pairs across the
same CWE categories Engine 1 checks), so the three engines genuinely
disagree or agree based on real pattern differences rather than being
hand-wired to the same answer.

Swap in a larger real-world dataset (e.g. Devign, Big-Vul, CodeXGLUE
defect-detection) by replacing `build_dataset()` — the rest of the pipeline
is unchanged.
"""
import random
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

ARTIFACT_DIR = Path(__file__).resolve().parent.parent / "ml_artifacts"

# (vulnerable snippet, secure snippet) template pairs, one set of variable
# names substituted in to multiply the dataset without hand-writing
# thousands of lines.
_PAIRS = [
    ("cursor.execute(f\"SELECT * FROM <<TABLE>> WHERE id = <<VAR>>\")",
     "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (<<VAR>>,))"),
    ("query = \"SELECT * FROM accounts WHERE user = '\" + <<VAR>> + \"'\"",
     "query = \"SELECT * FROM accounts WHERE user = %s\"\ncursor.execute(query, (<<VAR>>,))"),
    ("os.system(\"ping \" + <<VAR>>)",
     "subprocess.run([\"ping\", \"-c\", \"4\", <<VAR>>], shell=False, check=True)"),
    ("subprocess.run(<<VAR>>, shell=True)",
     "subprocess.run(<<VAR>>.split(), shell=False)"),
    ("eval(<<VAR>>)",
     "ast.literal_eval(<<VAR>>)"),
    ("exec(user_supplied_code)",
     "result = run_in_sandbox(user_supplied_code)"),
    ("el.innerHTML = <<VAR>>;",
     "el.textContent = <<VAR>>;"),
    ("document.write(<<VAR>>);",
     "document.body.appendChild(sanitize(<<VAR>>));"),
    ("API_KEY = \"sk-live-aBcD1234EfGh5678\"",
     "API_KEY = os.environ[\"API_KEY\"]"),
    ("password = \"SuperSecret123!\"",
     "password = os.environ.get(\"DB_PASSWORD\")"),
    ("hashlib.md5(<<VAR>>.encode()).hexdigest()",
     "bcrypt.hashpw(<<VAR>>.encode(), bcrypt.gensalt())"),
    ("hashlib.sha1(password.encode()).hexdigest()",
     "from passlib.hash import argon2\nargon2.hash(password)"),
    ("pickle.loads(<<VAR>>)",
     "json.loads(<<VAR>>)"),
    ("yaml.load(<<VAR>>)",
     "yaml.safe_load(<<VAR>>)"),
    ("open(os.path.join(base_dir, <<VAR>>))",
     "safe = (base_dir / <<VAR>>).resolve()\nopen(safe) if safe.is_relative_to(base_dir) else None"),
    ("requests.get(<<VAR>>)",
     "requests.get(<<VAR>>) if is_allowlisted(urlparse(<<VAR>>).hostname) else None"),
    ("token = str(random.randint(100000, 999999))",
     "token = secrets.token_urlsafe(32)"),
    ("session_id = random.random()",
     "session_id = secrets.token_hex(16)"),
    ("etree.parse(<<VAR>>)",
     "etree.parse(<<VAR>>, etree.XMLParser(resolve_entities=False))"),
    ("@app.delete(\"/scans/{id}\")\ndef delete_scan(id: str):\n    db.delete(id)",
     "@app.delete(\"/scans/{id}\")\ndef delete_scan(id: str, user: User = Depends(get_current_user)):\n    db.delete_owned(id, user.id)"),
]

_VAR_NAMES = ["user_id", "request.args.get('id')", "input_data", "filename", "user_input", "req.body.q", "name", "search_term"]
_TABLES = ["users", "orders", "accounts", "sessions", "products"]

# Benign, security-irrelevant code that should be classified SECURE — without
# these the model would just learn "any code = vulnerable".
_NEUTRAL_SNIPPETS = [
    "def add(a, b):\n    return a + b",
    "class User:\n    def __init__(self, name):\n        self.name = name",
    "for item in items:\n    print(item)",
    "const sum = (a, b) => a + b;",
    "function greet(name) {\n  return `Hello, ${name}`;\n}",
    "list.sort(key=lambda x: x.created_at)",
    "df = pd.read_csv('data.csv')\ndf.describe()",
    "@app.get('/health')\ndef health():\n    return {'status': 'ok'}",
    "logger.info('Processing started')",
    "result = [x * 2 for x in range(10)]",
    "with open('config.json') as f:\n    config = json.load(f)",
    "response = requests.get('https://api.github.com/repos/anthropics/claude')",
    "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    "token = secrets.token_urlsafe(32)",
    "el.textContent = userInput;",
]


def build_dataset() -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []  # 1 = vulnerable, 0 = secure

    for vuln_tpl, secure_tpl in _PAIRS:
        for _ in range(8):  # multiply each template with random variable substitutions
            var = random.choice(_VAR_NAMES)
            table = random.choice(_TABLES)
            texts.append(vuln_tpl.replace('<<VAR>>', var).replace('<<TABLE>>', table))
            labels.append(1)
            texts.append(secure_tpl.replace('<<VAR>>', var).replace('<<TABLE>>', table))
            labels.append(0)

    for snippet in _NEUTRAL_SNIPPETS:
        for _ in range(4):
            texts.append(snippet)
            labels.append(0)

    return texts, labels


def train() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    texts, labels = build_dataset()

    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    vectorizer = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(2, 5), max_features=4000, sublinear_tf=True
    )
    x_train_vec = vectorizer.fit_transform(x_train)
    x_test_vec = vectorizer.transform(x_test)

    model = LogisticRegression(max_iter=1000, C=2.0, class_weight="balanced")
    model.fit(x_train_vec, y_train)

    preds = model.predict(x_test_vec)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    print(f"Trained on {len(x_train)} samples, validated on {len(x_test)} — accuracy={acc:.3f} f1={f1:.3f}")

    joblib.dump(model, ARTIFACT_DIR / "vuln_classifier.joblib")
    joblib.dump(vectorizer, ARTIFACT_DIR / "vectorizer.joblib")
    print(f"Artifacts written to {ARTIFACT_DIR}")


if __name__ == "__main__":
    train()
