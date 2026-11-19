"""
HeyJournal — Quiz Schema Integrity, Scoring Engine & Frontend Contract Test Suite
Validates all drop-in quizzes in `quizzes/*.json`, executes `public/quiz-engine.js`
scoring scenarios, checks JS syntax across all frontend ES modules, and enforces
asset cache-busting + strict CSP invariants.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import unittest
from html.parser import HTMLParser

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
QUIZZES_DIR = os.path.join(BASE_DIR, "quizzes")


def find_js_runner():
    node = shutil.which("node")
    if node:
        return "node", node
    for cand in (
        "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc",
        shutil.which("jsc"),
    ):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return "jsc", cand
    return None, None


def run_es_module(js_code):
    engine, binary = find_js_runner()
    if not engine:
        raise unittest.SkipTest("No JS engine installed")
    cmd = [binary, "--input-type=module", "-e", js_code] if engine == "node" else [binary, "-m", "-e", js_code]
    res = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        raise AssertionError(f"{engine} failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
    return res.stdout.strip()


class InlineScriptFinder(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline_scripts = []
        self._in_inline_script = False
        self._buf = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attr_dict = dict(attrs)
            if "src" not in attr_dict:
                self._in_inline_script = True
                self._buf = []

    def handle_data(self, data):
        if self._in_inline_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_inline_script:
            self._in_inline_script = False
            content = "".join(self._buf).strip()
            if content:
                self.inline_scripts.append(content)


class TestQuizLibraryAndScoringEngine(unittest.TestCase):
    def test_all_quiz_json_files_match_schema(self):
        quiz_files = sorted(glob.glob(os.path.join(QUIZZES_DIR, "*.json")))
        self.assertGreaterEqual(len(quiz_files), 13)

        seen_ids = set()
        for qf in quiz_files:
            with open(qf, "r", encoding="utf-8") as fh:
                quiz = json.load(fh)
            for req in ("id", "name", "fullName", "category", "resourceUrl", "questions", "scoring"):
                self.assertIn(req, quiz, f"Missing {req} in {qf}")
            self.assertNotIn(quiz["id"], seen_ids, f"Duplicate quiz id {quiz['id']}")
            seen_ids.add(quiz["id"])
            self.assertTrue(quiz["resourceUrl"].startswith("https://"), f"Non-HTTPS resourceUrl in {qf}")
            self.assertGreater(len(quiz["questions"]), 0, f"Empty questions in {qf}")

            q_ids = set()
            for q in quiz["questions"]:
                self.assertIn("id", q)
                self.assertIn("text", q)
                self.assertNotIn(q["id"], q_ids, f"Duplicate question id {q['id']} in {qf}")
                q_ids.add(q["id"])
                has_opts = (isinstance(q.get("options"), list) and len(q["options"]) > 0) or (
                    isinstance(quiz.get("answerScale"), list) and len(quiz["answerScale"]) > 0
                )
                self.assertTrue(has_opts, f"Question {q['id']} in {qf} has no answer options")

            scoring = quiz["scoring"]
            self.assertIn("min", scoring)
            self.assertIn("max", scoring)
            self.assertIn("formulaDescription", scoring)
            self.assertIn("severityBands", scoring)
            self.assertGreater(len(scoring["severityBands"]), 0)

    def test_quiz_scoring_engine_math_across_all_modes(self):
        quizzes_by_id = {}
        for qf in glob.glob(os.path.join(QUIZZES_DIR, "*.json")):
            with open(qf, "r", encoding="utf-8") as fh:
                q = json.load(fh)
            quizzes_by_id[q["id"]] = q

        payload_json = json.dumps(quizzes_by_id)
        js = f"""
        import {{ scoreQuiz }} from "./public/quiz-engine.js";
        const quizzes = {payload_json};

        // 1. PHQ-9: score 12 (Moderate) with Q9 = 2 triggering safety flag
        const phqAns = {{ q1:2, q2:2, q3:1, q4:1, q5:1, q6:1, q7:1, q8:1, q9:2 }};
        const phqRes = scoreQuiz(quizzes["phq-9"], phqAns);

        // 2. PSS-10: all 4s -> 6 normal items * 4 = 24, 4 reversed items (4-4=0) = 0 -> total 24 (Moderate Stress)
        const pssAns = {{}};
        for (let i = 1; i <= 10; i++) pssAns["q" + i] = 4;
        const pssRes = scoreQuiz(quizzes["pss-10"], pssAns);

        // 3. WHO-5: all 5s -> 25 * 4 = 100% (High Well-Being, higherIsWorse: false)
        const whoAns = {{ q1:5, q2:5, q3:5, q4:5, q5:5 }};
        const whoRes = scoreQuiz(quizzes["who-5"], whoAns);

        // 4. WHODAS 2.0 12-item: all 2s -> raw 24 / 48 = 50% (Severe)
        const whodasAns = {{}};
        for (let i = 1; i <= 12; i++) whodasAns["s" + i] = 2;
        const whodasRes = scoreQuiz(quizzes["whodas-2-12"], whodasAns);

        // 5. DASS-21: all 1s -> 21 * 2 = 42 total; each 7-item subscale = 7 * 2 = 14
        const dassAns = {{}};
        for (let i = 1; i <= 21; i++) dassAns["q" + i] = 1;
        const dassRes = scoreQuiz(quizzes["dass-21"], dassAns);

        // 6. MDQ: Q1..Q13 = 1 (13), Q14 = 1, Q15 = 3 -> excludeFromTotal keeps score at 13
        const mdqAns = {{}};
        for (let i = 1; i <= 14; i++) mdqAns["q" + i] = 1;
        mdqAns["q15"] = 3;
        const mdqRes = scoreQuiz(quizzes["mdq"], mdqAns);

        const out = JSON.stringify({{ phqRes, pssRes, whoRes, whodasRes, dassRes, mdqRes }});
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module(js))

        self.assertEqual(out["phqRes"]["score"], 12)
        self.assertEqual(out["phqRes"]["band"]["label"], "Moderate")
        self.assertEqual(len(out["phqRes"]["safetyFlags"]), 1)

        self.assertEqual(out["pssRes"]["score"], 24)
        self.assertEqual(out["pssRes"]["band"]["label"], "Moderate Stress")

        self.assertEqual(out["whoRes"]["score"], 100)
        self.assertFalse(out["whoRes"]["higherIsWorse"])
        self.assertEqual(out["whoRes"]["band"]["label"], "High Well-Being")

        self.assertEqual(out["whodasRes"]["score"], 50)
        self.assertEqual(len(out["whodasRes"]["subscales"]), 6)

        self.assertEqual(out["dassRes"]["score"], 42)
        for sub in out["dassRes"]["subscales"]:
            self.assertEqual(sub["score"], 14)

        self.assertEqual(out["mdqRes"]["score"], 13)
        self.assertTrue(out["mdqRes"]["isComplete"])


class TestFrontendSyntaxAndContracts(unittest.TestCase):
    def test_all_public_js_files_have_valid_syntax(self):
        engine, binary = find_js_runner()
        if not engine:
            self.skipTest("No JS engine installed")
        js_files = sorted(glob.glob(os.path.join(PUBLIC_DIR, "*.js")))
        self.assertGreaterEqual(len(js_files), 7)

        for fpath in js_files:
            if engine == "node":
                res = subprocess.run([binary, "--check", fpath], capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, f"Syntax error in {fpath}: {res.stderr}")
            else:
                rel = "./" + os.path.relpath(fpath, BASE_DIR)
                if os.path.basename(fpath) in ("sw.js", "theme-boot.js"):
                    # Classic script syntax check
                    with open(fpath, "r", encoding="utf-8") as fh:
                        src = fh.read()
                    res = subprocess.run(
                        [binary, "-e", "function __check__(){\n" + src + "\n}"],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotIn("SyntaxError", res.stderr, f"Syntax error in {fpath}: {res.stderr}")
                else:
                    # ES module import syntax check
                    script = f"""
                    globalThis.window = globalThis;
                    globalThis.document = {{
                      addEventListener: () => {{}},
                      getElementById: () => null,
                      querySelector: () => null,
                      querySelectorAll: () => [],
                      documentElement: {{ setAttribute: () => {{}}, style: {{ setProperty: () => {{}} }} }},
                      head: {{ appendChild: () => {{}} }},
                      createElement: () => ({{ setAttribute: () => {{}}, style: {{}}, appendChild: () => {{}} }}),
                    }};
                    globalThis.navigator = {{}};
                    globalThis.location = {{ origin: "http://localhost:8080", href: "http://localhost:8080" }};
                    globalThis.localStorage = {{ getItem: () => null, setItem: () => {{}}, removeItem: () => {{}} }};
                    globalThis.sessionStorage = {{ getItem: () => null, setItem: () => {{}}, removeItem: () => {{}} }};
                    globalThis.fetch = () => Promise.resolve({{ ok: false }});
                    import("{rel}").catch((err) => {{
                      if (err && err.name === "SyntaxError") print("SYNTAX_ERROR:" + err.message);
                    }});
                    """
                    res = subprocess.run([binary, "-m", "-e", script], cwd=BASE_DIR, capture_output=True, text=True)
                    self.assertNotIn("SYNTAX_ERROR", res.stdout, f"Syntax error in {fpath}: {res.stdout}")
                    self.assertNotIn("SyntaxError", res.stderr, f"Syntax error in {fpath}: {res.stderr}")

    def test_index_html_has_zero_inline_scripts_for_strict_csp(self):
        with open(os.path.join(PUBLIC_DIR, "index.html"), "r", encoding="utf-8") as fh:
            html = fh.read()
        parser = InlineScriptFinder()
        parser.feed(html)
        self.assertEqual(parser.inline_scripts, [], "index.html must not contain inline scripts (strict CSP)")

    def test_asset_versions_synchronized_and_sw_excludes_api(self):
        with open(os.path.join(PUBLIC_DIR, "theme-engine.js"), "r", encoding="utf-8") as fh:
            m = re.search(r'ASSET_VERSION\s*=\s*"(\d+)"', fh.read())
        self.assertIsNotNone(m)
        ver = m.group(1)

        with open(os.path.join(PUBLIC_DIR, "sw.js"), "r", encoding="utf-8") as fh:
            sw_text = fh.read()
        self.assertIn(f'CACHE_NAME = "heyjournal-v{ver}"', sw_text)
        self.assertIn('startsWith("/api/")', sw_text)

        for fname in ("index.html", "theme-boot.js", "app.js", "manifest.json"):
            with open(os.path.join(PUBLIC_DIR, fname), "r", encoding="utf-8") as fh:
                content = fh.read()
            found = set(re.findall(r"\?v=(\d+)", content))
            self.assertEqual(found, {ver}, f"Version mismatch in {fname}: found {found}, expected {ver}")


if __name__ == "__main__":
    unittest.main()
