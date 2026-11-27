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
        self.assertGreaterEqual(len(quiz_files), 22)

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
        js = """
        import { scoreQuiz } from "./public/quiz-engine.js";
        const quizzes = __PAYLOAD__;

        // 1. PHQ-9: score 12 (Moderate) with Q9 = 2 triggering safety flag; Q10 excluded from total
        const phqAns = { q1:2, q2:2, q3:1, q4:1, q5:1, q6:1, q7:1, q8:1, q9:2, q10:3 };
        const phqRes = scoreQuiz(quizzes["phq-9"], phqAns);

        // 2. PSS-10: all 4s -> 6 normal items * 4 = 24, 4 reversed items (4-4=0) = 0 -> total 24 (Moderate Stress)
        const pssAns = {};
        for (let i = 1; i <= 10; i++) pssAns["q" + i] = 4;
        const pssRes = scoreQuiz(quizzes["pss-10"], pssAns);

        // 3. WHO-5: all 5s -> 25 * 4 = 100% (High Well-Being, higherIsWorse: false)
        const whoAns = { q1:5, q2:5, q3:5, q4:5, q5:5 };
        const whoRes = scoreQuiz(quizzes["who-5"], whoAns);

        // 4. WHODAS 2.0 12-item: all 2s -> raw 24 / 48 = 50% (Severe)
        const whodasAns = {};
        for (let i = 1; i <= 12; i++) whodasAns["s" + i] = 2;
        const whodasRes = scoreQuiz(quizzes["whodas-2-12"], whodasAns);

        // 5. DASS-21: all 1s -> 21 * 2 = 42 total; each 7-item subscale = 7 * 2 = 14 -> Moderate (Depression, Anxiety)
        const dassAns = {};
        for (let i = 1; i <= 21; i++) dassAns["q" + i] = 1;
        const dassRes = scoreQuiz(quizzes["dass-21"], dassAns);

        // 5b. DASS-21 single-domain Extreme Depression (28) with 0 Anxiety & 0 Stress -> must NOT report Normal!
        const dassDepOnly = {};
        for (let i = 1; i <= 21; i++) dassDepOnly["q" + i] = 0;
        for (const id of ["q3", "q5", "q10", "q13", "q16", "q17", "q21"]) dassDepOnly[id] = 2;
        const dassDepRes = scoreQuiz(quizzes["dass-21"], dassDepOnly);

        // 6. MDQ: 3-part screeningRule (Positive vs Incomplete vs Negative)
        const mdqPosAns = {};
        for (let i = 1; i <= 14; i++) mdqPosAns["q" + i] = 1;
        mdqPosAns["q15"] = 3;
        const mdqRes = scoreQuiz(quizzes["mdq"], mdqPosAns);

        const mdqPartialAns = { ...mdqPosAns, q14: 0, q15: 0 };
        const mdqPartialRes = scoreQuiz(quizzes["mdq"], mdqPartialAns);

        // 7. ASRS-v1.1 Part A WHO shaded-box thresholdCount (Q1-Q3 >= 2, Q4-Q6 >= 3 -> 4/6 Positive vs 3/6 Negative)
        const asrsPosAns = { q1: 2, q2: 2, q3: 2, q4: 3, q5: 2, q6: 2 };
        const asrsPosRes = scoreQuiz(quizzes["asrs-v1-1"], asrsPosAns);
        const asrsNegAns = { q1: 2, q2: 2, q3: 2, q4: 2, q5: 2, q6: 2 };
        const asrsNegRes = scoreQuiz(quizzes["asrs-v1-1"], asrsNegAns);

        // 8. Mean-scored & percentage-subscale Tier 1 quizzes: BRS, PEG, FSS, CBI, TFEQ-R18, REAP-S, MEDAS, SSS-8, STOP-BANG
        const brsRes = scoreQuiz(quizzes["brs"], { q1: 5, q2: 1, q3: 5, q4: 1, q5: 5, q6: 1 }); // all effective 5 -> 5.0 High Resilience
        const pegRes = scoreQuiz(quizzes["peg"], { q1: 6, q2: 4, q3: 5 }); // mean 5.0 -> Moderate
        const fssAns = {};
        for (let i = 1; i <= 9; i++) fssAns["q" + i] = 5;
        const fssRes = scoreQuiz(quizzes["fss"], fssAns); // mean 5.0 -> High Fatigue

        const cbiAns = {};
        for (let i = 1; i <= 12; i++) cbiAns["q" + i] = 75;
        cbiAns["q13"] = 25; // reversed -> 100 - 25 = 75 -> all items 75 -> 75% High Burnout
        const cbiRes = scoreQuiz(quizzes["cbi"], cbiAns);

        const tfeqAns = {};
        for (let i = 1; i <= 18; i++) tfeqAns["q" + i] = 1;
        tfeqAns["q3"] = 4; tfeqAns["q6"] = 4; tfeqAns["q10"] = 4; // Emotional Eating = 100%, others 0%
        const tfeqRes = scoreQuiz(quizzes["tfeq-r18"], tfeqAns);

        const reapAns = {};
        for (let i = 1; i <= 13; i++) reapAns["q" + i] = 3;
        const reapRes = scoreQuiz(quizzes["reap-s"], reapAns); // 39 -> High Diet Quality

        const medasAns = {};
        for (let i = 1; i <= 14; i++) medasAns["q" + i] = i <= 10 ? 1 : 0;
        const medasRes = scoreQuiz(quizzes["medas"], medasAns); // 10 -> High Adherence

        const sss8Res = scoreQuiz(quizzes["sss-8"], { q1: 2, q2: 2, q3: 1, q4: 1, q5: 0, q6: 0, q7: 2, q8: 2 }); // 10 -> Medium Burden
        const stopBangRes = scoreQuiz(quizzes["stop-bang"], { q1: 1, q2: 1, q3: 1, q4: 0, q5: 0, q6: 1, q7: 0, q8: 1 }); // 5 -> High OSA Risk

        // 9. 1-based percentage custom quiz & empty-string safety flag guard
        const customOneBased = {
          id: "custom-pct",
          name: "Custom",
          answerScale: [{ label: "Low", value: 1 }, { label: "Mid", value: 3 }, { label: "High", value: 5 }],
          questions: [{ id: "q1", text: "One" }, { id: "q2", text: "Two" }],
          scoring: {
            method: "percentage",
            min: 0,
            max: 100,
            severityBands: [{ min: 0, max: 100, label: "OK", level: "low" }],
            safetyFlags: [{ questionId: "q1", minValue: 0, message: "Should not fire on empty string" }]
          }
        };
        const customLow = scoreQuiz(customOneBased, { q1: 1, q2: 1 });
        const customEmpty = scoreQuiz(customOneBased, { q1: "", q2: 5 });

        const out = JSON.stringify({
          phqRes, pssRes, whoRes, whodasRes, dassRes, dassDepRes, mdqRes, mdqPartialRes,
          asrsPosRes, asrsNegRes, brsRes, pegRes, fssRes, cbiRes, tfeqRes, reapRes, medasRes, sss8Res, stopBangRes,
          customLow, customEmpty
        });
        if (typeof print === "function") print(out); else console.log(out);
        """.replace("__PAYLOAD__", payload_json)
        out = json.loads(run_es_module(js))

        self.assertEqual(out["phqRes"]["score"], 12)
        self.assertEqual(out["phqRes"]["band"]["label"], "Moderate")
        self.assertEqual(len(out["phqRes"]["safetyFlags"]), 1)
        self.assertTrue(out["phqRes"]["isComplete"])

        self.assertEqual(out["pssRes"]["score"], 24)
        self.assertEqual(out["pssRes"]["band"]["label"], "Moderate Stress")

        self.assertEqual(out["whoRes"]["score"], 100)
        self.assertFalse(out["whoRes"]["higherIsWorse"])
        self.assertEqual(out["whoRes"]["band"]["label"], "High Well-Being")

        self.assertEqual(out["whodasRes"]["score"], 50)
        self.assertEqual(len(out["whodasRes"]["subscales"]), 6)

        self.assertEqual(out["dassRes"]["score"], 42)
        self.assertEqual(out["dassRes"]["band"]["level"], "moderate")
        for sub in out["dassRes"]["subscales"]:
            self.assertEqual(sub["score"], 14)

        self.assertEqual(out["dassDepRes"]["score"], 28)
        self.assertEqual(out["dassDepRes"]["band"]["level"], "severe")
        self.assertIn("Depression", out["dassDepRes"]["band"]["label"])
        self.assertEqual(len(out["dassDepRes"]["safetyFlags"]), 1)

        self.assertEqual(out["mdqRes"]["score"], 13)
        self.assertTrue(out["mdqRes"]["isComplete"])
        self.assertEqual(out["mdqRes"]["band"]["label"], "Positive Screen")
        self.assertTrue(out["mdqRes"]["screening"]["positive"])
        self.assertEqual(out["mdqPartialRes"]["band"]["label"], "Negative Screen (Criteria Incomplete)")
        self.assertFalse(out["mdqPartialRes"]["screening"]["positive"])

        asrs_pos_part_a = next(s for s in out["asrsPosRes"]["subscales"] if s["id"] == "part-a")
        asrs_neg_part_a = next(s for s in out["asrsNegRes"]["subscales"] if s["id"] == "part-a")
        self.assertEqual(asrs_pos_part_a["score"], 4)
        self.assertEqual(asrs_pos_part_a["band"]["level"], "high")
        self.assertEqual(asrs_neg_part_a["score"], 3)
        self.assertEqual(asrs_neg_part_a["band"]["level"], "low")

        self.assertEqual(out["brsRes"]["score"], 5)
        self.assertFalse(out["brsRes"]["higherIsWorse"])
        self.assertEqual(out["brsRes"]["band"]["label"], "High Resilience")

        self.assertEqual(out["pegRes"]["score"], 5)
        self.assertEqual(out["pegRes"]["band"]["label"], "Moderate")

        self.assertEqual(out["fssRes"]["score"], 5)
        self.assertEqual(out["fssRes"]["band"]["label"], "High Fatigue")

        self.assertEqual(out["cbiRes"]["score"], 75)
        self.assertEqual(out["cbiRes"]["band"]["label"], "High Burnout")
        for sub in out["cbiRes"]["subscales"]:
            self.assertEqual(sub["score"], 75)
            self.assertEqual(sub["unit"], "%")

        tfeq_ee = next(s for s in out["tfeqRes"]["subscales"] if s["id"] == "emotional-eating")
        tfeq_ue = next(s for s in out["tfeqRes"]["subscales"] if s["id"] == "uncontrolled-eating")
        self.assertEqual(tfeq_ee["score"], 100)
        self.assertEqual(tfeq_ue["score"], 0)
        self.assertEqual(out["tfeqRes"]["band"]["level"], "high")

        self.assertEqual(out["reapRes"]["score"], 39)
        self.assertFalse(out["reapRes"]["higherIsWorse"])
        self.assertEqual(out["reapRes"]["band"]["label"], "High Diet Quality")

        self.assertEqual(out["medasRes"]["score"], 10)
        self.assertFalse(out["medasRes"]["higherIsWorse"])
        self.assertEqual(out["medasRes"]["band"]["label"], "High Adherence")

        self.assertEqual(out["sss8Res"]["score"], 10)
        self.assertEqual(out["sss8Res"]["band"]["label"], "Medium Burden")

        self.assertEqual(out["stopBangRes"]["score"], 5)
        self.assertEqual(out["stopBangRes"]["band"]["label"], "High OSA Risk")

        self.assertEqual(out["customLow"]["score"], 0)
        self.assertEqual(len(out["customEmpty"]["safetyFlags"]), 0)

    def test_find_severity_band_handles_fractional_gaps_cleanly(self):
        js = """
        import { findSeverityBand } from "./public/quiz-engine.js";
        const bands = [
          { min: 0, max: 4, label: "Minimal", level: "low" },
          { min: 5, max: 9, label: "Mild", level: "mild" },
          { min: 20, max: 27, label: "Severe", level: "severe" }
        ];
        const gapLow = findSeverityBand(4.2, bands);
        const gapHigh = findSeverityBand(4.8, bands);
        const out = JSON.stringify({ gapLow, gapHigh });
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module(js))
        self.assertEqual(out["gapLow"]["label"], "Minimal")
        self.assertEqual(out["gapHigh"]["label"], "Mild")


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
                if os.path.basename(fpath) in ("sw.js", "theme-boot.js", "print-summary.js"):
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
        self.assertEqual(set(re.findall(r"\?v=(\d+)", sw_text)), {ver})

        for fname in ("index.html", "theme-boot.js", "app.js", "charts.js", "export.js", "manifest.json"):
            with open(os.path.join(PUBLIC_DIR, fname), "r", encoding="utf-8") as fh:
                content = fh.read()
            found = set(re.findall(r"\?v=(\d+)", content))
            self.assertEqual(found, {ver}, f"Version mismatch in {fname}: found {found}, expected {ver}")

        # Ensure clinician summary HTML contains zero inline event handlers (strict CSP)
        with open(os.path.join(PUBLIC_DIR, "export.js"), "r", encoding="utf-8") as fh:
            export_src = fh.read()
        self.assertNotIn("onclick=", export_src)

    def test_csv_escape_neutralizes_formulas_while_preserving_negative_numbers(self):
        js = """
        import { csvEscape } from "./public/export.js";
        const out = JSON.stringify({
          eq: csvEscape("=SUM(A1:A2)"),
          plus: csvEscape("+cmd"),
          at: csvEscape("@foo"),
          dashText: csvEscape("- felt tired"),
          negInt: csvEscape(-5),
          negFloat: csvEscape("-2.5"),
          comma: csvEscape("a, b"),
          normal: csvEscape("slept well"),
        });
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module(js))
        self.assertEqual(out["eq"], "'=SUM(A1:A2)")
        self.assertEqual(out["plus"], "'+cmd")
        self.assertEqual(out["at"], "'@foo")
        self.assertEqual(out["dashText"], "'- felt tired")
        self.assertEqual(out["negInt"], "-5")
        self.assertEqual(out["negFloat"], "-2.5")
        self.assertEqual(out["comma"], '"a, b"')
        self.assertEqual(out["normal"], "slept well")


if __name__ == "__main__":
    unittest.main()
