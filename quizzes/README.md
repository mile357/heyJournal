# HeyJournal Standardized Quiz Library (`quizzes/`)

Drop any `.json` file into `quizzes/` and it is automatically discovered by the server (`GET /api/quizzes`), shown in the **Metrics Library** tab, runnable in the guided quiz interface, and graphed automatically on the **Report** tab once you have at least 3 data points.

No core application files need to be edited to add a new quiz.

---

## Schema Reference

```json
{
  "id": "phq-9",
  "name": "PHQ-9",
  "fullName": "Patient Health Questionnaire-9",
  "category": "Mood & Depression",
  "shortDescription": "Brief 1-line description shown in the Metrics Library.",
  "timeframe": "Prompt shown above questions (e.g. Over the last 2 weeks...)",
  "estimatedMinutes": 2,
  "resourceUrl": "https://example.org/clinical-reference",
  "resourceLabel": "Clinical Reference Label",
  "citation": "Author et al., Journal, Year.",
  "answerScale": [
    { "label": "Not at all", "value": 0 },
    { "label": "Several days", "value": 1 },
    { "label": "More than half the days", "value": 2 },
    { "label": "Nearly every day", "value": 3 }
  ],
  "questions": [
    {
      "id": "q1",
      "text": "Question prompt text",
      "reverse": false,
      "subscale": "optional-subscale-id",
      "options": []
    }
  ],
  "scoring": {
    "method": "sum",
    "min": 0,
    "max": 27,
    "multiplier": 1,
    "unit": "pts",
    "higherIsWorse": true,
    "formulaDescription": "Plain-English explanation of how the score is calculated.",
    "severityBands": [
      { "min": 0, "max": 4, "label": "Minimal", "level": "low" },
      { "min": 5, "max": 9, "label": "Mild", "level": "mild" },
      { "min": 10, "max": 14, "label": "Moderate", "level": "moderate" },
      { "min": 15, "max": 19, "label": "Moderately Severe", "level": "high" },
      { "min": 20, "max": 27, "label": "Severe", "level": "severe" }
    ],
    "subscales": [
      { "id": "subscale-id", "name": "Display Name", "multiplier": 1, "min": 0, "max": 12 }
    ],
    "safetyFlags": [
      { "questionId": "q9", "minValue": 1, "message": "Supportive crisis resource message." }
    ]
  }
}
```

### Supported Scoring Fields
- **`scoring.method`**:
  - `"sum"` *(default)*: Sums all answered question values (applying per-question `reverse: true` as `maxOptionValue - value`, then multiplying by `scoring.multiplier`, default `1`). Questions with `excludeFromTotal: true` are recorded for clinical context without adding to the primary numeric score.
  - `"percentage"`: Computes `Math.round((rawSum / rawMax) * 100)` on a `0–100` scale.
- **`question.options`** *(optional)*: Overrides the quiz-wide `answerScale` for a specific question (used in quizzes like AUDIT or MDQ where later questions have different answer choices).
- **`scoring.severityBands`**: Ordered `{ min, max, label, level }` ranges (`level`: `"low" | "mild" | "moderate" | "high" | "severe"`). Used both for the post-quiz result badge and horizontal clinical reference bands on **Report** charts.
- **`scoring.subscales`** *(optional)*: Named subscale definitions that sum matching `question.subscale` items (or explicit `questionIds`), each with optional `multiplier`, `min`, `max`, and `severityBands`.
- **`scoring.higherIsWorse`**: Set `false` for positive well-being scales (like WHO-5) so trend deltas and chart colors reflect improvement accurately.
- **`scoring.safetyFlags`** *(optional)*: Displays a compassionate crisis/support callout whenever a sensitive item meets or exceeds `minValue`.

> **Disclaimer**: Self-assessment quizzes in HeyJournal are intended for personal tracking and reflection over time and are not a substitute for professional medical or psychological diagnosis.
