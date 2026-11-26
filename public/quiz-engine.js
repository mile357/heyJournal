/**
 * heyJo — Generalized Clinical Quiz Scoring Engine
 * Zero hard-coded quiz IDs: every quiz is driven purely by its JSON schema in `quizzes/*.json`.
 */

export function getQuestionOptions(quiz, question) {
  if (question && Array.isArray(question.options) && question.options.length > 0) {
    return question.options;
  }
  return Array.isArray(quiz && quiz.answerScale) ? quiz.answerScale : [];
}

export function findSeverityBand(score, bands) {
  if (!Array.isArray(bands) || bands.length === 0 || typeof score !== "number" || Number.isNaN(score)) {
    return null;
  }
  const sorted = [...bands].sort((a, b) => (a.min ?? -Infinity) - (b.min ?? -Infinity));
  for (const band of sorted) {
    const min = typeof band.min === "number" ? band.min : -Infinity;
    const max = typeof band.max === "number" ? band.max : Infinity;
    if (score >= min && score <= max) {
      return {
        label: String(band.label || ""),
        level: String(band.level || "low"),
        min,
        max,
      };
    }
  }
  // Boundary or fractional-gap fallback: pick closest band instead of jumping to severe
  let best = sorted[0];
  let bestDist = Infinity;
  for (const band of sorted) {
    const min = typeof band.min === "number" ? band.min : -Infinity;
    const max = typeof band.max === "number" ? band.max : Infinity;
    const dist = score < min ? min - score : score > max ? score - max : 0;
    if (dist < bestDist) {
      bestDist = dist;
      best = band;
    }
  }
  return {
    label: String(best.label || ""),
    level: String(best.level || "low"),
    min: best.min,
    max: best.max,
  };
}

function getEffectiveQuestionValue(quiz, question, rawVal) {
  const num = Number(rawVal);
  if (!Number.isFinite(num)) return 0;
  if (!question.reverse) return num;
  const opts = getQuestionOptions(quiz, question);
  const vals = opts.map((o) => Number(o.value)).filter(Number.isFinite);
  if (vals.length === 0) return num;
  const maxVal = Math.max(...vals);
  const minVal = Math.min(...vals);
  return maxVal + minVal - num;
}

export function scoreQuiz(quiz, answersMap = {}) {
  const questions = Array.isArray(quiz && quiz.questions) ? quiz.questions : [];
  const scoring = (quiz && quiz.scoring) || {};
  const method = scoring.method || "sum";
  const multiplier = typeof scoring.multiplier === "number" ? scoring.multiplier : 1;

  let rawSum = 0;
  let rawMinPossible = 0;
  let rawMaxPossible = 0;
  let answeredCount = 0;
  const effectiveById = {};

  for (const q of questions) {
    const raw = answersMap[q.id];
    const hasAnswer = raw !== undefined && raw !== null && raw !== "" && Number.isFinite(Number(raw));
    if (hasAnswer) {
      answeredCount++;
      const eff = getEffectiveQuestionValue(quiz, q, raw);
      effectiveById[q.id] = eff;
      if (!q.excludeFromTotal) {
        rawSum += eff;
      }
    }
    if (!q.excludeFromTotal) {
      const opts = getQuestionOptions(quiz, q);
      const optVals = opts.map((o) => Number(o.value)).filter(Number.isFinite);
      if (optVals.length > 0) {
        rawMinPossible += Math.min(...optVals);
        rawMaxPossible += Math.max(...optVals);
      }
    }
  }

  let score;
  if (method === "percentage") {
    const span = rawMaxPossible - rawMinPossible;
    score = span > 0 ? Math.round(((rawSum - rawMinPossible) / span) * 100) : 0;
  } else {
    score = Math.round(rawSum * multiplier * 100) / 100;
  }

  const band = findSeverityBand(score, scoring.severityBands);

  // Subscales
  const subscales = [];
  if (Array.isArray(scoring.subscales)) {
    for (const sub of scoring.subscales) {
      const matchingQs = Array.isArray(sub.questionIds)
        ? questions.filter((q) => sub.questionIds.includes(q.id))
        : questions.filter((q) => q.subscale === sub.id);
      let subRaw = 0;
      for (const mq of matchingQs) {
        if (effectiveById[mq.id] !== undefined) {
          subRaw += effectiveById[mq.id];
        }
      }
      const subMult = typeof sub.multiplier === "number" ? sub.multiplier : 1;
      const subScore = Math.round(subRaw * subMult * 100) / 100;
      const subBand = findSeverityBand(subScore, sub.severityBands);
      subscales.push({
        id: sub.id,
        name: sub.name || sub.id,
        score: subScore,
        min: typeof sub.min === "number" ? sub.min : 0,
        max: typeof sub.max === "number" ? sub.max : null,
        band: subBand,
      });
    }
  }

  // Safety / clinical callout flags
  const triggeredSafetyFlags = [];
  if (Array.isArray(scoring.safetyFlags)) {
    for (const flag of scoring.safetyFlags) {
      const val = answersMap[flag.questionId];
      if (val !== undefined && val !== null && val !== "" && Number.isFinite(Number(val)) && Number(val) >= Number(flag.minValue ?? 1)) {
        triggeredSafetyFlags.push({
          questionId: flag.questionId,
          value: Number(val),
          message: String(flag.message || ""),
        });
      }
    }
  }

  // Normalized answer details for encrypted archival & later review
  const answerDetails = questions.map((q) => {
    const raw = answersMap[q.id];
    const hasAnswer = raw !== undefined && raw !== null && raw !== "" && Number.isFinite(Number(raw));
    const opts = getQuestionOptions(quiz, q);
    const chosenOpt = hasAnswer ? opts.find((o) => Number(o.value) === Number(raw)) : null;
    return {
      questionId: q.id,
      text: q.text,
      value: hasAnswer ? Number(raw) : null,
      label: chosenOpt ? chosenOpt.label : "",
      reverse: Boolean(q.reverse),
    };
  });

  return {
    quizId: quiz.id,
    quizName: quiz.name || quiz.id,
    score,
    rawScore: rawSum,
    minScore: typeof scoring.min === "number" ? scoring.min : 0,
    maxScore: typeof scoring.max === "number" ? scoring.max : rawMaxPossible * multiplier,
    unit: scoring.unit || "pts",
    higherIsWorse: scoring.higherIsWorse !== false,
    band,
    subscales,
    safetyFlags: triggeredSafetyFlags,
    answers: { ...answersMap },
    answerDetails,
    answeredCount,
    totalQuestions: questions.length,
    isComplete: questions.length > 0 && answeredCount === questions.length,
  };
}

export function formatScoreValue(score, unit = "pts") {
  if (typeof score !== "number" || Number.isNaN(score)) return "—";
  const rounded = Number.isInteger(score) ? String(score) : score.toFixed(1);
  if (unit === "%") return `${rounded}%`;
  return unit ? `${rounded} ${unit}` : rounded;
}
