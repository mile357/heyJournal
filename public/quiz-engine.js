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

const SEVERITY_LEVEL_RANK = {
  low: 0,
  mild: 1,
  moderate: 2,
  high: 3,
  severe: 4,
};

function evaluateRuleCondition(cond, ctx) {
  let val = null;
  if (cond.target === "score") {
    val = ctx.score;
  } else if (cond.questionId) {
    const raw = ctx.answersMap[cond.questionId];
    if (raw === undefined || raw === null || raw === "" || !Number.isFinite(Number(raw))) {
      return false;
    }
    val = Number(raw);
  } else if (cond.subscaleId) {
    const sub = ctx.subscales.find((s) => s.id === cond.subscaleId);
    if (!sub || typeof sub.score !== "number" || Number.isNaN(sub.score)) {
      return false;
    }
    val = sub.score;
  }
  if (val === null || !Number.isFinite(val)) return false;
  if (typeof cond.min === "number" && val < cond.min) return false;
  if (typeof cond.max === "number" && val > cond.max) return false;
  return true;
}

function evaluateScreeningRule(rule, ctx) {
  if (!rule || !Array.isArray(rule.allOf) || rule.allOf.length === 0) return null;
  const isPositive = rule.allOf.every((c) => evaluateRuleCondition(c, ctx));
  if (isPositive && rule.positiveBand) {
    return {
      positive: true,
      label: String(rule.positiveBand.label || "Positive Screen"),
      level: String(rule.positiveBand.level || "high"),
    };
  }
  if (Array.isArray(rule.partialAllOf) && rule.partialAllOf.length > 0 && rule.partialBand) {
    const isPartial = rule.partialAllOf.every((c) => evaluateRuleCondition(c, ctx));
    if (isPartial) {
      return {
        positive: false,
        label: String(rule.partialBand.label || "Partial Criteria"),
        level: String(rule.partialBand.level || "mild"),
      };
    }
  }
  if (rule.negativeBand) {
    return {
      positive: false,
      label: String(rule.negativeBand.label || "Negative Screen"),
      level: String(rule.negativeBand.level || "low"),
    };
  }
  return null;
}

function findHighestSubscaleBand(subscales) {
  if (!Array.isArray(subscales) || subscales.length === 0) return null;
  let maxRank = -1;
  for (const sub of subscales) {
    if (!sub.band) continue;
    const rank = SEVERITY_LEVEL_RANK[sub.band.level] ?? 0;
    if (rank > maxRank) maxRank = rank;
  }
  if (maxRank < 0) return null;
  const matching = subscales.filter((sub) => sub.band && (SEVERITY_LEVEL_RANK[sub.band.level] ?? 0) === maxRank);
  if (matching.length === 0) return null;
  const primary = matching[0].band;
  if (maxRank === 0) {
    return { label: primary.label, level: primary.level };
  }
  const names = matching.map((s) => s.name).join(", ");
  return {
    label: `${primary.label} (${names})`,
    level: primary.level,
  };
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
  let includedAnsweredCount = 0;
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
        includedAnsweredCount++;
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
  } else if (method === "mean") {
    score = includedAnsweredCount > 0 ? Math.round((rawSum / includedAnsweredCount) * multiplier * 100) / 100 : 0;
  } else {
    score = Math.round(rawSum * multiplier * 100) / 100;
  }

  // Subscales
  const subscales = [];
  if (Array.isArray(scoring.subscales)) {
    for (const sub of scoring.subscales) {
      const matchingQs = Array.isArray(sub.questionIds)
        ? questions.filter((q) => sub.questionIds.includes(q.id))
        : questions.filter((q) => q.subscale === sub.id);
      const subMethod = sub.method || "sum";
      let subRaw = 0;
      let subAnswered = 0;
      let subMinPossible = 0;
      let subMaxPossible = 0;
      let thresholdHits = 0;
      for (const mq of matchingQs) {
        if (effectiveById[mq.id] !== undefined) {
          const effVal = effectiveById[mq.id];
          subRaw += effVal;
          subAnswered++;
          if (subMethod === "thresholdCount") {
            const thr =
              sub.thresholds && typeof sub.thresholds[mq.id] === "number"
                ? sub.thresholds[mq.id]
                : typeof sub.defaultThreshold === "number"
                  ? sub.defaultThreshold
                  : 1;
            if (effVal >= thr) thresholdHits++;
          } else if (subMethod === "percentage") {
            const opts = getQuestionOptions(quiz, mq);
            const optVals = opts.map((o) => Number(o.value)).filter(Number.isFinite);
            if (optVals.length > 0) {
              subMinPossible += Math.min(...optVals);
              subMaxPossible += Math.max(...optVals);
            }
          }
        }
      }
      const subMult = typeof sub.multiplier === "number" ? sub.multiplier : 1;
      let subScore;
      if (subMethod === "thresholdCount") {
        subScore = thresholdHits;
      } else if (subMethod === "mean") {
        subScore = subAnswered > 0 ? Math.round((subRaw / subAnswered) * subMult * 100) / 100 : 0;
      } else if (subMethod === "percentage") {
        const subSpan = subMaxPossible - subMinPossible;
        subScore = subSpan > 0 ? Math.round(((subRaw - subMinPossible) / subSpan) * 100) : 0;
      } else {
        subScore = Math.round(subRaw * subMult * 100) / 100;
      }
      const subBand = findSeverityBand(subScore, sub.severityBands);
      subscales.push({
        id: sub.id,
        name: sub.name || sub.id,
        score: subScore,
        min: typeof sub.min === "number" ? sub.min : 0,
        max: typeof sub.max === "number" ? sub.max : null,
        unit: sub.unit || "",
        band: subBand,
      });
    }
  }

  // Headline severity band: declarative screeningRule > bandStrategy > score severityBands
  const screening = evaluateScreeningRule(scoring.screeningRule, { score, answersMap, subscales });
  let band;
  if (screening) {
    band = { label: screening.label, level: screening.level };
  } else if (scoring.bandStrategy === "highestSubscale") {
    band = findHighestSubscaleBand(subscales) || findSeverityBand(score, scoring.severityBands);
  } else {
    band = findSeverityBand(score, scoring.severityBands);
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
    screening,
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
