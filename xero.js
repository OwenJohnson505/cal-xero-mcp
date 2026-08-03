// Pure reconciliation logic (no network). Pairs documents between two sides and
// flags anything that doesn't line up on: value, invoice date, due date, paid date, paid amount.

function daysBetween(a, b) {
  if (!a || !b) return null;
  const da = new Date(a + "T00:00:00Z").getTime();
  const db = new Date(b + "T00:00:00Z").getTime();
  return Math.round((da - db) / 86400000);
}

function money(n) {
  return n === null || n === undefined ? null : Math.round(Number(n) * 100) / 100;
}

// Pair each doc in listX with a doc in listY.
// Match primary key = total value (within amountTolerance). Tie-break = nearest invoice date.
export function reconcilePair(
  listX,
  listY,
  {
    labelX = "Side A",
    labelY = "Side B",
    amountTolerance = 0.01,
    dateToleranceDays = null, // if set, reject a match whose invoice dates differ by more than this
  } = {}
) {
  const xs = [...listX];
  const ys = [...listY].map((y) => ({ doc: y, used: false }));
  const matched = [];
  const unmatchedX = [];

  for (const x of xs) {
    let best = null;
    let bestScore = Infinity;
    for (const cand of ys) {
      if (cand.used) continue;
      if (x.total === null || cand.doc.total === null) continue;
      if (Math.abs(x.total - cand.doc.total) > amountTolerance) continue;
      const dd = daysBetween(x.invoiceDate, cand.doc.invoiceDate);
      const score = dd === null ? 9999 : Math.abs(dd);
      if (dateToleranceDays !== null && score !== null && score > dateToleranceDays) continue;
      if (score < bestScore) {
        bestScore = score;
        best = cand;
      }
    }
    if (best) {
      best.used = true;
      matched.push({ x, y: best.doc, discrepancies: compareDocs(x, best.doc, labelX, labelY) });
    } else {
      unmatchedX.push(x);
    }
  }

  const unmatchedY = ys.filter((c) => !c.used).map((c) => c.doc);

  const withDiffs = matched.filter((m) => m.discrepancies.length > 0);
  return {
    labelX,
    labelY,
    summary: {
      totalX: listX.length,
      totalY: listY.length,
      matched: matched.length,
      matchedWithDiscrepancies: withDiffs.length,
      missingCounterpartOnY: unmatchedX.length, // X exists, no Y
      missingCounterpartOnX: unmatchedY.length, // Y exists, no X
    },
    matched,
    unmatchedX, // exist on X, missing on Y
    unmatchedY, // exist on Y, missing on X
  };
}

function compareDocs(x, y, labelX, labelY) {
  const d = [];
  const push = (field, xv, yv, note) => d.push({ field, [labelX]: xv, [labelY]: yv, note });

  if (money(x.total) !== money(y.total)) push("value (total)", money(x.total), money(y.total));

  if ((x.invoiceDate || null) !== (y.invoiceDate || null)) {
    const gap = daysBetween(x.invoiceDate, y.invoiceDate);
    push("invoice date", x.invoiceDate, y.invoiceDate, gap === null ? undefined : `${Math.abs(gap)} day(s) apart`);
  }

  if ((x.dueDate || null) !== (y.dueDate || null)) {
    push("due date", x.dueDate, y.dueDate);
  }

  if ((x.paidDate || null) !== (y.paidDate || null)) {
    const gap = daysBetween(x.paidDate, y.paidDate);
    push("paid date", x.paidDate, y.paidDate, gap === null ? undefined : `${Math.abs(gap)} day(s) apart`);
  }

  if (money(x.amountPaid) !== money(y.amountPaid)) {
    push("paid amount", money(x.amountPaid), money(y.amountPaid));
  }

  // Settlement-status mismatch (one fully paid, other still owing).
  const xPaid = (x.amountDue ?? 0) === 0 && (x.amountPaid ?? 0) > 0;
  const yPaid = (y.amountDue ?? 0) === 0 && (y.amountPaid ?? 0) > 0;
  if (xPaid !== yPaid) {
    push("settlement status", xPaid ? "paid" : "outstanding", yPaid ? "paid" : "outstanding");
  }

  return d;
}

// Human-readable digest for the MCP text response.
export function formatReconciliation(title, result) {
  const s = result.summary;
  const lines = [];
  lines.push(`### ${title}`);
  lines.push(
    `${result.labelX}: ${s.totalX} docs · ${result.labelY}: ${s.totalY} docs · ` +
      `matched: ${s.matched} · with mismatches: ${s.matchedWithDiscrepancies}`
  );
  if (s.missingCounterpartOnY)
    lines.push(`⚠️ ${s.missingCounterpartOnY} on ${result.labelX} with NO counterpart on ${result.labelY}`);
  if (s.missingCounterpartOnX)
    lines.push(`⚠️ ${s.missingCounterpartOnX} on ${result.labelY} with NO counterpart on ${result.labelX}`);

  if (result.unmatchedX.length) {
    lines.push(`\nMissing on ${result.labelY}:`);
    for (const x of result.unmatchedX)
      lines.push(`  • ${x.number || x.reference || x.invoiceId} — ${x.invoiceDate} — ${x.currency} ${x.total}`);
  }
  if (result.unmatchedY.length) {
    lines.push(`\nMissing on ${result.labelX}:`);
    for (const y of result.unmatchedY)
      lines.push(`  • ${y.number || y.reference || y.invoiceId} — ${y.invoiceDate} — ${y.currency} ${y.total}`);
  }
  const diffs = result.matched.filter((m) => m.discrepancies.length);
  if (diffs.length) {
    lines.push(`\nMatched but not aligned:`);
    for (const m of diffs) {
      const id = m.x.number || m.x.reference || m.x.invoiceId;
      const fields = m.discrepancies.map((dd) => dd.field).join(", ");
      lines.push(`  • ${id} (${m.x.currency} ${m.x.total}) — differs on: ${fields}`);
    }
  }
  if (!s.missingCounterpartOnX && !s.missingCounterpartOnY && !diffs.length) {
    lines.push(`✅ Every document has a clean, aligned counterpart.`);
  }
  return lines.join("\n");
}
