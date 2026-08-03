// Cal Xero MCP — single-file build (multi-org Xero connector + reconciliation)
import fs from "node:fs";
import path from "node:path";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import crypto from "node:crypto";

// ===== xero client =====
// Xero API client with multi-tenant support and rotating refresh-token persistence.
// Read-only usage: pulls organisations, invoices (ACCREC) and bills (ACCPAY) incl. payments.


const IDENTITY_TOKEN_URL = "https://identity.xero.com/connect/token";
const CONNECTIONS_URL = "https://api.xero.com/connections";
const API_BASE = "https://api.xero.com/api.xro/2.0";

const CLIENT_ID = process.env.XERO_CLIENT_ID;
const CLIENT_SECRET = process.env.XERO_CLIENT_SECRET;
const ENV_REFRESH_TOKEN = process.env.XERO_REFRESH_TOKEN;
// Where to persist the (rotating) refresh token across restarts. Strongly recommended.
const TOKEN_STORE = process.env.XERO_TOKEN_STORE || "";

// Read-only scopes used for both the browser sign-in flow and refreshes.
const XERO_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "accounting.transactions.read",
  "accounting.contacts.read",
  "accounting.settings.read",
].join(" ");

// Build the Xero consent URL (used by the server's /auth route).
function getAuthorizeUrl(redirectUri, state) {
  if (!CLIENT_ID) throw new Error("XERO_CLIENT_ID is not set.");
  return (
    "https://login.xero.com/identity/connect/authorize?" +
    new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: redirectUri,
      scope: XERO_SCOPES,
      state,
    }).toString()
  );
}

// Exchange an authorization code for tokens, persist the refresh token, return granted tenants.
async function exchangeAuthorizationCode(code, redirectUri) {
  assertConfig();
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  const res = await fetch(IDENTITY_TOKEN_URL, {
    method: "POST",
    headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Xero token exchange failed (${res.status}): ${text}`);
  const json = JSON.parse(text);
  cache.accessToken = json.access_token;
  cache.accessTokenExpiry = Date.now() + (json.expires_in ? json.expires_in * 1000 : 1800000) - 60000;
  if (json.refresh_token) persistRefreshToken(json.refresh_token);
  const conns = await getConnections(true);
  return conns.map((c) => ({ name: c.tenantName, tenantId: c.tenantId }));
}

// True once we have a usable refresh token (env or persisted store).
function hasRefreshToken() {
  return Boolean(currentRefreshToken());
}

let cache = {
  accessToken: null,
  accessTokenExpiry: 0, // epoch ms
  refreshToken: null,
  connections: null, // [{ tenantId, tenantName, ... }]
  connectionsAt: 0,
};

function assertConfig() {
  const missing = [];
  if (!CLIENT_ID) missing.push("XERO_CLIENT_ID");
  if (!CLIENT_SECRET) missing.push("XERO_CLIENT_SECRET");
  if (missing.length) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}. ` +
        `Set them on the host (see README / .env.example).`
    );
  }
}

function readStoredRefreshToken() {
  if (TOKEN_STORE) {
    try {
      if (fs.existsSync(TOKEN_STORE)) {
        const raw = JSON.parse(fs.readFileSync(TOKEN_STORE, "utf8"));
        if (raw && typeof raw.refresh_token === "string") return raw.refresh_token;
      }
    } catch (e) {
      console.error(`[xero] could not read token store at ${TOKEN_STORE}: ${e.message}`);
    }
  }
  return null;
}

function persistRefreshToken(refreshToken) {
  cache.refreshToken = refreshToken;
  if (!TOKEN_STORE) return;
  try {
    fs.mkdirSync(path.dirname(TOKEN_STORE), { recursive: true });
    fs.writeFileSync(
      TOKEN_STORE,
      JSON.stringify({ refresh_token: refreshToken, updated_at: new Date().toISOString() }, null, 2)
    );
  } catch (e) {
    console.error(`[xero] could not persist token store at ${TOKEN_STORE}: ${e.message}`);
  }
}

function currentRefreshToken() {
  return cache.refreshToken || readStoredRefreshToken() || ENV_REFRESH_TOKEN || null;
}

async function refreshAccessToken() {
  assertConfig();
  const refreshToken = currentRefreshToken();
  if (!refreshToken) {
    throw new Error(
      "No Xero refresh token available. Run `npm run get-token` once to obtain one, " +
        "then set XERO_REFRESH_TOKEN (and ideally XERO_TOKEN_STORE for persistence)."
    );
  }
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  const res = await fetch(IDENTITY_TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `Xero token refresh failed (${res.status}): ${text}. ` +
        `If this says 'invalid_grant', the refresh token has expired or was rotated away — ` +
        `run \`npm run get-token\` again to mint a fresh one.`
    );
  }
  const json = await res.json();
  cache.accessToken = json.access_token;
  // Xero access tokens last 1800s; refresh 60s early.
  cache.accessTokenExpiry = Date.now() + (json.expires_in ? json.expires_in * 1000 : 1800000) - 60000;
  if (json.refresh_token) persistRefreshToken(json.refresh_token);
  return cache.accessToken;
}

async function getAccessToken() {
  if (cache.accessToken && Date.now() < cache.accessTokenExpiry) return cache.accessToken;
  return refreshAccessToken();
}

async function xeroFetch(url, { tenantId, method = "GET" } = {}) {
  let attempt = 0;
  // Simple retry loop for 401 (token) and 429 (rate limit).
  while (true) {
    attempt++;
    const token = await getAccessToken();
    const headers = {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    };
    if (tenantId) headers["Xero-tenant-id"] = tenantId;
    const res = await fetch(url, { method, headers });

    if (res.status === 401 && attempt <= 2) {
      cache.accessToken = null; // force refresh
      continue;
    }
    if (res.status === 429 && attempt <= 5) {
      const retryAfter = Number(res.headers.get("Retry-After")) || 2;
      await new Promise((r) => setTimeout(r, (retryAfter + 1) * 1000));
      continue;
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Xero API ${method} ${url} failed (${res.status}): ${text}`);
    }
    return res.json();
  }
}

async function getConnections(force = false) {
  if (!force && cache.connections && Date.now() - cache.connectionsAt < 5 * 60 * 1000) {
    return cache.connections;
  }
  const list = await xeroFetch(CONNECTIONS_URL);
  // Only keep organisation connections.
  cache.connections = (Array.isArray(list) ? list : []).filter(
    (c) => c.tenantType === "ORGANISATION" || !c.tenantType
  );
  cache.connectionsAt = Date.now();
  return cache.connections;
}

// Resolve an org by tenantId or (partial, case-insensitive) name.
async function resolveTenant(orgNameOrId) {
  const conns = await getConnections();
  if (!orgNameOrId) {
    if (conns.length === 1) return conns[0];
    throw new Error(
      `Multiple organisations are connected — specify which one. Options: ${conns
        .map((c) => `"${c.tenantName}"`)
        .join(", ")}`
    );
  }
  const needle = String(orgNameOrId).trim().toLowerCase();
  let match = conns.find((c) => c.tenantId.toLowerCase() === needle);
  if (match) return match;
  match = conns.find((c) => c.tenantName.toLowerCase() === needle);
  if (match) return match;
  const partial = conns.filter((c) => c.tenantName.toLowerCase().includes(needle));
  if (partial.length === 1) return partial[0];
  if (partial.length > 1) {
    throw new Error(
      `Organisation "${orgNameOrId}" is ambiguous. Matches: ${partial
        .map((c) => `"${c.tenantName}"`)
        .join(", ")}`
    );
  }
  throw new Error(
    `No connected organisation matches "${orgNameOrId}". Connected: ${conns
      .map((c) => `"${c.tenantName}"`)
      .join(", ")}`
  );
}

function buildInvoiceWhere({ type, contactName, dateFrom, dateTo, status }) {
  const clauses = [];
  if (type) clauses.push(`Type=="${type}"`);
  if (contactName) clauses.push(`Contact.Name=="${contactName.replace(/"/g, '\\"')}"`);
  if (dateFrom) clauses.push(`Date>=DateTime(${dateFrom.replaceAll("-", ", ")})`);
  if (dateTo) clauses.push(`Date<=DateTime(${dateTo.replaceAll("-", ", ")})`);
  if (status) clauses.push(`Status=="${status}"`);
  return clauses.join(" && ");
}

// Fetch invoices/bills (with payments) for a tenant, paginating fully.
async function getInvoices({
  tenantId,
  type, // "ACCREC" (sales invoice) | "ACCPAY" (bill) | undefined (both)
  contactName,
  dateFrom, // YYYY-MM-DD (invoice date)
  dateTo,
  status, // e.g. "AUTHORISED" | "PAID" — omit for all non-deleted
}) {
  const where = buildInvoiceWhere({ type, contactName, dateFrom, dateTo, status });
  const all = [];
  let page = 1;
  while (true) {
    const params = new URLSearchParams({ page: String(page) });
    if (where) params.set("where", where);
    params.set("order", "Date");
    const url = `${API_BASE}/Invoices?${params.toString()}`;
    const json = await xeroFetch(url, { tenantId });
    const batch = json.Invoices || [];
    all.push(...batch);
    if (batch.length < 100) break;
    page++;
    if (page > 200) break; // hard safety cap
  }
  return all.map(normaliseInvoice);
}

function normaliseInvoice(inv) {
  const payments = (inv.Payments || []).map((p) => ({
    paymentId: p.PaymentID,
    date: xeroDate(p.Date),
    amount: p.Amount,
    reference: p.Reference,
  }));
  // Latest payment date = the date it became settled (best proxy for "paid date").
  const lastPaymentDate = payments.length
    ? payments.map((p) => p.date).filter(Boolean).sort().slice(-1)[0]
    : null;
  return {
    invoiceId: inv.InvoiceID,
    type: inv.Type, // ACCREC | ACCPAY
    number: inv.InvoiceNumber || null,
    reference: inv.Reference || null,
    contact: inv.Contact ? inv.Contact.Name : null,
    contactId: inv.Contact ? inv.Contact.ContactID : null,
    status: inv.Status,
    invoiceDate: xeroDate(inv.Date) || xeroDate(inv.DateString),
    dueDate: xeroDate(inv.DueDate) || xeroDate(inv.DueDateString),
    currency: inv.CurrencyCode,
    total: numify(inv.Total),
    subTotal: numify(inv.SubTotal),
    totalTax: numify(inv.TotalTax),
    amountPaid: numify(inv.AmountPaid),
    amountDue: numify(inv.AmountDue),
    fullyPaidOnDate: xeroDate(inv.FullyPaidOnDate),
    paidDate: xeroDate(inv.FullyPaidOnDate) || lastPaymentDate,
    payments,
  };
}

function numify(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Xero serialises dates as "/Date(1596240000000+0000)/" or ISO strings.
function xeroDate(v) {
  if (!v) return null;
  if (typeof v === "string") {
    const m = v.match(/\/Date\((\d+)([+-]\d+)?\)\//);
    if (m) {
      const d = new Date(Number(m[1]));
      return isoDay(d);
    }
    const d = new Date(v);
    if (!isNaN(d.getTime())) return isoDay(d);
    return null;
  }
  return null;
}

function isoDay(d) {
  // UTC calendar day (Xero dates are date-only at midnight UTC).
  return d.toISOString().slice(0, 10);
}


// ===== reconcile =====
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
function reconcilePair(
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
function formatReconciliation(title, result) {
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


// ===== server =====
// Cal Xero MCP — multi-organisation Xero connector (remote, Streamable HTTP).
// Exposes organisations, invoices/bills with payment dates, and an inter-company
// reconciliation tool across two organisations.



const PORT = process.env.PORT || 8080;
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || ""; // optional bearer protection
// Public base URL of this server (e.g. https://cal-xero.example.com). Used to build the
// Xero OAuth redirect. If unset, it is inferred from the incoming request.
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");

let oauthState = null; // one-time CSRF state for the browser sign-in flow

function baseUrl(req) {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL;
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "https";
  const host = req.headers["x-forwarded-host"] || req.headers["host"];
  return `${proto}://${host}`;
}

function htmlPage(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f4f5f7;color:#1a1a2e;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#fff;max-width:520px;padding:32px;border-radius:14px;box-shadow:0 2px 14px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 10px}p{line-height:1.5;color:#444}a.btn{display:inline-block;background:#13b5ea;color:#fff;text-decoration:none;padding:12px 20px;border-radius:10px;font-weight:600;margin-top:10px}
code{background:#f0f0f4;padding:2px 6px;border-radius:5px}</style></head><body><div class="card">${body}</div></body></html>`;
}

function textResult(text, data) {
  const content = [{ type: "text", text }];
  if (data !== undefined) {
    content.push({ type: "text", text: "```json\n" + JSON.stringify(data, null, 2) + "\n```" });
  }
  return { content };
}

function errorResult(err) {
  return { content: [{ type: "text", text: `Error: ${err.message || String(err)}` }], isError: true };
}

function buildServer() {
  const server = new McpServer({ name: "cal-xero", version: "1.0.0" });

  server.tool(
    "list_organisations",
    "List the Xero organisations this connector can access (Cal South, Cal Sameday, Courier & Logistics, etc.), with their tenant IDs. Call this first if you are unsure of the exact organisation names.",
    {},
    async () => {
      try {
        const conns = await getConnections(true);
        const orgs = conns.map((c) => ({ name: c.tenantName, tenantId: c.tenantId }));
        return textResult(
          `Connected organisations:\n${orgs.map((o) => `• ${o.name}`).join("\n")}`,
          orgs
        );
      } catch (e) {
        return errorResult(e);
      }
    }
  );

  server.tool(
    "list_invoices",
    "List invoices and/or bills for ONE organisation, including payment dates and paid amounts. " +
      "doc_type: 'sales' = sales invoices (money owed to the org, ACCREC), 'bills' = purchase bills (money the org owes, ACCPAY), 'both' = both. " +
      "Optionally filter by contact name and invoice-date range. Returns per-document value, invoice date, due date, paid date, amount paid and amount due.",
    {
      organisation: z.string().describe("Organisation name or tenant ID (e.g. 'Cal South', 'Cal Sameday')."),
      doc_type: z.enum(["sales", "bills", "both"]).default("both"),
      contact: z.string().optional().describe("Filter to a single contact name (exact match)."),
      date_from: z.string().optional().describe("Invoice date from, YYYY-MM-DD."),
      date_to: z.string().optional().describe("Invoice date to, YYYY-MM-DD."),
      status: z.string().optional().describe("Optional Xero status filter, e.g. AUTHORISED, PAID."),
    },
    async (args) => {
      try {
        const tenant = await resolveTenant(args.organisation);
        const typeMap = { sales: "ACCREC", bills: "ACCPAY" };
        const types = args.doc_type === "both" ? ["ACCREC", "ACCPAY"] : [typeMap[args.doc_type]];
        let docs = [];
        for (const t of types) {
          const batch = await getInvoices({
            tenantId: tenant.tenantId,
            type: t,
            contactName: args.contact,
            dateFrom: args.date_from,
            dateTo: args.date_to,
            status: args.status,
          });
          docs = docs.concat(batch);
        }
        return textResult(
          `${tenant.tenantName}: ${docs.length} document(s) (${args.doc_type}).`,
          { organisation: tenant.tenantName, count: docs.length, documents: docs }
        );
      } catch (e) {
        return errorResult(e);
      }
    }
  );

  server.tool(
    "reconcile_intercompany",
    "Reconcile inter-company transactions between TWO organisations. For every sales invoice one company raises to the other, there should be a matching bill on the other side (and vice-versa). " +
      "This checks both directions and flags: (a) invoices with no matching bill, (b) bills with no matching invoice, and (c) matched pairs that don't align on value, invoice date, due date, paid date or paid amount. " +
      "Provide the contact name each company is booked under in the other's ledger (counterparty_in_a / counterparty_in_b).",
    {
      org_a: z.string().describe("First organisation name or tenant ID, e.g. 'Cal South'."),
      org_b: z.string().describe("Second organisation name or tenant ID, e.g. 'Cal Sameday'."),
      counterparty_in_a: z
        .string()
        .describe("The contact name that org B appears as inside org A's ledger (e.g. 'Cal Sameday')."),
      counterparty_in_b: z
        .string()
        .describe("The contact name that org A appears as inside org B's ledger (e.g. 'Cal South')."),
      date_from: z.string().optional().describe("Invoice date from, YYYY-MM-DD."),
      date_to: z.string().optional().describe("Invoice date to, YYYY-MM-DD."),
      amount_tolerance: z.number().default(0.01).describe("Max value difference to treat two docs as the same transaction."),
    },
    async (args) => {
      try {
        const tA = await resolveTenant(args.org_a);
        const tB = await resolveTenant(args.org_b);
        const common = {
          dateFrom: args.date_from,
          dateTo: args.date_to,
        };
        // Direction 1: A sells to B  -> A's ACCREC should equal B's ACCPAY.
        const aSales = await getInvoices({ tenantId: tA.tenantId, type: "ACCREC", contactName: args.counterparty_in_a, ...common });
        const bBills = await getInvoices({ tenantId: tB.tenantId, type: "ACCPAY", contactName: args.counterparty_in_b, ...common });
        const dir1 = reconcilePair(aSales, bBills, {
          labelX: `${tA.tenantName} invoices`,
          labelY: `${tB.tenantName} bills`,
          amountTolerance: args.amount_tolerance,
        });
        // Direction 2: B sells to A -> B's ACCREC should equal A's ACCPAY.
        const bSales = await getInvoices({ tenantId: tB.tenantId, type: "ACCREC", contactName: args.counterparty_in_b, ...common });
        const aBills = await getInvoices({ tenantId: tA.tenantId, type: "ACCPAY", contactName: args.counterparty_in_a, ...common });
        const dir2 = reconcilePair(bSales, aBills, {
          labelX: `${tB.tenantName} invoices`,
          labelY: `${tA.tenantName} bills`,
          amountTolerance: args.amount_tolerance,
        });

        const digest =
          formatReconciliation(`${tA.tenantName} → ${tB.tenantName} (invoices vs bills)`, dir1) +
          "\n\n" +
          formatReconciliation(`${tB.tenantName} → ${tA.tenantName} (invoices vs bills)`, dir2);

        return textResult(digest, { direction_1: dir1, direction_2: dir2 });
      } catch (e) {
        return errorResult(e);
      }
    }
  );

  return server;
}

const app = express();
app.use(express.json({ limit: "4mb" }));

app.get("/health", (_req, res) => res.json({ ok: true, service: "cal-xero-mcp" }));
app.get("/", (req, res) => {
  const connected = hasRefreshToken();
  res.send(
    htmlPage(
      "Cal Xero MCP",
      `<h1>Cal Xero MCP</h1>
      <p>Status: ${connected ? "✅ connected to Xero" : "⚠️ not connected to Xero yet"}.</p>
      <p>${connected ? "You can add this server to Claude as a custom connector using the <code>/mcp</code> URL." : "Click below to sign in to Xero and authorise your organisations (do this once)."}</p>
      ${connected ? "" : `<a class="btn" href="${baseUrl(req)}/auth">Connect Xero</a>`}`
    )
  );
});

// ---- One-time browser sign-in flow (no terminal needed) ----
app.get("/auth", (req, res) => {
  try {
    oauthState = crypto.randomBytes(16).toString("hex");
    const redirectUri = `${baseUrl(req)}/auth/callback`;
    res.redirect(getAuthorizeUrl(redirectUri, oauthState));
  } catch (e) {
    res.status(500).send(htmlPage("Error", `<h1>Setup error</h1><p>${e.message}</p>`));
  }
});

app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send(htmlPage("Error", "<h1>No code returned</h1>"));
  if (!state || state !== oauthState)
    return res.status(400).send(htmlPage("Error", "<h1>State mismatch</h1><p>Please start again from /auth.</p>"));
  try {
    const redirectUri = `${baseUrl(req)}/auth/callback`;
    const orgs = await exchangeAuthorizationCode(code, redirectUri);
    oauthState = null;
    const list = orgs.map((o) => `<li>${o.name}</li>`).join("");
    res.send(
      htmlPage(
        "Connected",
        `<h1>✅ Xero connected</h1><p>Authorised organisations:</p><ul>${list}</ul>
        <p>You're done here. Add <code>${baseUrl(req)}/mcp</code> to Claude as a custom connector.</p>`
      )
    );
  } catch (e) {
    res.status(500).send(htmlPage("Error", `<h1>Token exchange failed</h1><p>${e.message}</p>`));
  }
});

function checkAuth(req, res) {
  if (!AUTH_TOKEN) return true;
  const header = req.headers["authorization"] || "";
  if (header === `Bearer ${AUTH_TOKEN}`) return true;
  res.status(401).json({ error: "unauthorized" });
  return false;
}

// Stateless Streamable HTTP: a fresh server+transport per request.
app.post("/mcp", async (req, res) => {
  if (!checkAuth(req, res)) return;
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("[mcp] request error:", e);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  }
});

// Stateless mode does not support server-initiated streams.
app.get("/mcp", (_req, res) => res.status(405).json({ error: "Method Not Allowed" }));
app.delete("/mcp", (_req, res) => res.status(405).json({ error: "Method Not Allowed" }));

app.listen(PORT, () => {
  console.log(`Cal Xero MCP listening on :${PORT}  (POST /mcp)`);
  if (!AUTH_TOKEN) console.log("[warn] MCP_AUTH_TOKEN not set — endpoint is unauthenticated. Protect via an unguessable URL or platform access controls.");
});

