// Xero API client with multi-tenant support and rotating refresh-token persistence.
// Read-only usage: pulls organisations, invoices (ACCREC) and bills (ACCPAY) incl. payments.

import fs from "node:fs";
import path from "node:path";

const IDENTITY_TOKEN_URL = "https://identity.xero.com/connect/token";
const CONNECTIONS_URL = "https://api.xero.com/connections";
const API_BASE = "https://api.xero.com/api.xro/2.0";

const CLIENT_ID = process.env.XERO_CLIENT_ID;
const CLIENT_SECRET = process.env.XERO_CLIENT_SECRET;
const ENV_REFRESH_TOKEN = process.env.XERO_REFRESH_TOKEN;
// Where to persist the (rotating) refresh token across restarts. Strongly recommended.
const TOKEN_STORE = process.env.XERO_TOKEN_STORE || "";

// Read-only scopes used for both the browser sign-in flow and refreshes.
export const XERO_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "accounting.transactions.read",
  "accounting.contacts.read",
  "accounting.settings.read",
].join(" ");

// Build the Xero consent URL (used by the server's /auth route).
export function getAuthorizeUrl(redirectUri, state) {
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
export async function exchangeAuthorizationCode(code, redirectUri) {
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
export function hasRefreshToken() {
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

export async function getConnections(force = false) {
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
export async function resolveTenant(orgNameOrId) {
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
export async function getInvoices({
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
