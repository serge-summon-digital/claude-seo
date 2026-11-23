// Re-issues the Google refresh token used by the Summon Google Performance connector
// (Railway project summon-dataforseo-mcp / service summon-google-performance-mcp),
// adding BigQuery read-only access, and saves it to Railway only after checking that the
// new login still reaches every GA4 property, Search Console site and the Google Ads
// manager account the connector is configured for.
//
// Usage (in your own Terminal, Railway CLI logged in):
//   node scripts/oauth/update-google-performance-token.mjs            # sign in, check, save
//   node scripts/oauth/update-google-performance-token.mjs --dry-run  # sign in and check only
//
// The refresh token is never printed or written to disk.

import http from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";

const RAILWAY = {
  project: process.env.RAILWAY_PROJECT_ID || "382b67c0-ef80-49ab-b4b5-21beae00f9e4",
  environment: process.env.RAILWAY_ENVIRONMENT_ID || "f8d7905b-4625-4386-b62a-88f5f19ea4d7",
  service: process.env.RAILWAY_SERVICE_ID || "dcaef2f5-e32d-4165-a4aa-a53a4b1518be",
};
const BIGQUERY_CHECK_DATASET =
  process.env.BIGQUERY_CHECK_DATASET || "boreal-mode-485011-v3.analytics_250395279";
const dryRun = process.argv.includes("--dry-run");
const port = Number.parseInt(process.env.OAUTH_PORT || "53682", 10);
const redirectUri = `http://127.0.0.1:${port}/callback`;
const REQUIRED_SCOPES = [
  "https://www.googleapis.com/auth/analytics.readonly",
  "https://www.googleapis.com/auth/webmasters.readonly",
  "https://www.googleapis.com/auth/adwords",
  "https://www.googleapis.com/auth/bigquery.readonly",
];
const scopes = [...REQUIRED_SCOPES, "openid", "email"];

const railwayArgs = ["-p", RAILWAY.project, "-e", RAILWAY.environment, "-s", RAILWAY.service];
const vars = JSON.parse(
  execFileSync("railway", ["variable", "list", "--json", ...railwayArgs], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  }),
);
const clientId = vars.GOOGLE_CLIENT_ID;
const clientSecret = vars.GOOGLE_CLIENT_SECRET;
if (!clientId) {
  fail("GOOGLE_CLIENT_ID is not set on the Railway service.");
}
const allowlist = JSON.parse(vars.CLIENT_ALLOWLIST_JSON || "{}");

const state = randomBytes(24).toString("base64url");
const codeVerifier = randomBytes(48).toString("base64url");
const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, redirectUri);
  if (url.pathname !== "/callback") {
    res.writeHead(404).end("Not found");
    return;
  }
  if (url.searchParams.get("state") !== state || !url.searchParams.get("code")) {
    res.writeHead(400).end(`Sign-in failed: ${url.searchParams.get("error") || "invalid response"}`);
    server.close();
    fail(`Google sign-in failed: ${url.searchParams.get("error") || "invalid response"}`);
  }
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("Signed in. Go back to Terminal to see the checks. You can close this tab.");
  server.close();
  try {
    await finish(url.searchParams.get("code"));
  } catch (error) {
    fail(error.message);
  }
});

server.listen(port, "127.0.0.1", () => {
  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: scopes.join(" "),
    access_type: "offline",
    prompt: "consent",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });
  console.log("\nOpening Google sign-in in your browser. If it does not open, paste this link:\n");
  console.log(authUrl.toString(), "\n");
  spawn("open", [authUrl.toString()], { stdio: "ignore" }).on("error", () => {});
});

async function finish(code) {
  const body = new URLSearchParams({
    client_id: clientId,
    code,
    code_verifier: codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });
  if (clientSecret) body.set("client_secret", clientSecret);
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const token = await tokenResponse.json();
  if (!tokenResponse.ok || !token.refresh_token) {
    throw new Error(`Google did not return a refresh token: ${token.error_description || token.error || tokenResponse.status}`);
  }
  const auth = { authorization: `Bearer ${token.access_token}` };

  const info = await getJson(`https://oauth2.googleapis.com/tokeninfo?access_token=${token.access_token}`);
  const granted = new Set(String(info.scope || "").split(" "));
  console.log(`Signed in as: ${info.email || "(email not shared)"}`);
  const problems = [];
  const warnings = [];
  const missingScopes = REQUIRED_SCOPES.filter((scope) => !granted.has(scope));
  if (missingScopes.length) {
    problems.push(`Permissions not granted (tick every box on the Google screen): ${missingScopes.join(", ")}`);
  }

  // GA4: every allowlisted property must be visible to this account.
  const ga4Visible = new Set();
  let pageToken = "";
  do {
    const page = await getJson(
      `https://analyticsadmin.googleapis.com/v1beta/accountSummaries?pageSize=200${pageToken ? `&pageToken=${pageToken}` : ""}`,
      auth,
    );
    for (const account of page.accountSummaries || []) {
      for (const property of account.propertySummaries || []) {
        ga4Visible.add(String(property.property).replace("properties/", ""));
      }
    }
    pageToken = page.nextPageToken || "";
  } while (pageToken);

  // Search Console: every allowlisted site must be listed.
  const gsc = await getJson("https://www.googleapis.com/webmasters/v3/sites", auth);
  const gscVisible = new Set((gsc.siteEntry || []).map((site) => site.siteUrl));

  for (const [key, client] of Object.entries(allowlist)) {
    const missingGa4 = (client.ga4Properties || []).filter((id) => !ga4Visible.has(String(id)));
    const missingGsc = (client.gscSites || []).filter((site) => !gscVisible.has(site));
    if (missingGa4.length) problems.push(`${key}: cannot see GA4 properties ${missingGa4.join(", ")}`);
    if (missingGsc.length) problems.push(`${key}: cannot see Search Console sites ${missingGsc.join(", ")}`);
  }

  // Google Ads: the manager account (login customer) must be accessible.
  if (vars.GOOGLE_ADS_DEVELOPER_TOKEN) {
    const version = vars.GOOGLE_ADS_API_VERSION || "v24";
    const ads = await getJson(
      `https://googleads.googleapis.com/${version}/customers:listAccessibleCustomers`,
      { ...auth, "developer-token": vars.GOOGLE_ADS_DEVELOPER_TOKEN },
    );
    const accessible = new Set((ads.resourceNames || []).map((name) => name.replace("customers/", "")));
    const login = String(vars.GOOGLE_ADS_LOGIN_CUSTOMER_ID || "").replace(/\D/g, "");
    if (login && !accessible.has(login)) {
      problems.push(`cannot access Google Ads manager account ${login}`);
    }
  }

  // BigQuery: report only; missing access here is fixed with IAM roles, not a new sign-in.
  const [bqProject, bqDataset] = [
    BIGQUERY_CHECK_DATASET.slice(0, BIGQUERY_CHECK_DATASET.lastIndexOf(".")),
    BIGQUERY_CHECK_DATASET.slice(BIGQUERY_CHECK_DATASET.lastIndexOf(".") + 1),
  ];
  const bq = await fetch(
    `https://bigquery.googleapis.com/bigquery/v2/projects/${bqProject}/datasets/${bqDataset}/tables?maxResults=1`,
    { headers: auth },
  );
  const bqOk = bq.ok;
  if (!bqOk) {
    warnings.push(
      `BigQuery: this account cannot read ${BIGQUERY_CHECK_DATASET} yet (HTTP ${bq.status}). It needs the roles BigQuery Data Viewer and BigQuery Job User in project ${bqProject}.`,
    );
  }

  console.log(`GA4 properties visible: ${ga4Visible.size}, Search Console sites: ${gscVisible.size}`);
  console.log(`BigQuery access to ${BIGQUERY_CHECK_DATASET}: ${bqOk ? "OK" : "not yet"}`);
  warnings.forEach((warning) => console.log(`WARNING: ${warning}`));

  if (problems.length) {
    console.log("\nNOT SAVED. The connector keeps its current login. Problems:");
    problems.forEach((problem) => console.log(`  - ${problem}`));
    console.log("\nMost likely you signed in with a different Google account. Run the command again and pick the account that has access to all client GA4 properties.");
    process.exit(1);
  }

  if (dryRun) {
    console.log("\nAll checks passed. --dry-run: nothing was saved.");
    process.exit(0);
  }

  execFileSync(
    "railway",
    ["variable", "set", "GOOGLE_REFRESH_TOKEN", "--stdin", ...railwayArgs],
    { input: token.refresh_token, stdio: ["pipe", "ignore", "inherit"] },
  );
  console.log("\nAll checks passed. Saved to Railway; the connector is redeploying now (about 1 minute).");
  process.exit(0);
}

async function getJson(url, headers = {}) {
  const response = await fetch(url, { headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`${new URL(url).hostname} returned ${response.status}: ${data.error?.message || data.error_description || "error"}`);
  }
  return data;
}

function fail(message) {
  console.error(`\nNOT SAVED. ${message}`);
  process.exit(1);
}
