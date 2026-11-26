const { test, expect } = require("@playwright/test");
const { openScriptSources } = require("./csp-policy");
const { resolveTimeout } = require("./timeouts");
const {
  assertCspResponseHeader,
  assertUnauthenticatedLanding,
  attachDiagnostics,
  expectNoCspViolations,
  gotoOnion,
  inAppLogout,
  installCspViolationObserver,
  keycloakAdminAddUserToGroup,
  keycloakRemoveUserFromGroupViaRest,
  normalizeBaseUrl,
  performKeycloakLoginForm,
  requireDotenvValue,
} = require("./personas");
const { skipUnlessServiceDisabled, skipUnlessServiceEnabled } = require("./service-gating");
test.use({ ignoreHTTPSErrors: true });

const baseUrl = normalizeBaseUrl(requireDotenvValue(process.env.APP_BASE_URL, "APP_BASE_URL"));
const anonymous = process.env.ANONYMOUS_ENABLED === "true";
const captcha = process.env.CAPTCHA_ENABLED === "true";
const cdnOrigin = new URL(requireDotenvValue(process.env.CDN_BASE_URL, "CDN_BASE_URL")).origin;
const REPORT_TIMEOUT_MS = 180_000;
const URL_REPORT_TIMEOUT_MS = 900_000;
const LAUNCHER_PERIOD_MS = 30_000;
const CAPTCHA_TIMEOUT_MS = 60_000;
const LOGIN_TIMEOUT_MS = 60_000;
const CLEANUP_TIMEOUT_MS = 30_000;
const SUBMISSION_BUDGET_MS = 5_000;
const PAGE_MARGIN_MS = 60_000;
const SESSION_COOKIE = "__Host-quality-session";
const REPORT_PATH = /\/r\/[0-9a-f]{32}$/;
const PENDING_OR_DONE = /The scan is running\.|Findings in the rules that ran: \d+\.|Not checked:/;
const DONE = /Findings in the rules that ran: \d+\.|Not checked:/;
const SNIPPET = "import os\n";

function perUserLimit() {
  return Number(requireDotenvValue(process.env.REGISTERED_PER_USER_HOUR, "REGISTERED_PER_USER_HOUR"));
}

function assertClosedCsp(response, label) {
  expect(
    openScriptSources(assertCspResponseHeader(response, label), cdnOrigin),
    `${label}: the rendered CSP MUST run scripts and the captcha worker from 'self' only`,
  ).toEqual([]);
}

async function solveCaptcha(page, workers) {
  if (!captcha) {
    return;
  }
  await page.locator("altcha-widget input[type=checkbox]").click({ position: { x: 2, y: 2 } });
  await expect(page.locator("altcha-widget [data-state=verified], altcha-widget[data-state=verified]").first())
    .toBeAttached({ timeout: resolveTimeout(CAPTCHA_TIMEOUT_MS) });
  expect(workers.length, "the captcha MUST solve in its worker").toBeGreaterThan(0);
  expect(workers.filter((url) => new URL(url).origin !== new URL(baseUrl).origin), "the captcha worker MUST load from 'self'")
    .toEqual([]);
}

function repositoryUrl(url) {
  return async (page) => {
    await page.getByLabel("Public repository URL").check();
    await page.locator("input[name=url]").fill(url);
  };
}

function uploadedFile(name, content) {
  return async (page) => {
    await page.getByLabel(/One file/).check();
    await page.locator("input[name=file]").setInputFiles({ name, mimeType: "text/plain", buffer: Buffer.from(content) });
  };
}

function pastedText(language, content) {
  return async (page) => {
    await page.getByLabel("Pasted code").check();
    await page.locator("select[name=language]").selectOption(language);
    await page.locator("textarea[name=text]").fill(content);
  };
}

async function submitAnonymously(page, fill) {
  const foreign = [];
  const workers = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(`${baseUrl}/`)) {
      foreign.push(request.url());
    }
  });
  page.on("worker", (worker) => workers.push(worker.url()));
  const diagnostics = attachDiagnostics(page);
  await installCspViolationObserver(page);
  assertClosedCsp(await gotoOnion(page, `${baseUrl}/`), "start page");
  await fill(page);
  await solveCaptcha(page, workers);
  await expectNoCspViolations(page, diagnostics, "start page");
  const report = page.waitForResponse(
    (response) => REPORT_PATH.test(response.url()) && response.request().resourceType() === "document",
  );
  await page.getByRole("button", { name: "Check" }).click();
  assertClosedCsp(await report, "report page");
  await expect(page).toHaveURL(REPORT_PATH);
  await expect(page.getByRole("heading", { name: "Quality report" })).toBeVisible();
  await expect(page.locator("main")).toContainText(/The scan is (queued|running)\./);
  await expectNoCspViolations(page, diagnostics, "report page");
  return foreign;
}

async function awaitReport(page, timeoutMs) {
  const main = page.locator("main");
  const picked = await expect(main)
    .toContainText(PENDING_OR_DONE, { timeout: resolveTimeout(3 * LAUNCHER_PERIOD_MS) })
    .then(() => true, () => false);
  test.skip(!picked, "the launcher timer is stopped: rerun after the deploy with make compose-playwright role=web-app-cst-quality-check");
  await expect(main).toContainText(DONE, { timeout: resolveTimeout(timeoutMs) });
  await expect(main).not.toContainText("Not checked:");
  return main.innerText();
}

function anonymousBudget(reportMs) {
  return resolveTimeout(CAPTCHA_TIMEOUT_MS + 3 * LAUNCHER_PERIOD_MS + reportMs + PAGE_MARGIN_MS);
}

async function submitAtAccount(page, fill) {
  await gotoOnion(page, `${baseUrl}/account/`);
  await fill(page);
  const posted = page.waitForResponse(
    (response) => response.request().method() === "POST" && response.url() === `${baseUrl}/account/submit`,
    { timeout: resolveTimeout(LOGIN_TIMEOUT_MS) },
  );
  await page.getByRole("button", { name: "Check" }).click();
  const status = (await posted).status();
  if (status === 303) {
    await expect(page).toHaveURL(REPORT_PATH);
  }
  return status;
}

async function submitRepeatedly(page, attempts) {
  const fill = repositoryUrl(requireDotenvValue(process.env.UNREACHABLE_REPOSITORY_URL, "UNREACHABLE_REPOSITORY_URL"));
  const statuses = [];
  while (statuses.length < attempts && statuses.every((status) => status === 303)) {
    statuses.push(await submitAtAccount(page, fill));
  }
  return statuses;
}

async function logIn(page, username, password) {
  await gotoOnion(page, `${baseUrl}/`);
  await page.getByRole("link", { name: "Log in" }).click({ timeout: resolveTimeout(LOGIN_TIMEOUT_MS) });
  await expect(page).toHaveURL(/\/protocol\/openid-connect\/auth/, { timeout: resolveTimeout(LOGIN_TIMEOUT_MS) });
  await performKeycloakLoginForm(page, username, password);
  await expect(page).toHaveURL(`${baseUrl}/account/`, { timeout: resolveTimeout(LOGIN_TIMEOUT_MS) });
  await expect(page.getByRole("link", { name: username })).toBeVisible();
  await expect(page.getByRole("link", { name: "Log out" })).toBeVisible();
}

async function logOut(page) {
  await inAppLogout(page);
  const cookies = await page.context().cookies(baseUrl);
  expect(cookies.map((cookie) => cookie.name), "the app session MUST end on logout").not.toContain(SESSION_COOKIE);
  await assertUnauthenticatedLanding(page, baseUrl);
  await expect(page.getByRole("link", { name: "Log in" })).toBeVisible();
}

function withDeadline(promise, ms, label) {
  let timer;
  const deadline = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} exceeded ${ms} ms`)), ms);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

/**
 * Args:
 *   browser: Playwright browser that opens the context for the Keycloak admin calls.
 *   username: Keycloak user name of the account.
 *   member: true joins the account to the role group for body, false takes it out; a change is undone afterwards.
 *   body: async function run while the membership holds; its result is returned.
 */
async function withMembership(browser, username, member, body) {
  const admin = [
    requireDotenvValue(process.env.SUPER_ADMIN_USERNAME, "SUPER_ADMIN_USERNAME"),
    requireDotenvValue(process.env.SUPER_ADMIN_PASSWORD, "SUPER_ADMIN_PASSWORD"),
  ];
  const opts = {
    adminRealm: requireDotenvValue(process.env.KEYCLOAK_ADMIN_REALM, "KEYCLOAK_ADMIN_REALM"),
    adminClientId: requireDotenvValue(process.env.KEYCLOAK_ADMIN_CLI_CLIENT_ID, "KEYCLOAK_ADMIN_CLI_CLIENT_ID"),
  };
  const keycloak = [
    normalizeBaseUrl(requireDotenvValue(process.env.KEYCLOAK_BASE_URL, "KEYCLOAK_BASE_URL")),
    requireDotenvValue(process.env.KEYCLOAK_REALM_NAME, "KEYCLOAK_REALM_NAME"),
  ];
  const group = requireDotenvValue(process.env.RBAC_MEMBER_GROUP_PATH, "RBAC_MEMBER_GROUP_PATH");
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const join = () => keycloakAdminAddUserToGroup(context.request, ...keycloak, group, username, ...admin, opts);
  const leave = () => keycloakRemoveUserFromGroupViaRest(context.request, ...keycloak, ...admin, group, username, opts);
  let restore = null;
  try {
    const joined = await join();
    if (member) {
      restore = joined ? leave : null;
    } else {
      await leave();
      restore = joined ? null : join;
    }
    return await body();
  } finally {
    if (restore) {
      await withDeadline(restore(), resolveTimeout(CLEANUP_TIMEOUT_MS), `Restoring ${username} in ${group}`)
        .catch((error) => console.warn(`Restoring the membership of ${username} in ${group} failed: ${error}`));
    }
    await context.close().catch(() => {});
  }
}

test("anonymous: this repository's public URL is accepted, queued and scanned at HEAD", async ({ page }) => {
  test.skip(!anonymous, "anonymous submissions are off in this variant");
  test.setTimeout(anonymousBudget(URL_REPORT_TIMEOUT_MS));
  const foreign = await submitAnonymously(page, repositoryUrl(requireDotenvValue(process.env.REPOSITORY_URL, "REPOSITORY_URL")));
  expect(foreign).toEqual([]);
  await awaitReport(page, URL_REPORT_TIMEOUT_MS);
  await expect(page.locator("dl.header")).toContainText(/Commit\s*[0-9a-f]{40}/);
  await expect(page.locator("main")).toContainText("HEAD only: history not scanned");
  expect(foreign).toEqual([]);
});

test("anonymous: an uploaded file is accepted, queued and reported with the unused import", async ({ page }) => {
  test.skip(!anonymous, "anonymous submissions are off in this variant");
  test.setTimeout(anonymousBudget(REPORT_TIMEOUT_MS));
  const foreign = await submitAnonymously(page, uploadedFile("upload.py", SNIPPET));
  expect(foreign).toEqual([]);
  const text = await awaitReport(page, REPORT_TIMEOUT_MS);
  expect(text).toContain("coding.unused-import");
  expect(text).toContain("upload.py");
  expect(foreign).toEqual([]);
});

test("anonymous: pasted text is accepted, queued and reported with the unused import", async ({ page }) => {
  test.skip(!anonymous, "anonymous submissions are off in this variant");
  test.setTimeout(anonymousBudget(REPORT_TIMEOUT_MS));
  const foreign = await submitAnonymously(page, pastedText("python", SNIPPET));
  expect(foreign).toEqual([]);
  const text = await awaitReport(page, REPORT_TIMEOUT_MS);
  expect(text).toContain("coding.unused-import");
  expect(text).not.toContain("badge");
  expect(foreign).toEqual([]);
});

test("report pages refuse unknown ids and send no referrer", async ({ page }) => {
  const response = await gotoOnion(page, `${baseUrl}/r/${"0".repeat(32)}`);
  expect(response.status()).toBe(404);
  expect(response.headers()["referrer-policy"]).toBe("no-referrer");
  expect(response.headers()["x-robots-tag"]).toContain("noindex");
});

test("without anonymous access the start page holds no form", async ({ page }) => {
  test.skip(anonymous, "anonymous submissions are on in this variant");
  assertClosedCsp(await gotoOnion(page, `${baseUrl}/`), "start page");
  await expect(page.locator("form")).toHaveCount(0);
  await expect(page.locator("main")).toContainText("Scans are available after logging in.");
});

test("with SSO the login sends the browser to the identity provider", async ({ request }) => {
  skipUnlessServiceEnabled("sso");
  const response = await request.get(`${baseUrl}/account/login`, { maxRedirects: 0, timeout: resolveTimeout(30_000) });
  expect(response.status()).toBe(302);
  expect(response.headers()["location"]).toContain("code_challenge_method=S256");
});

test("without SSO the login route does not exist", async ({ request }) => {
  skipUnlessServiceDisabled("sso");
  const response = await request.get(`${baseUrl}/account/login`, { maxRedirects: 0, timeout: resolveTimeout(30_000) });
  expect(response.status()).toBe(404);
});

/**
 * Args:
 *   browser: Playwright browser that opens the context for the Keycloak admin calls.
 *   page: Page the account logs in and submits on.
 *   persona: Prefix of the account's dotenv keys, ADMIN or BIBER.
 *   member: true submits as a member of the role group, false from outside it.
 *   judge: function given the statuses of limit + 1 submissions, the limit and the user name, run before the logout.
 */
async function submitPastTheLimit(browser, page, persona, member, judge) {
  skipUnlessServiceEnabled("sso");
  const limit = perUserLimit();
  test.setTimeout(resolveTimeout(4 * LOGIN_TIMEOUT_MS + (limit + 1) * SUBMISSION_BUDGET_MS));
  const username = requireDotenvValue(process.env[`${persona}_USERNAME`], `${persona}_USERNAME`);
  const password = requireDotenvValue(process.env[`${persona}_PASSWORD`], `${persona}_PASSWORD`);
  await withMembership(browser, username, member, async () => {
    await logIn(page, username, password);
    judge(await submitRepeatedly(page, limit + 1), limit, username);
    await logOut(page);
  });
}

test("administrator: as a member of the role group submits at /account/ beyond the per-user limit", async ({ browser, page }) => {
  await submitPastTheLimit(browser, page, "ADMIN", true, (statuses, limit) => {
    expect(statuses, `a member MUST pass ${limit + 1} submissions, one more than registered_per_user_hour`)
      .toEqual(Array(limit + 1).fill(303));
  });
});

test("biber: outside the role group submits at /account/ up to the per-user limit", async ({ browser, page }) => {
  await submitPastTheLimit(browser, page, "BIBER", false, (statuses, limit, username) => {
    test.skip(
      statuses.length === 1 && statuses[0] === 429,
      `${username} spent registered_per_user_hour earlier in this clock hour: rerun after the hour turns or the web app restarts`,
    );
    expect(statuses, `an account outside the group MUST pass ${limit} submissions and get 429 on the next`)
      .toEqual([...Array(limit).fill(303), 429]);
  });
});
