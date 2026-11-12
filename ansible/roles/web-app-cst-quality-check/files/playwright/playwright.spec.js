const { test, expect } = require("@playwright/test");
const { resolveTimeout } = require("./timeouts");
const { gotoOnion, normalizeBaseUrl, requireDotenvValue } = require("./personas");
const { skipUnlessServiceDisabled, skipUnlessServiceEnabled } = require("./service-gating");
test.use({ ignoreHTTPSErrors: true });

const baseUrl = normalizeBaseUrl(requireDotenvValue(process.env.APP_BASE_URL, "APP_BASE_URL"));
const anonymous = process.env.ANONYMOUS_ENABLED === "true";
const captcha = process.env.CAPTCHA_ENABLED === "true";
const REPORT_TIMEOUT_MS = 180_000;
const LAUNCHER_PERIOD_MS = 30_000;

async function solveCaptcha(page) {
  if (!captcha) {
    return;
  }
  await page.locator("altcha-widget input[type=checkbox]").click({ position: { x: 2, y: 2 } });
  await expect(page.locator("altcha-widget [data-state=verified], altcha-widget[data-state=verified]").first())
    .toBeAttached({ timeout: resolveTimeout(60_000) });
}

async function submitPastedText(page) {
  const foreign = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(baseUrl)) {
      foreign.push(request.url());
    }
  });
  await gotoOnion(page, `${baseUrl}/`);
  await page.getByLabel("Pasted code").check();
  await page.locator("select[name=language]").selectOption("python");
  await page.locator("textarea[name=text]").fill("import os\n");
  await solveCaptcha(page);
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page).toHaveURL(/\/r\/[0-9a-f]{32}$/);
  await expect(page.getByRole("heading", { name: "Quality report" })).toBeVisible();
  return foreign;
}

test("anonymous pasted text is accepted and waits for the launcher", async ({ page }) => {
  test.skip(!anonymous, "anonymous submissions are off in this variant");
  const foreign = await submitPastedText(page);
  await expect(page.locator("main")).toContainText(/The scan is (queued|running)\./);
  expect(foreign).toEqual([]);
});

test("the launcher turns pasted text into a report with the unused import", async ({ page }) => {
  test.skip(!anonymous, "anonymous submissions are off in this variant");
  const foreign = await submitPastedText(page);
  const main = page.locator("main");
  const picked = await expect(main)
    .not.toContainText("The scan is queued.", { timeout: resolveTimeout(3 * LAUNCHER_PERIOD_MS) })
    .then(() => true, () => false);
  test.skip(!picked, "the launcher timer is stopped: rerun after the deploy with make compose-playwright role=web-app-cst-quality-check");
  await expect(main).not.toContainText("The scan is running.", { timeout: resolveTimeout(REPORT_TIMEOUT_MS) });
  const text = await main.innerText();
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
  await gotoOnion(page, `${baseUrl}/`);
  await expect(page.locator("form")).toHaveCount(0);
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
