import { test, expect } from "@playwright/test";

async function seedAgent(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    localStorage.setItem(
      "security-trainer-storage",
      JSON.stringify({
        state: {
          xp: 0,
          level: 1,
          completedModules: [],
          completedLessons: [],
          badges: [],
          currentModuleId: null,
          streakDays: 1,
          lastLoginDate: new Date().toISOString().slice(0, 10),
          dailyChallengeId: null,
          dailyChallengeDate: null,
          dailyChallengeCompleted: false,
          lessonReviews: {},
          completedPaths: [],
          ctfProgress: {},
          ctfTotalPoints: 0,
          userRole: "skipped",
        },
        version: 0,
      }),
    );
  });
}

async function openApp(page: import("@playwright/test").Page, path: string) {
  await seedAgent(page);
  await page.goto(path);
}

test.describe("Security Trainer expanded flows", () => {
  test("module search filters missions", async ({ page }) => {
    await openApp(page, "/modules");
    await page.getByLabel("Search modules").fill("SQL");
    await expect(page.getByText("SQL Injection (SQLi)")).toBeVisible();
    await expect(page.getByText("Cross-Site Scripting")).not.toBeVisible();
  });

  test("CTF challenge select and flag format validation", async ({ page }) => {
    await openApp(page, "/ctf");
    await expect(
      page.getByRole("heading", { name: "CTF Challenges" }),
    ).toBeVisible();

    await page.getByRole("button", { name: /Cookie Monster/i }).click();
    await expect(page.getByText("Description")).toBeVisible();

    const flagInput = page.getByPlaceholder("FLAG{...}");
    await flagInput.fill("not-a-flag");
    await page.getByRole("button", { name: /Submit/i }).click();
    await expect(page.getByText(/FLAG\{/)).toBeVisible();
  });

  test("CTF correct flag submission", async ({ page }) => {
    await openApp(page, "/ctf");
    await page.getByRole("button", { name: /Cookie Monster/i }).click();

    const flagInput = page.getByPlaceholder("FLAG{...}");
    await flagInput.fill("FLAG{c00kies_are_delicious}");
    await page.getByRole("button", { name: /Submit/i }).click();
    await expect(page.getByText(/Correct|earned|Completed/i)).toBeVisible({
      timeout: 10_000,
    });
  });

  test("lab view shows intel briefing and deploy", async ({ page }) => {
    await openApp(page, "/modules/owasp-intro/owasp-lab");
    await expect(page.getByText("Mission Objective")).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.getByText("Intel Briefing")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Deploy Patch/i }),
    ).toBeVisible();
  });

  test("final exam start screen", async ({ page }) => {
    await openApp(page, "/challenge");
    await expect(
      page.getByRole("region", { name: /Final exam start/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Start the final exam/i }),
    ).toBeVisible();
  });

  test("reviews page loads", async ({ page }) => {
    await openApp(page, "/reviews");
    await expect(
      page.getByRole("heading", { name: /Intel Refresher/i }),
    ).toBeVisible();
  });

  test("intel review nav link works", async ({ page }) => {
    await openApp(page, "/");
    await page.getByRole("link", { name: /Intel Review/i }).click();
    await expect(page).toHaveURL(/\/reviews/);
  });

  test("learning path detail via paths page", async ({ page }) => {
    await openApp(page, "/paths/web-fundamentals");
    await expect(
      page.getByText(/Operation Firewall|Web Security Fundamentals/i).first(),
    ).toBeVisible();
  });
});
