import { test, expect } from "@playwright/test";

/** Seed persisted game state so onboarding does not block flows. */
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

async function openApp(page: import("@playwright/test").Page, path = "/") {
  await seedAgent(page);
  await page.goto(path);
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible({
    timeout: 15_000,
  });
}

test.describe("Security Trainer smoke tests", () => {
  test("onboarding and dashboard", async ({ page }) => {
    await openApp(page, "/");
    await expect(page.getByText("Welcome back, Agent.")).toBeVisible();
    await expect(page.getByLabel("Statistics")).toBeVisible();
    await expect(
      page.getByRole("link", { name: /Resume Training|Continue Mission/i }),
    ).toBeVisible();
  });

  test("modules list and lesson navigation", async ({ page }) => {
    await openApp(page, "/modules");
    await expect(
      page.getByRole("heading", { name: "Active Operations" }),
    ).toBeVisible();

    await page
      .getByRole("link", { name: /Start Mission|Continue/i })
      .first()
      .click();
    await expect(
      page.getByRole("heading", { name: "What is OWASP?", exact: true }),
    ).toBeVisible();
    await expect(page.getByLabel(/Lesson progress/i)).toBeVisible();

    await page.getByLabel("Go to next lesson").click();
    await expect(page.getByText("Knowledge Check")).toBeVisible();
  });

  test("learning paths page", async ({ page }) => {
    await openApp(page, "/paths");
    await expect(
      page.getByRole("heading", { name: "Learning Paths" }),
    ).toBeVisible();
    await expect(page.getByText("Web Security Fundamentals")).toBeVisible();
    await page.getByRole("link", { name: "Start Path" }).first().click();
    await expect(page.getByLabel("Path modules")).toBeVisible();
  });

  test("category filter on modules page", async ({ page }) => {
    await openApp(page, "/modules");
    await page.getByRole("button", { name: /Web Security/i }).click();
    await expect(page.getByText("Introduction to OWASP")).toBeVisible();
    await expect(page.getByText("API Security")).not.toBeVisible();
  });
});
