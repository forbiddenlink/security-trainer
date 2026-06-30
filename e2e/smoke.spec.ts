import { test, expect } from "@playwright/test";

async function completeOnboarding(page: import("@playwright/test").Page) {
  await page.goto("/");
  const roleSection = page.getByRole("region", { name: "Role selection" });
  if (await roleSection.isVisible()) {
    await page.getByRole("button", { name: /Developer \/ Engineer/i }).click();
    await expect(page.getByText("Welcome back, Agent.")).toBeVisible();
  }
}

test.describe("Security Trainer smoke tests", () => {
  test("onboarding and dashboard", async ({ page }) => {
    await completeOnboarding(page);
    await expect(page.getByRole("main")).toBeVisible();
    await expect(page.getByLabel("Statistics")).toBeVisible();
    await expect(page.getByLabel("Resume training modules")).toBeVisible();
  });

  test("modules list and lesson navigation", async ({ page }) => {
    await completeOnboarding(page);
    await page.getByLabel("Resume training modules").click();
    await expect(
      page.getByRole("heading", { name: "Active Operations" }),
    ).toBeVisible();

    await page.getByRole("link", { name: "Start Mission" }).first().click();
    await expect(page.getByText("What is OWASP?")).toBeVisible();
    await expect(page.getByLabel(/Lesson progress/i)).toBeVisible();

    await page.getByLabel("Go to next lesson").click();
    await expect(page.getByText("Knowledge Check")).toBeVisible();
  });

  test("learning paths page", async ({ page }) => {
    await completeOnboarding(page);
    await page.goto("/paths");
    await expect(
      page.getByRole("heading", { name: "Learning Paths" }),
    ).toBeVisible();
    await expect(page.getByText("Web Security Fundamentals")).toBeVisible();
    await page.getByRole("link", { name: "Start Path" }).first().click();
    await expect(page.getByLabel("Path modules")).toBeVisible();
  });

  test("category filter on modules page", async ({ page }) => {
    await completeOnboarding(page);
    await page.goto("/modules");
    await page.getByRole("button", { name: /Web Security/i }).click();
    await expect(page.getByText("Introduction to OWASP")).toBeVisible();
    await expect(page.getByText("API Security")).not.toBeVisible();
  });
});
