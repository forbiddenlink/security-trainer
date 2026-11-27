import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const init = vi.fn();
vi.mock("posthog-js", () => ({ default: { init, capture: vi.fn() } }));

async function loadModule() {
  vi.resetModules();
  return import("./posthog");
}

describe("initPostHog", () => {
  beforeEach(() => {
    init.mockClear();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it.each(["", "   ", "undefined", "null"])(
    "does not call posthog.init when the key is %j",
    async (value) => {
      vi.stubEnv("VITE_POSTHOG_KEY", value);
      const { initPostHog } = await loadModule();
      initPostHog();
      await Promise.resolve();
      expect(init).not.toHaveBeenCalled();
    },
  );

  it("calls posthog.init with the trimmed key when set", async () => {
    vi.stubEnv("VITE_POSTHOG_KEY", " phc_placeholder ");
    const { initPostHog } = await loadModule();
    initPostHog();
    await vi.waitFor(() => expect(init).toHaveBeenCalledTimes(1));
    expect(init.mock.calls[0][0]).toBe("phc_placeholder");
  });
});

describe("resolvePostHogKey", () => {
  it("returns null for non-strings", async () => {
    const { resolvePostHogKey } = await loadModule();
    expect(resolvePostHogKey(undefined)).toBeNull();
  });
});
