import { beforeEach, describe, expect, it, vi } from "vitest";
const { single } = vi.hoisted(() => ({ single: vi.fn() }));
vi.mock("../lib/supabase", () => ({
  isSupabaseConfigured: () => true,
  supabase: {
    from: () => ({
      update: () => ({ eq: () => ({ select: () => ({ single }) }) }),
    }),
  },
}));
import { useAuthStore } from "./authStore";
describe("profile save result", () => {
  beforeEach(() => {
    useAuthStore.setState({ user: { id: "fixture" } as never, profile: null });
    single.mockReset();
  });
  it.each(["resolved", "thrown"])(
    "reports %s database failure without changing the profile",
    async (mode) => {
      if (mode === "resolved")
        single.mockResolvedValue({
          data: null,
          error: { message: "Save failed" },
        });
      else single.mockRejectedValue(new Error("Save failed"));
      const result = await useAuthStore
        .getState()
        .updateProfile({ display_name: "Fixture" });
      expect(result).toMatchObject({ error: { message: "Save failed" } });
      expect(useAuthStore.getState().profile).toBeNull();
    },
  );
  it("reports successful save and stores the returned profile", async () => {
    const profile = { id: "fixture", display_name: "Fixture" };
    single.mockResolvedValue({ data: profile, error: null });
    expect(
      await useAuthStore.getState().updateProfile({ display_name: "Fixture" }),
    ).toEqual({
      error: null,
    });
    expect(useAuthStore.getState().profile).toEqual(profile);
  });
});
