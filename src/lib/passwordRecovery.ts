import { create } from "zustand";
import { supabase } from "./supabase";

export function isRecoveryLocation(url: URL): boolean {
  const fragment = new URLSearchParams(url.hash.slice(1));
  return (
    url.pathname === "/reset-password" ||
    fragment.get("type") === "recovery" ||
    [fragment, url.searchParams].some(
      (params) => params.get("error_code") === "otp_expired",
    )
  );
}

interface RecoveryState {
  ready: boolean;
  userId: string | null;
}

export const useRecovery = create<RecoveryState>(() => ({
  ready: false,
  userId: null,
}));

// Subscribe during startup, before the auth client finishes processing the email link.
export function observeRecovery(url: URL): void {
  const fragment = new URLSearchParams(url.hash.slice(1));
  const hasCallback =
    (fragment.get("type") === "recovery" && fragment.has("access_token")) ||
    url.searchParams.has("code");
  if (
    !supabase ||
    !hasCallback ||
    fragment.has("error") ||
    url.searchParams.has("error")
  ) {
    useRecovery.setState({ ready: true, userId: null });
    return;
  }
  supabase.auth.onAuthStateChange((event, session) => {
    if (event === "PASSWORD_RECOVERY" && session) {
      useRecovery.setState({ ready: true, userId: session.user.id });
    } else if (!session || session.user.id !== useRecovery.getState().userId) {
      useRecovery.setState({ ready: true, userId: null });
    }
  });
}

export async function saveRecoveredPassword(password: string): Promise<void> {
  const userId = useRecovery.getState().userId;
  if (!supabase || !userId)
    throw new Error("Request a fresh password reset link.");
  const { data, error: sessionError } = await supabase.auth.getSession();
  if (
    sessionError ||
    data.session?.user.id !== userId ||
    useRecovery.getState().userId !== userId
  ) {
    useRecovery.setState({ userId: null });
    throw new Error("Request a fresh password reset link.");
  }
  const { error } = await supabase.auth.updateUser({ password });
  if (error) throw new Error(error.message);
  useRecovery.setState({ userId: null });
}
