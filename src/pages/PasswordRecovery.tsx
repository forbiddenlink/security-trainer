import { useEffect, useState, type FormEvent } from "react";
import { Button, Input } from "../components/ui";
import { useAuthStore } from "../store/authStore";
import { isSupabaseConfigured } from "../lib/supabase";
import { saveRecoveredPassword, useRecovery } from "../lib/passwordRecovery";

export function PasswordRecovery() {
  const { ready, userId } = useRecovery();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  useEffect(() => {
    document.title = "Reset password · Security Trainer";
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (busy) return;
    setError("");
    if (userId && password !== confirmation) {
      setError("The passwords must match.");
      return;
    }
    setBusy(true);
    try {
      if (userId) {
        await saveRecoveredPassword(password);
        setPassword("");
        setConfirmation("");
        setNotice("Your password has been updated.");
      } else {
        const { error } = await useAuthStore
          .getState()
          .resetPasswordForEmail(email);
        if (error)
          throw new Error("Could not request an email. Please try again.");
        setNotice(
          "If this address has an account, check your email for a fresh link.",
        );
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen grid place-items-center bg-background text-foreground p-4">
      <section className="ui-card w-full max-w-md p-6 space-y-5">
        <h1 className="text-h2">Reset password</h1>
        {!ready ? (
          <p role="status">Checking your link…</p>
        ) : notice ? (
          <p role="status">{notice}</p>
        ) : !isSupabaseConfigured() ? (
          <p>Account recovery is unavailable on this installation.</p>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            {userId ? (
              <>
                <label htmlFor="recovery-new" className="block">
                  New password
                  <Input
                    id="recovery-new"
                    autoComplete="new-password"
                    type="password"
                    minLength={6}
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                </label>
                <label htmlFor="recovery-confirm" className="block">
                  Confirm new password
                  <Input
                    id="recovery-confirm"
                    autoComplete="new-password"
                    type="password"
                    required
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                  />
                </label>
              </>
            ) : (
              <>
                <p>
                  Request a new email if your reset link has expired or has
                  already been used.
                </p>
                <label htmlFor="recovery-email" className="block">
                  Email
                  <Input
                    id="recovery-email"
                    type="email"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                  />
                </label>
              </>
            )}
            {error && <p role="alert">{error}</p>}
            <Button type="submit" variant="signal" disabled={busy}>
              {userId ? "Save new password" : "Send reset email"}
            </Button>
          </form>
        )}
        <a className="btn-ghost-rule" href="/">
          Return to training
        </a>
      </section>
    </main>
  );
}
