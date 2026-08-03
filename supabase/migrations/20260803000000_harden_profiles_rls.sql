-- Harden profiles RLS: stop public email exposure.
--
-- Before: the profiles SELECT policy was `using (true)` and `grant all` was given
-- to `anon`, so anyone holding the client-side anon key could read EVERY user's
-- row — including the `email` column — via a single `select` (a public PII dump).
--
-- After: base-table reads are scoped to the row owner, and the public leaderboard
-- is served from a dedicated view that never selects email.

-- 1) Replace the permissive public SELECT policy with owner-only access.
drop policy if exists "Public profiles are viewable by everyone" on public.profiles;

drop policy if exists "Users can view their own profile" on public.profiles;
create policy "Users can view their own profile"
    on public.profiles for select
    using (auth.uid() = id);

-- 2) Let users delete their own profile (data-deletion / GDPR).
drop policy if exists "Users can delete their own profile" on public.profiles;
create policy "Users can delete their own profile"
    on public.profiles for delete
    using (auth.uid() = id);

-- 3) Public leaderboard WITHOUT PII.
--    This view intentionally runs with definer rights (security_invoker = false)
--    so it can read across users for the leaderboard, but it only ever exposes
--    non-PII columns — email is never selected. This is the sole public surface.
create or replace view public.leaderboard
with (security_invoker = false) as
    select id, display_name, avatar_url, xp, level
    from public.profiles;

-- 4) Least-privilege grants: anon can read only the leaderboard view; the base
--    table is reachable only by authenticated users (still scoped by RLS above).
revoke all on public.profiles from anon;
grant select, insert, update, delete on public.profiles to authenticated;
grant select on public.leaderboard to anon, authenticated;
