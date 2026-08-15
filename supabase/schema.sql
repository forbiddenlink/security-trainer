-- Security Trainer Database Schema
-- Run this in your Supabase SQL editor to set up the database

-- Create profiles table
create table if not exists public.profiles (
    id uuid references auth.users on delete cascade primary key,
    email text,
    display_name text,
    avatar_url text,
    xp integer default 0,
    level integer default 1,
    badges text[] default '{}',
    completed_modules text[] default '{}',
    completed_lessons text[] default '{}',
    streak_days integer default 0,
    last_login_date text,
    daily_challenge_id text,
    daily_challenge_date text,
    daily_challenge_completed boolean default false,
    updated_at timestamp with time zone default now()
);

-- Enable Row Level Security
alter table public.profiles enable row level security;

-- Create policies
-- SELECT is owner-only: the anon key ships in the client bundle, so a public
-- SELECT policy would expose every user's email. Public reads go through the
-- PII-free `leaderboard` view below instead.
create policy "Users can view their own profile"
    on public.profiles for select
    using (auth.uid() = id);

create policy "Users can insert their own profile"
    on public.profiles for insert
    with check (auth.uid() = id);

create policy "Users can update their own profile"
    on public.profiles for update
    using (auth.uid() = id);

create policy "Users can delete their own profile"
    on public.profiles for delete
    using (auth.uid() = id);

-- Public leaderboard WITHOUT PII. Definer-rights view (security_invoker = false)
-- reads across users but only exposes non-PII columns — email is never selected.
create or replace view public.leaderboard
with (security_invoker = false) as
    select id, display_name, avatar_url, xp, level
    from public.profiles;

-- Create index for leaderboard queries
create index if not exists profiles_xp_idx on public.profiles (xp desc);

-- Function to automatically create a profile on user signup
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    insert into public.profiles (id, email, display_name)
    values (
        new.id,
        new.email,
        coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1))
    );
    return new;
end;
$$;

-- Trigger to call the function on user creation
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute procedure public.handle_new_user();

-- Grant necessary permissions (least privilege).
-- anon may read ONLY the leaderboard view; the base table is reachable only by
-- authenticated users, still row-scoped by the policies above.
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on public.profiles to authenticated;
grant select on public.leaderboard to anon, authenticated;
