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

drop policy if exists "Users can insert their own profile" on public.profiles;
create policy "Users can insert their own profile"
    on public.profiles for insert
    with check (auth.uid() = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
    on public.profiles for update
    using (auth.uid() = id);

-- Create index for leaderboard queries
create index if not exists profiles_xp_idx on public.profiles (xp desc);
