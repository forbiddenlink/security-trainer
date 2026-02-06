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
create policy "Public profiles are viewable by everyone"
    on public.profiles for select
    using (true);

create policy "Users can insert their own profile"
    on public.profiles for insert
    with check (auth.uid() = id);

create policy "Users can update their own profile"
    on public.profiles for update
    using (auth.uid() = id);

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

-- Grant necessary permissions
grant usage on schema public to anon, authenticated;
grant all on public.profiles to anon, authenticated;
