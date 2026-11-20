-- Function to automatically create a profile on user signup
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
    insert into public.profiles (id, email, display_name)
    values (
        new.id,
        new.email,
        coalesce(nullif(trim(new.raw_user_meta_data->>'display_name'), ''), 'Agent')
    );
    return new;
end;
$$;

-- Trigger to call the function on user creation
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute procedure public.handle_new_user();


revoke all on function public.handle_new_user() from public, anon, authenticated;

create or replace function public.delete_own_account()
returns void language sql security definer set search_path = ''
as $$
    delete from auth.users where id = (select auth.uid());
$$;

revoke all on function public.delete_own_account() from public, anon, authenticated;
grant execute on function public.delete_own_account() to authenticated;

-- Supabase projects may provide broad default privileges on new public tables.
revoke all on public.profiles from public, anon, authenticated;
grant select, insert, update, delete on public.profiles to authenticated;
revoke all on public.leaderboard from public, anon, authenticated;
grant select on public.leaderboard to anon, authenticated;
