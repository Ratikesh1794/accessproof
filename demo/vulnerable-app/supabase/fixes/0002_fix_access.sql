-- The fix for 0001_init.sql. Copy into supabase/migrations/ to turn the tests green.

-- orders: only the owner may read
drop policy "orders read" on public.orders;
create policy "orders read own" on public.orders for select using (auth.uid() = user_id);
create policy "orders delete own" on public.orders for delete using (auth.uid() = user_id);

-- notes: enable RLS and scope to the owner
alter table public.notes enable row level security;
create policy "notes own" on public.notes for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- posts: only the author may edit
drop policy "posts update signed in" on public.posts;
create policy "posts update own" on public.posts for update using (auth.uid() = author_id);

-- avatars: only the owner may delete
drop policy "avatar delete" on storage.objects;
create policy "avatar delete own" on storage.objects for delete
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar update own" on storage.objects for update
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- profiles: users must not change their own role
create function public.block_role_change() returns trigger as $$
begin
  if new.role is distinct from old.role and current_user <> 'postgres' and coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'role cannot be changed';
  end if;
  return new;
end;
$$ language plpgsql;
create trigger profiles_block_role before update on public.profiles
  for each row execute procedure public.block_role_change();
