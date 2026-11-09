-- DELIBERATELY INSECURE demo schema. See ../../README.md.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text,
  role text not null default 'user',
  created_at timestamptz default now()
);
alter table public.profiles enable row level security;
create policy "profiles select own" on public.profiles for select using (auth.uid() = id);
create policy "profiles update own" on public.profiles for update using (auth.uid() = id);

create function public.handle_new_user() returns trigger as $$
begin
  insert into public.profiles (id, username) values (new.id, new.email);
  return new;
end;
$$ language plpgsql security definer;
create trigger on_auth_user_created after insert on auth.users
  for each row execute procedure public.handle_new_user();

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  item text not null,
  total_cents integer not null default 0,
  created_at timestamptz default now()
);
alter table public.orders enable row level security;
-- BUG: "temporary" debugging policy that lets everyone read every order
create policy "orders read" on public.orders for select using (true);
create policy "orders insert own" on public.orders for insert with check (auth.uid() = user_id);
create policy "orders update own" on public.orders for update using (auth.uid() = user_id);

-- BUG: RLS is never enabled on this table
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null default ''
);

create table public.posts (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references auth.users(id) on delete cascade,
  title text not null default '',
  body text
);
alter table public.posts enable row level security;
create policy "posts public read" on public.posts for select using (true);
create policy "posts insert own" on public.posts for insert with check (auth.uid() = author_id);
-- BUG: any signed-in user can edit any post
create policy "posts update signed in" on public.posts for update using (auth.role() = 'authenticated');
create policy "posts delete own" on public.posts for delete using (auth.uid() = author_id);

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "avatar read" on storage.objects for select using (bucket_id = 'avatars');
create policy "avatar upload own" on storage.objects for insert
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
-- BUG: any signed-in user can delete anyone's avatar
create policy "avatar delete" on storage.objects for delete
  using (bucket_id = 'avatars' and auth.role() = 'authenticated');
