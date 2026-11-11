-- Fresh Beast Detailers: customer accounts, wash history, Beast Tokens, requests
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  phone text not null default '',
  parish text,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.washes (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id) on delete cascade,
  wash_date date not null default current_date,
  package text not null,
  addons text[] not null default '{}',
  amount integer not null check (amount >= 0),
  tokens integer generated always as (amount / 100) stored,
  paid_with_tokens boolean not null default false,
  photo_path text,
  notes text,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);
create index if not exists washes_customer_idx on public.washes(customer_id, wash_date desc);

create table if not exists public.redemptions (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id) on delete cascade,
  reward text not null,
  cost integer not null check (cost > 0),
  status text not null default 'pending' check (status in ('pending','used','cancelled')),
  created_at timestamptz not null default now()
);
create index if not exists redemptions_customer_idx on public.redemptions(customer_id);

create table if not exists public.requests (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id) on delete cascade,
  kind text not null check (kind in ('booking','rewash','token_wash')),
  wash_id uuid references public.washes(id) on delete set null,
  title text not null,
  details text,
  preferred_date date,
  preferred_time text,
  status text not null default 'requested' check (status in ('requested','confirmed','done','cancelled')),
  created_at timestamptz not null default now()
);
create index if not exists requests_customer_idx on public.requests(customer_id, created_at desc);
create unique index if not exists one_rewash_per_wash on public.requests(wash_id) where kind = 'rewash' and status <> 'cancelled';

-- Helpers
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.token_balance(uid uuid default auth.uid()) returns integer
language sql stable security definer set search_path = public as $$
  select case when uid = auth.uid() or public.is_admin() then
    coalesce((select sum(tokens) from public.washes where customer_id = uid),0)
    - coalesce((select sum(cost) from public.redemptions where customer_id = uid and status <> 'cancelled'),0)
  else null end;
$$;

-- New sign-ups get a profile
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name, phone)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name',''), coalesce(new.raw_user_meta_data->>'phone',''))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- Customers can't promote themselves to admin
create or replace function public.protect_admin_flag() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.is_admin is distinct from old.is_admin and not public.is_admin() then
    new.is_admin := old.is_admin;
  end if;
  return new;
end $$;
drop trigger if exists profiles_protect_admin on public.profiles;
create trigger profiles_protect_admin before update on public.profiles for each row execute function public.protect_admin_flag();

-- Customer actions (checked on the server)
create or replace function public.redeem_tokens(p_reward text) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_cost int; v_id uuid;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  v_cost := case p_reward when 'Beast Express Wash' then 200 when 'Beast Clean & Go' then 300 when 'Beast Premium Detail' then 550 end;
  if v_cost is null then raise exception 'Unknown reward'; end if;
  if public.token_balance(auth.uid()) < v_cost then raise exception 'Not enough Beast Tokens'; end if;
  insert into public.redemptions(customer_id, reward, cost) values (auth.uid(), p_reward, v_cost) returning id into v_id;
  insert into public.requests(customer_id, kind, title, details) values (auth.uid(), 'token_wash', p_reward || ' — paid with ' || v_cost || ' tokens', 'Token redemption ' || v_id);
  return v_id;
end $$;

create or replace function public.request_rewash(p_wash uuid, p_reasons text, p_date date, p_time text, p_notes text) returns uuid
language plpgsql security definer set search_path = public as $$
declare w public.washes; v_id uuid;
begin
  select * into w from public.washes where id = p_wash and customer_id = auth.uid();
  if not found then raise exception 'Wash not found'; end if;
  if w.wash_date < current_date - 7 then raise exception 'Rewash requests must be made within 7 days'; end if;
  if p_date < current_date then raise exception 'Pick a future date'; end if;
  insert into public.requests(customer_id, kind, wash_id, title, details, preferred_date, preferred_time)
  values (auth.uid(), 'rewash', p_wash, 'Rewash check-up — ' || w.package, p_reasons || coalesce(' · ' || nullif(p_notes,''), ''), p_date, p_time)
  returning id into v_id;
  return v_id;
end $$;

-- Row level security
alter table public.profiles enable row level security;
alter table public.washes enable row level security;
alter table public.redemptions enable row level security;
alter table public.requests enable row level security;

drop policy if exists "own profile read" on public.profiles;
create policy "own profile read" on public.profiles for select to authenticated using (id = (select auth.uid()) or (select public.is_admin()));
drop policy if exists "own profile update" on public.profiles;
create policy "own profile update" on public.profiles for update to authenticated using (id = (select auth.uid()) or (select public.is_admin())) with check (id = (select auth.uid()) or (select public.is_admin()));

drop policy if exists "washes read" on public.washes;
create policy "washes read" on public.washes for select to authenticated using (customer_id = (select auth.uid()) or (select public.is_admin()));
drop policy if exists "washes admin write" on public.washes;
create policy "washes admin write" on public.washes for all to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));

drop policy if exists "redemptions read" on public.redemptions;
create policy "redemptions read" on public.redemptions for select to authenticated using (customer_id = (select auth.uid()) or (select public.is_admin()));
drop policy if exists "redemptions admin write" on public.redemptions;
create policy "redemptions admin write" on public.redemptions for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));

drop policy if exists "requests read" on public.requests;
create policy "requests read" on public.requests for select to authenticated using (customer_id = (select auth.uid()) or (select public.is_admin()));
drop policy if exists "requests own booking" on public.requests;
create policy "requests own booking" on public.requests for insert to authenticated with check (customer_id = (select auth.uid()) and kind = 'booking' and status = 'requested');
drop policy if exists "requests admin update" on public.requests;
create policy "requests admin update" on public.requests for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));

revoke all on function public.redeem_tokens(text) from public, anon;
revoke all on function public.request_rewash(uuid,text,date,text,text) from public, anon;
grant execute on function public.redeem_tokens(text) to authenticated;
grant execute on function public.request_rewash(uuid,text,date,text,text) to authenticated;
revoke all on function public.token_balance(uuid) from public, anon;
grant execute on function public.token_balance(uuid) to authenticated;

-- Private bucket for wash verification photos (admin uploads; customers can view their own)
insert into storage.buckets (id, name, public) values ('wash-photos','wash-photos', false) on conflict (id) do nothing;
drop policy if exists "wash photos admin" on storage.objects;
create policy "wash photos admin" on storage.objects for all to authenticated using (bucket_id = 'wash-photos' and (select public.is_admin())) with check (bucket_id = 'wash-photos' and (select public.is_admin()));
drop policy if exists "wash photos own" on storage.objects;
create policy "wash photos own" on storage.objects for select to authenticated using (bucket_id = 'wash-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- Internal helpers are not callable from outside
revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.protect_admin_flag() from public, anon, authenticated;
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;
