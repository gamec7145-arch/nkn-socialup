-- NKN SocialUp: secure panel database functions
-- Run in Supabase SQL Editor. Review existing tables before production use.
-- This migration builds on the tables already created for NKN SocialUp.

create table if not exists public.wallet_balances (
  user_id uuid primary key references auth.users(id) on delete cascade,
  balance numeric(12,2) not null default 0 check (balance >= 0),
  updated_at timestamptz not null default now()
);

alter table public.wallet_balances enable row level security;
revoke all on public.wallet_balances from anon, authenticated;
grant select on public.wallet_balances to authenticated;
drop policy if exists "Users read own wallet balance" on public.wallet_balances;
create policy "Users read own wallet balance"
on public.wallet_balances for select to authenticated
using (user_id = auth.uid());

-- Ensure new auth users receive a profile and wallet.
create or replace function public.nkn_handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;

  insert into public.wallet_balances (user_id, balance)
  values (new.id, 0)
  on conflict (user_id) do nothing;

  insert into public.user_roles (user_id, role)
  values (new.id, 'customer')
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists nkn_on_auth_user_created on auth.users;
create trigger nkn_on_auth_user_created
after insert on auth.users
for each row execute procedure public.nkn_handle_new_user();

-- Helpers for all security-definer RPCs. User role cannot be self-assigned
-- from the browser: user_roles has no authenticated INSERT/UPDATE grant.
create or replace function public.nkn_is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.user_roles r
    where r.user_id = auth.uid() and r.role = 'admin'
  );
$$;
revoke all on function public.nkn_is_admin() from public;
grant execute on function public.nkn_is_admin() to authenticated;

-- Atomic order placement: server validates service/quantity and charges wallet.
create or replace function public.place_order(
  p_service_id bigint,
  p_link text,
  p_quantity integer
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_service public.services%rowtype;
  v_balance numeric(12,2);
  v_cost numeric(12,2);
  v_order_id bigint;
begin
  if v_uid is null then raise exception 'Please log in first.'; end if;
  if p_link is null or length(trim(p_link)) < 8 or length(p_link) > 1000
     or trim(p_link) !~* '^https?://' then
    raise exception 'Enter a valid http or https link.';
  end if;
  if p_quantity is null or p_quantity <= 0 then raise exception 'Quantity must be positive.'; end if;

  select * into v_service from public.services
  where id = p_service_id and active = true for share;
  if not found then raise exception 'Service is unavailable.'; end if;
  if p_quantity < v_service.min_quantity or p_quantity > v_service.max_quantity then
    raise exception 'Quantity is outside the allowed range (% to %).', v_service.min_quantity, v_service.max_quantity;
  end if;
  v_cost := round((v_service.price_per_1000 * p_quantity / 1000.0)::numeric, 2);
  if v_cost <= 0 then raise exception 'Calculated order price must be positive.'; end if;

  insert into public.wallet_balances(user_id,balance)
  values(v_uid,0) on conflict(user_id) do nothing;

  select balance into v_balance from public.wallet_balances where user_id=v_uid for update;
  if v_balance < v_cost then raise exception 'Insufficient wallet balance. Please add funds first.'; end if;

  update public.wallet_balances set balance=balance-v_cost, updated_at=now() where user_id=v_uid;

  insert into public.orders(user_id,service_id,link,quantity,status)
  values(v_uid,p_service_id,trim(p_link),p_quantity,'pending')
  returning id into v_order_id;

  insert into public.wallet_transactions(user_id,amount,transaction_type,reference,note)
  values(v_uid,-v_cost,'order',v_order_id::text,'Charge for order #'||v_order_id);

  return v_order_id;
end;
$$;
revoke all on function public.place_order(bigint,text,integer) from public;
grant execute on function public.place_order(bigint,text,integer) to authenticated;

-- Admin verifies payment, then credits wallet once in the same transaction.
create or replace function public.admin_approve_deposit(p_deposit_id bigint)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare v_req public.deposit_requests%rowtype;
begin
  if auth.uid() is null or not public.nkn_is_admin() then raise exception 'Admin access required.'; end if;
  select * into v_req from public.deposit_requests where id=p_deposit_id for update;
  if not found then raise exception 'Deposit request not found.'; end if;
  if v_req.status <> 'pending' then raise exception 'This request has already been reviewed.'; end if;

  insert into public.wallet_balances(user_id,balance) values(v_req.user_id,0)
  on conflict(user_id) do nothing;
  update public.wallet_balances
    set balance=balance+v_req.amount, updated_at=now()
    where user_id=v_req.user_id;
  update public.deposit_requests set status='approved' where id=p_deposit_id;
  insert into public.wallet_transactions(user_id,amount,transaction_type,reference,note)
  values(v_req.user_id,v_req.amount,'deposit',p_deposit_id::text,
    'Admin-approved '||v_req.payment_method||' deposit; transaction ID '||v_req.transaction_id);
end;
$$;
revoke all on function public.admin_approve_deposit(bigint) from public;
grant execute on function public.admin_approve_deposit(bigint) to authenticated;

create or replace function public.admin_reject_deposit(p_deposit_id bigint)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare v_req public.deposit_requests%rowtype;
begin
  if auth.uid() is null or not public.nkn_is_admin() then raise exception 'Admin access required.'; end if;
  select * into v_req from public.deposit_requests where id=p_deposit_id for update;
  if not found then raise exception 'Deposit request not found.'; end if;
  if v_req.status <> 'pending' then raise exception 'This request has already been reviewed.'; end if;
  update public.deposit_requests set status='rejected' where id=p_deposit_id;
end;
$$;
revoke all on function public.admin_reject_deposit(bigint) from public;
grant execute on function public.admin_reject_deposit(bigint) to authenticated;

-- Admin order status changes. A cancellation/refund credits the wallet only once.
create or replace function public.admin_update_order_status(p_order_id bigint, p_new_status text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare v_order public.orders%rowtype; v_service public.services%rowtype; v_cost numeric(12,2);
begin
  if auth.uid() is null or not public.nkn_is_admin() then raise exception 'Admin access required.'; end if;
  if p_new_status not in ('pending','processing','completed','partial','cancelled','refunded') then
    raise exception 'Invalid order status.';
  end if;
  select * into v_order from public.orders where id=p_order_id for update;
  if not found then raise exception 'Order not found.'; end if;
  if v_order.status in ('cancelled','refunded') and p_new_status in ('cancelled','refunded') then
    raise exception 'This order has already been refunded or cancelled.';
  end if;

  if p_new_status in ('cancelled','refunded') and v_order.status not in ('cancelled','refunded') then
    select * into v_service from public.services where id=v_order.service_id;
    if not found then raise exception 'Original service not found; contact database administrator.'; end if;
    v_cost := round((v_service.price_per_1000 * v_order.quantity / 1000.0)::numeric,2);
    insert into public.wallet_balances(user_id,balance) values(v_order.user_id,0)
      on conflict(user_id) do nothing;
    update public.wallet_balances set balance=balance+v_cost,updated_at=now() where user_id=v_order.user_id;
    insert into public.wallet_transactions(user_id,amount,transaction_type,reference,note)
      values(v_order.user_id,v_cost,'refund',v_order.id::text,'Refund for order #'||v_order.id);
  end if;
  update public.orders set status=p_new_status where id=p_order_id;
end;
$$;
revoke all on function public.admin_update_order_status(bigint,text) from public;
grant execute on function public.admin_update_order_status(bigint,text) to authenticated;

-- Admins need read access to all orders and deposit requests for the admin screen.
drop policy if exists "Admins read all orders" on public.orders;
create policy "Admins read all orders"
on public.orders for select to authenticated
using (public.nkn_is_admin());

drop policy if exists "Admins read all deposit requests" on public.deposit_requests;
create policy "Admins read all deposit requests"
on public.deposit_requests for select to authenticated
using (public.nkn_is_admin());

-- Only admins may insert/update/delete services from the browser.
grant select, insert, update, delete on public.services to authenticated;
drop policy if exists "Admins manage services" on public.services;
create policy "Admins manage services"
on public.services for all to authenticated
using (public.nkn_is_admin())
with check (public.nkn_is_admin());

-- Keep customers from directly inserting orders with arbitrary price/status.
drop policy if exists "Users create own pending orders" on public.orders;
drop policy if exists "Users insert own pending orders" on public.orders;
revoke insert, update, delete on public.orders from anon, authenticated;
grant select on public.orders to authenticated;

-- Customers may submit pending deposit requests, but cannot update their status.
drop policy if exists "Users create own pending deposits" on public.deposit_requests;
drop policy if exists "Users insert own pending deposits" on public.deposit_requests;
revoke update, delete on public.deposit_requests from anon, authenticated;
grant select, insert on public.deposit_requests to authenticated;
drop policy if exists "Users insert own pending deposits" on public.deposit_requests;
create policy "Users insert own pending deposits"
on public.deposit_requests for insert to authenticated
with check (user_id = auth.uid() and status = 'pending' and amount > 0);

-- Only own rows readable. Ledger is never client-writable.
alter table public.wallet_transactions enable row level security;
revoke insert, update, delete on public.wallet_transactions from anon, authenticated;
grant select on public.wallet_transactions to authenticated;
drop policy if exists "Users read own wallet transactions" on public.wallet_transactions;
create policy "Users read own wallet transactions"
on public.wallet_transactions for select to authenticated
using (user_id = auth.uid());

-- Do not let ordinary users promote themselves to admin.
alter table public.user_roles enable row level security;
revoke insert, update, delete on public.user_roles from anon, authenticated;
grant select on public.user_roles to authenticated;
drop policy if exists "Users read own role" on public.user_roles;
create policy "Users read own role"
on public.user_roles for select to authenticated
using (user_id = auth.uid());

-- IMPORTANT: assign your own admin role manually after registering.
-- First register through the website. Then find your user's UUID in
-- Supabase > Authentication > Users and run (replace UUID):
-- update public.user_roles set role='admin' where user_id='YOUR-USER-UUID';
-- If no role row exists, run:
-- insert into public.user_roles(user_id,role) values('YOUR-USER-UUID','admin')
-- on conflict(user_id) do update set role='admin';
