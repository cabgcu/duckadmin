-- Bans: block student IDs (or devices) from Duck Hunt. Run once in the
-- Supabase SQL editor. Safe to run again.
--
-- Admins ban a student ID by hand from the Bans tab. The app no longer bans
-- anyone on its own (see sql/remove-autoban.sql); the device ID it sends (a
-- random ID the app keeps on the phone) is only used to enforce bans.
--
-- Enforcement in the database (works even when someone calls the API
-- directly instead of using the app):
--   * a banned student ID can't register, claim ducks, get scan points or
--     file code reports;
--   * a banned device can't do any of that either: the app sends its device
--     ID in an x-duck-device header with every request.
-- Admins see every ban in the Bans tab and can lift any of them there.

create table if not exists private.bans (
    id          bigint generated always as identity primary key,
    kind        text not null check (kind in ('device', 'student')),
    value       text not null,              -- the device ID or the student ID
    reason      text not null,
    details     text,
    device_id   text,                       -- the device it was caught on
    student_id  text,                       -- who was signed in, if anyone
    user_agent  text,
    created_at  timestamptz not null default now(),
    lifted_at   timestamptz,
    lifted_by   text
);
-- One live ban per device / student ID (later catches just add to the log)
create unique index if not exists bans_one_active on private.bans (kind, value) where lifted_at is null;
create index if not exists bans_created on private.bans (created_at desc);
revoke all on private.bans from public, anon, authenticated;

create or replace function private.request_header(p_name text)
returns text language sql stable as $$
    select nullif(btrim(nullif(current_setting('request.headers', true), '')::json ->> p_name), '');
$$;

create or replace function private.clean_device_id(p text)
returns text language sql immutable as $$
    select case when p ~ '^[A-Za-z0-9_-]{8,64}$' then p end;
$$;

create or replace function private.active_ban(p_device_id text, p_student_id text)
returns private.bans language sql stable security definer set search_path = public, private as $$
    select b.* from private.bans b
     where b.lifted_at is null
       and ((b.kind = 'device' and b.value = private.clean_device_id(p_device_id))
         or (b.kind = 'student' and b.value = nullif(btrim(p_student_id), '')))
     order by (b.kind = 'student') desc, b.created_at
     limit 1;
$$;

-- The app asks this on start and before signing in
create or replace function public.check_ban(p_device_id text, p_student_id text default null)
returns jsonb language plpgsql stable security definer set search_path = public, private as $$
declare
    b private.bans;
begin
    b := private.active_ban(p_device_id, p_student_id);
    if b.id is null then return jsonb_build_object('banned', false); end if;
    return jsonb_build_object('banned', true, 'kind', b.kind, 'reason', b.reason, 'since', b.created_at);
end $$;

-- The app used to ban itself through this; that's been removed
drop function if exists public.report_tamper(text, text, text, text);

-- ---------- Enforcement ----------
-- Trigger: TG_ARGV[0] names the student ID column. Admins are never blocked.
create or replace function private.enforce_ban()
returns trigger language plpgsql security definer set search_path = public, private as $$
declare
    col text := tg_argv[0];
    sid text := to_jsonb(new) ->> col;
    b   private.bans;
begin
    if tg_op = 'UPDATE' and sid is not distinct from (to_jsonb(old) ->> col) then return new; end if;
    if sid is null or coalesce(public.is_admin(), false) then return new; end if;
    b := private.active_ban(private.request_header('x-duck-device'), sid);
    if b.id is not null then
        raise exception 'DUCK_BANNED: This % is banned from Duck Hunt.',
            case b.kind when 'device' then 'device' else 'Student ID' end
            using errcode = 'P0001';
    end if;
    return new;
end $$;

do $$
declare
    t record;
begin
    for t in select * from (values
            ('players', 'student_id', 'insert'),
            ('ducks', 'claimed_by', 'insert or update'),
            ('duck_log', 'student_id', 'insert'),
            ('code_reports', 'student_id', 'insert')) v(tbl, col, ev)
    loop
        if exists (select 1 from information_schema.columns
                    where table_schema = 'public' and table_name = t.tbl and column_name = t.col) then
            execute format('drop trigger if exists enforce_ban on public.%I', t.tbl);
            execute format('create trigger enforce_ban before %s on public.%I for each row execute function private.enforce_ban(%L)',
                           t.ev, t.tbl, t.col);
        end if;
    end loop;
end $$;

-- ---------- Admin ----------
create or replace function public.admin_list_bans()
returns jsonb language plpgsql stable security definer set search_path = public, private as $$
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    return coalesce((
        select jsonb_agg(jsonb_build_object(
                   'id', b.id, 'kind', b.kind, 'value', b.value, 'reason', b.reason, 'details', b.details,
                   'device_id', b.device_id, 'student_id', b.student_id, 'user_agent', b.user_agent,
                   'player_name', nullif(btrim(coalesce(p.first_name, '') || ' ' || coalesce(p.last_name, '')), ''),
                   'created_at', b.created_at, 'lifted_at', b.lifted_at, 'lifted_by', b.lifted_by)
               order by (b.lifted_at is null) desc, b.created_at desc)
          from (select * from private.bans order by created_at desc limit 500) b
          left join public.players p on p.student_id::text = b.student_id
    ), '[]'::jsonb);
end $$;

create or replace function public.admin_unban(p_id bigint)
returns void language plpgsql security definer set search_path = public, private as $$
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    update private.bans
       set lifted_at = now(),
           lifted_by = coalesce(auth.jwt() ->> 'email', 'admin')
     where id = p_id and lifted_at is null;
end $$;

-- Ban a device or student ID by hand from the admin
create or replace function public.admin_ban(p_kind text, p_value text, p_reason text default null)
returns void language plpgsql security definer set search_path = public, private as $$
declare
    v text := nullif(btrim(coalesce(p_value, '')), '');
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    if p_kind not in ('device', 'student') or v is null then raise exception 'Pick a device or student ID to ban.'; end if;
    insert into private.bans (kind, value, reason, device_id, student_id)
    values (p_kind, v, coalesce(nullif(btrim(coalesce(p_reason, '')), ''), 'Banned by an admin'),
            case when p_kind = 'device' then v end, case when p_kind = 'student' then v end)
    on conflict (kind, value) where lifted_at is null do nothing;
end $$;

revoke all on function public.check_ban(text, text) from public;
revoke all on function public.admin_list_bans() from public, anon;
revoke all on function public.admin_unban(bigint) from public, anon;
revoke all on function public.admin_ban(text, text, text) from public, anon;
grant execute on function public.check_ban(text, text) to anon, authenticated;
grant execute on function public.admin_list_bans() to authenticated;
grant execute on function public.admin_unban(bigint) to authenticated;
grant execute on function public.admin_ban(text, text, text) to authenticated;
