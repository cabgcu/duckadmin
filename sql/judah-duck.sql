-- Judah Floyd, Student Body President duck.
-- Run once in the Supabase SQL editor. Safe to run again.
--
-- A duck counts as the Judah duck when its Duck ID or type mentions
-- "Judah" or "Student Body President" (any case), e.g. type
-- "Judah Floyd -- Student Body President".
--
-- Whoever claims it loses ALL of their points (set to 0). The points they had
-- are saved here. Their objective is to find Student Body President Judah
-- Floyd in person; when they do, an admin lifts the penalty from the Rescuers
-- tab and they get every removed point back plus a 500 point bonus.
-- Points they earn after the penalty are kept as normal.
--
-- The penalty runs from a trigger on public.ducks at the end of the
-- transaction, so it applies however the duck gets claimed (scan, approved
-- broken-code report, ...), after claim_duck has added the duck's points.

create table if not exists private.judah_penalties (
    id              bigint generated always as identity primary key,
    student_id      text not null,
    duck_id         text,
    points_removed  integer not null,
    created_at      timestamptz not null default now(),
    lifted_at       timestamptz,
    lifted_by       text,
    points_returned integer,                -- removed points + bonus, when lifted
    bonus           integer
);
create index if not exists judah_penalties_student on private.judah_penalties (student_id, created_at desc);
revoke all on private.judah_penalties from public, anon, authenticated;

do $$
begin
    if not exists (select 1 from information_schema.columns
                    where table_schema = 'public' and table_name = 'players' and column_name = 'points') then
        raise exception 'public.players needs a points column';
    end if;
end $$;

create or replace function private.is_judah(p_duck_id text, p_type text)
returns boolean language sql immutable as $$
    select coalesce(lower(coalesce(p_duck_id, '') || ' ' || coalesce(p_type, '')) ~ '(judah|student body president)', false);
$$;

-- ---------- The penalty ----------
create or replace function private.judah_claimed()
returns trigger language plpgsql security definer set search_path = public, private as $$
declare
    sid text := new.claimed_by::text;
    had integer;
begin
    if sid is null or not private.is_judah(new.duck_id::text, new.duck_type) then return null; end if;
    if tg_op = 'UPDATE' and old.claimed_by is not distinct from new.claimed_by then return null; end if;
    -- Still claimed by them at commit (not undone in the same transaction)?
    if not exists (select 1 from public.ducks where duck_id = new.duck_id and claimed_by::text = sid) then return null; end if;
    -- Only once per claim
    if exists (select 1 from private.judah_penalties
                where student_id = sid and duck_id = new.duck_id::text and lifted_at is null) then return null; end if;

    select coalesce(points, 0) into had from public.players where student_id::text = sid for update;
    if not found then return null; end if;

    update public.players set points = 0 where student_id::text = sid;
    insert into private.judah_penalties (student_id, duck_id, points_removed)
    values (sid, new.duck_id::text, greatest(had, 0));
    return null;
end $$;

drop trigger if exists judah_claimed on public.ducks;
create constraint trigger judah_claimed
    after insert or update of claimed_by on public.ducks
    deferrable initially deferred
    for each row execute function private.judah_claimed();

-- ---------- Player app ----------
-- Has this rescuer found the Judah duck, and is their penalty still on?
create or replace function public.get_judah_status(p_student_id text)
returns jsonb language plpgsql stable security definer set search_path = public, private as $$
declare
    j private.judah_penalties;
begin
    select * into j from private.judah_penalties
     where student_id = btrim(coalesce(p_student_id, ''))
     order by (lifted_at is null) desc, created_at desc limit 1;
    if j.id is null then return jsonb_build_object('found', false); end if;
    return jsonb_build_object(
        'found', true, 'id', j.id, 'found_at', j.created_at, 'points_removed', j.points_removed,
        'lifted', j.lifted_at is not null, 'lifted_at', j.lifted_at,
        'points_returned', j.points_returned, 'bonus', j.bonus);
end $$;

-- ---------- Admin ----------
create or replace function public.admin_list_judah()
returns jsonb language plpgsql stable security definer set search_path = public, private as $$
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    return coalesce((
        select jsonb_agg(jsonb_build_object(
                   'id', j.id, 'student_id', j.student_id, 'duck_id', j.duck_id,
                   'points_removed', j.points_removed, 'created_at', j.created_at,
                   'lifted_at', j.lifted_at, 'lifted_by', j.lifted_by,
                   'points_returned', j.points_returned, 'bonus', j.bonus)
               order by j.created_at desc)
          from private.judah_penalties j
    ), '[]'::jsonb);
end $$;

-- Give back everything that was removed, plus the bonus (500 by default)
create or replace function public.admin_lift_judah(p_id bigint, p_bonus integer default 500)
returns integer language plpgsql security definer set search_path = public, private as $$
declare
    j private.judah_penalties;
    give integer;
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    select * into j from private.judah_penalties where id = p_id and lifted_at is null for update;
    if j.id is null then raise exception 'That point removal was already lifted.'; end if;

    give := j.points_removed + greatest(coalesce(p_bonus, 0), 0);
    update public.players set points = coalesce(points, 0) + give where student_id::text = j.student_id;
    update private.judah_penalties
       set lifted_at = now(), lifted_by = coalesce(auth.jwt() ->> 'email', 'admin'),
           points_returned = give, bonus = greatest(coalesce(p_bonus, 0), 0)
     where id = j.id;
    return give;
end $$;

revoke all on function public.get_judah_status(text) from public;
revoke all on function public.admin_list_judah() from public, anon;
revoke all on function public.admin_lift_judah(bigint, integer) from public, anon;
grant execute on function public.get_judah_status(text) to anon, authenticated;
grant execute on function public.admin_list_judah() to authenticated;
grant execute on function public.admin_lift_judah(bigint, integer) to authenticated;
