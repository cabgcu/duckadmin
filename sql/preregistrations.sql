-- Pre-registrations: bulk add rescuers from a spreadsheet (first name, last
-- name, email) before they have a student ID in Duck Hunt. Run once in the
-- Supabase SQL editor. Safe to run again.
--
-- Rescuers are keyed by student ID, which the spreadsheet doesn't have, so the
-- imported rows wait here. The student still signs in or registers in the
-- app with their student ID; when they enter their @my.gcu.edu email, the app
-- fills in the name from this list, and as soon as a rescuer with that email
-- exists the pre-registration is marked claimed (with their student ID).
--
-- Admin: "Import list" and the "Waiting for student ID" filter on the
-- Rescuers tab.

create schema if not exists private;

create table if not exists private.preregistrations (
    email        text primary key,            -- lower case, trimmed
    first_name   text not null,
    last_name    text not null default '',
    imported_at  timestamptz not null default now(),
    imported_by  text,
    claimed_at   timestamptz,                 -- when they registered in the app
    student_id   text                         -- the student ID they registered with
);
create index if not exists preregistrations_pending on private.preregistrations (imported_at) where claimed_at is null;
revoke all on private.preregistrations from public, anon, authenticated;

-- ---------- Claiming ----------
-- Whenever a rescuer is added (or their email changes), claim the matching
-- pre-registration. A trigger, so it works however the rescuer is created.
create or replace function private.claim_preregistration()
returns trigger language plpgsql security definer set search_path = public, private as $$
begin
    if new.email is not null and btrim(new.email) <> '' then
        update private.preregistrations
           set claimed_at = coalesce(claimed_at, now()),
               student_id = new.student_id
         where email = lower(btrim(new.email));
    end if;
    return new;
end $$;

drop trigger if exists claim_preregistration on public.players;
create trigger claim_preregistration
    after insert or update of email, student_id on public.players
    for each row execute function private.claim_preregistration();

-- ---------- App ----------
-- The register form asks this when the student types their email, to fill in
-- their name. Only names of still-unclaimed pre-registrations come back.
create or replace function public.find_preregistration(p_email text)
returns jsonb language sql stable security definer set search_path = public, private as $$
    select jsonb_build_object('first_name', r.first_name, 'last_name', r.last_name)
      from private.preregistrations r
     where r.email = lower(btrim(p_email))
       and r.claimed_at is null;
$$;

-- ---------- Admin ----------
-- p_rows: [{ "first_name": "...", "last_name": "...", "email": "..." }, ...]
-- Adds new emails, updates names of ones already waiting, and skips emails
-- that already belong to a rescuer. Returns the counts.
create or replace function public.admin_import_preregistrations(p_rows jsonb)
returns jsonb language plpgsql security definer set search_path = public, private as $$
declare
    who text := coalesce(auth.jwt() ->> 'email', 'admin');
    result jsonb;
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    if jsonb_typeof(p_rows) <> 'array' then raise exception 'Expected a list of rows.'; end if;

    with src as (
        select distinct on (lower(btrim(x ->> 'email')))
               lower(btrim(x ->> 'email')) as email,
               btrim(coalesce(x ->> 'first_name', '')) as first_name,
               btrim(coalesce(x ->> 'last_name', '')) as last_name
          from jsonb_array_elements(p_rows) x
         order by lower(btrim(x ->> 'email'))
    ), valid as (
        select * from src
         where email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' and first_name <> ''
    ), fresh as (
        select v.* from valid v
         where not exists (select 1 from public.players p where lower(btrim(p.email)) = v.email)
    ), up as (
        insert into private.preregistrations as r (email, first_name, last_name, imported_by)
        select email, first_name, last_name, who from fresh
        on conflict (email) do update
           set first_name = excluded.first_name,
               last_name = excluded.last_name,
               imported_at = now(),
               imported_by = excluded.imported_by
         where r.claimed_at is null
        returning (xmax = 0) as inserted
    )
    select jsonb_build_object(
               'added', (select count(*) from up where inserted),
               'updated', (select count(*) from up where not inserted),
               'already_registered', (select count(*) from valid) - (select count(*) from fresh),
               'invalid', (select count(*) from src) - (select count(*) from valid))
      into result;
    return result;
end $$;

-- Everyone still waiting to sign in with their student ID
create or replace function public.admin_list_preregistrations()
returns jsonb language plpgsql stable security definer set search_path = public, private as $$
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    return coalesce((
        select jsonb_agg(jsonb_build_object('email', r.email, 'first_name', r.first_name, 'last_name', r.last_name,
                                            'imported_at', r.imported_at, 'imported_by', r.imported_by)
                         order by r.last_name, r.first_name)
          from private.preregistrations r
         where r.claimed_at is null), '[]'::jsonb);
end $$;

create or replace function public.admin_delete_preregistrations(p_emails text[])
returns integer language plpgsql security definer set search_path = public, private as $$
declare
    n integer;
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    delete from private.preregistrations
     where claimed_at is null
       and email in (select lower(btrim(e)) from unnest(p_emails) e);
    get diagnostics n = row_count;
    return n;
end $$;

revoke all on function public.find_preregistration(text) from public;
revoke all on function public.admin_import_preregistrations(jsonb) from public, anon;
revoke all on function public.admin_list_preregistrations() from public, anon;
revoke all on function public.admin_delete_preregistrations(text[]) from public, anon;
grant execute on function public.find_preregistration(text) to anon, authenticated;
grant execute on function public.admin_import_preregistrations(jsonb) to authenticated;
grant execute on function public.admin_list_preregistrations() to authenticated;
grant execute on function public.admin_delete_preregistrations(text[]) to authenticated;
