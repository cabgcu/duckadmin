-- Hide duck locations from rescuers (e.g. the first week of the hunt).
-- Run once in the Supabase SQL editor. Safe to run again.
--
-- While locations are hidden, get_rebel_coordinates returns no locations and
-- no duck counts, just a "hidden" marker, so neither can be read from the
-- app or by calling the API directly. Admins flip it from the
-- "Locations" switch in the admin header.

create table if not exists public.location_settings (
    id         integer primary key default 1 check (id = 1),
    hidden     boolean not null default false,
    changed_at timestamptz not null default now()
);
insert into public.location_settings (id) values (1) on conflict (id) do nothing;

-- Anyone may read the switch (it's just on/off); only the functions below change it
alter table public.location_settings enable row level security;
drop policy if exists "location settings are public" on public.location_settings;
create policy "location settings are public" on public.location_settings for select using (true);
grant select on public.location_settings to anon, authenticated;

-- Push changes live to the player app and the admin
do $$
begin
    if not exists (select 1 from pg_publication_tables
                   where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'location_settings') then
        alter publication supabase_realtime add table public.location_settings;
    end if;
end $$;

create or replace function private.locations_hidden()
returns boolean language sql stable security definer set search_path = public as $$
    select coalesce((select hidden from public.location_settings where id = 1), false);
$$;

create or replace function public.admin_get_locations_hidden()
returns boolean language plpgsql stable security definer set search_path = public, private as $$
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    return private.locations_hidden();
end $$;

create or replace function public.admin_set_locations_hidden(p_hidden boolean)
returns boolean language plpgsql security definer set search_path = public, private as $$
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    update public.location_settings set hidden = p_hidden, changed_at = now() where id = 1;
    return p_hidden;
end $$;

revoke all on function public.admin_get_locations_hidden() from public, anon;
revoke all on function public.admin_set_locations_hidden(boolean) from public, anon;
grant execute on function public.admin_get_locations_hidden() to authenticated;
grant execute on function public.admin_set_locations_hidden(boolean) to authenticated;

-- Move the existing get_rebel_coordinates aside (first run only) and put a
-- wrapper in its place that returns nothing but a marker while they're hidden.
do $$
declare
    returns_set boolean;
    source text;
begin
    if to_regprocedure('private.get_rebel_coordinates_all()') is null then
        alter function public.get_rebel_coordinates() set schema private;
        alter function private.get_rebel_coordinates() rename to get_rebel_coordinates_all;
        revoke all on function private.get_rebel_coordinates_all() from public, anon, authenticated;
    end if;

    select proretset into returns_set from pg_proc where oid = 'private.get_rebel_coordinates_all()'::regprocedure;
    source := case when returns_set
        then '(select jsonb_agg(to_jsonb(r)) from private.get_rebel_coordinates_all() r)'
        else 'to_jsonb(private.get_rebel_coordinates_all())' end;

    -- The original may have had a different return type, so replace it outright
    drop function if exists public.get_rebel_coordinates();
    execute format($f$
        create function public.get_rebel_coordinates()
        returns jsonb language plpgsql stable security definer set search_path = public, private as $body$
        begin
            -- Not even an empty list: that would give away "every duck is rescued"
            if private.locations_hidden() then return '[{"hidden": true}]'::jsonb; end if;
            return coalesce(%s, '[]'::jsonb);
        end $body$;
    $f$, source);
end $$;

grant execute on function public.get_rebel_coordinates() to anon, authenticated;
