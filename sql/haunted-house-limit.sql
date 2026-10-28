-- Haunted House codes: each rescuer can claim only ONE, total (not per day).
-- Run once in the Supabase SQL editor. Safe to run again.
--
-- A duck counts as a Haunted House code when its type is "Haunted House"
-- (also "Haunted", "Haunted House Duck", "Haunted House Code"; any case).
-- Set it with the Type field or the bulk "Type ... Set" button in the admin.
--
-- claim_duck gets a wrapper in front of it: a rescuer who already has a
-- Haunted House code gets status 'haunted_limit' for any other one, and the
-- code stays unclaimed for someone else. Everything else goes through to
-- the original claim_duck unchanged.

create or replace function private.is_haunted_house(p_type text)
returns boolean language sql immutable as $$
    select coalesce(lower(btrim(p_type)) ~ '^haunted( house)?( (duck|code))?$', false);
$$;

-- Move the existing claim_duck aside (first run only) and put the wrapper in its place
do $$
declare
    fn regprocedure;
    args text;
    ident text;
    returns_set boolean;
    source text;
begin
    -- The wrapper reads who claimed each duck straight from the ducks table
    if (select count(*) from information_schema.columns
         where table_schema = 'public' and table_name = 'ducks'
           and column_name in ('duck_id', 'duck_type', 'qr_code', 'claimed_by')) < 4 then
        raise exception 'public.ducks needs duck_id, duck_type, qr_code and claimed_by columns';
    end if;

    select p.oid::regprocedure into fn from pg_proc p
     where p.pronamespace = 'private'::regnamespace and p.proname = 'claim_duck_all';
    if fn is null then
        select p.oid::regprocedure into fn from pg_proc p
         where p.pronamespace = 'public'::regnamespace and p.proname = 'claim_duck';
        if fn is null then raise exception 'public.claim_duck not found'; end if;
        execute format('alter function %s set schema private', fn);
        select p.oid::regprocedure into fn from pg_proc p
         where p.pronamespace = 'private'::regnamespace and p.proname = 'claim_duck';
        execute format('alter function %s rename to claim_duck_all', fn);
        select p.oid::regprocedure into fn from pg_proc p
         where p.pronamespace = 'private'::regnamespace and p.proname = 'claim_duck_all';
        execute format('revoke all on function %s from public, anon, authenticated', fn);
    end if;

    -- Keep the original's parameter types so the app's call still matches
    select pg_get_function_arguments(p.oid), pg_get_function_identity_arguments(p.oid), p.proretset
      into args, ident, returns_set
      from pg_proc p where p.oid = fn;
    source := case when returns_set
        then '(select to_jsonb(r) from private.claim_duck_all(p_student_id, p_qr_code) r limit 1)'
        else 'to_jsonb(private.claim_duck_all(p_student_id, p_qr_code))' end;

    execute format('drop function if exists public.claim_duck(%s)', ident);
    execute format($f$
        create function public.claim_duck(%1$s)
        returns jsonb language plpgsql volatile security definer set search_path = public, private as $body$
        declare
            target public.ducks%%rowtype;
            result jsonb;
        begin
            select * into target from public.ducks
             where upper(btrim(qr_code)) = upper(btrim(p_qr_code)) limit 1;

            if found and private.is_haunted_house(target.duck_type) and target.claimed_by is null then
                -- One scan at a time per rescuer, so two Haunted House codes
                -- scanned at once can't both get through
                perform pg_advisory_xact_lock(hashtext('haunted-house:' || p_student_id::text));
                if exists (select 1 from public.ducks d
                            where d.claimed_by::text = p_student_id::text
                              and d.duck_id <> target.duck_id
                              and private.is_haunted_house(d.duck_type)) then
                    return jsonb_build_object('status', 'haunted_limit', 'duck_id', target.duck_id,
                                              'duck_type', target.duck_type, 'limit', 1);
                end if;
            end if;

            result := %2$s;
            return result;
        end $body$;
    $f$, args, source);

    execute format('revoke all on function public.claim_duck(%s) from public', ident);
    execute format('grant execute on function public.claim_duck(%s) to anon, authenticated', ident);
end $$;
