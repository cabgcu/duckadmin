-- Set the type of many ducks at once (the "Type ... Set" button that shows
-- when ducks are selected in the admin). Run once in the Supabase SQL editor.
-- Safe to run again.
--
-- An empty type clears it. Returns how many ducks were changed.

create or replace function public.admin_set_ducks_type(p_duck_ids text[], p_duck_type text)
returns integer language plpgsql security definer set search_path = public as $$
declare
    n integer;
begin
    if not coalesce(public.is_admin(), false) then raise exception 'Admins only.'; end if;
    update public.ducks
       set duck_type = nullif(btrim(p_duck_type), '')
     where duck_id = any(p_duck_ids);
    get diagnostics n = row_count;
    return n;
end $$;

revoke all on function public.admin_set_ducks_type(text[], text) from public, anon;
grant execute on function public.admin_set_ducks_type(text[], text) to authenticated;
