-- Remove the autoban and unban everyone.
-- Run once in the Supabase SQL editor. Safe to run again.
--
-- Duck Hunt used to ban a phone (and the student ID signed in on it) on its
-- own when it thought someone was opening dev tools, pausing in a debugger
-- or guessing codes. That's gone from the app. This:
--   * lifts every ban that's active right now, automatic or by an admin;
--   * removes report_tamper, the function the app used to ban itself, so
--     an old copy of the page still open on a phone can't ban anyone.
-- Bans an admin adds by hand from the Bans tab still work.

update private.bans
   set lifted_at = now(),
       lifted_by = 'Autoban removed: everyone unbanned'
 where lifted_at is null;

drop function if exists public.report_tamper(text, text, text, text);

-- Should list nobody
select kind, value, reason, created_at from private.bans where lifted_at is null;
