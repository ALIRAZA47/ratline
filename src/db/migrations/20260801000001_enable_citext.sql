-- Case-insensitive text, used for email addresses and other identifiers where
-- "Ali@example.com" and "ali@example.com" must be the same value. Doing this
-- with a citext column rather than lower() everywhere means a missed lower()
-- cannot create a duplicate account, which is an account-takeover shape.
--
-- First migration, so it also proves the runner's up/down/up cycle end to end.

-- migrate:up
create extension if not exists citext;

-- migrate:down
drop extension if exists citext;
