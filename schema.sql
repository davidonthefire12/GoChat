-- Run this once in the Supabase SQL Editor (Project → SQL Editor → New query).
-- If you already created the "messages" table before, just add the new
-- "users" table below - "create table if not exists" won't touch messages.

create table if not exists messages (
    id          bigserial primary key,
    username    text not null,
    text        text not null,
    created_at  bigint not null,   -- unix timestamp (seconds), matches the app's "ts" field
    edited_at   bigint             -- unix timestamp of the last edit, null if never edited
);

create index if not exists idx_messages_id_desc on messages (id desc);

-- Accounts: first time a username is used it's registered with the given
-- password (hashed with bcrypt - the plaintext password is never stored).
-- Every later login with that name must match the stored hash.
create table if not exists users (
    username_lower text primary key,  -- lower(username), enforces case-insensitive uniqueness
    username        text not null,     -- original casing, used everywhere as the canonical display name
    password_hash   text not null,
    created_at      bigint not null
);

alter table messages enable row level security;
alter table users enable row level security;
-- No policies are added on purpose: the Go server talks to Postgres directly
-- with the postgres role (which bypasses RLS), so these tables stay fully
-- inaccessible through Supabase's public REST/GraphQL API, where they'd
-- otherwise be exposed to anyone holding the project's anon key.
