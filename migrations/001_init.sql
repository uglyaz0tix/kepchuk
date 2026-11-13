-- initial schema for kepchuk central server

create table if not exists bots (
    bot_id text primary key,
    api_key_hash text not null,
    secret text not null,
    is_active integer not null default 1,
    created_at text not null default (datetime('now'))
);

create table if not exists users (
    user_id text primary key,
    tokens integer not null default 1000,
    tier text not null default 'free',
    is_blocked integer not null default 0,
    blocked_until text,
    created_at text not null default (datetime('now'))
);

create table if not exists billing_ledger (
    id integer primary key autoincrement,
    user_id text not null,
    bot_id text not null,
    delta_tokens integer not null,
    balance_after integer not null,
    reason text not null,
    created_at text not null default (datetime('now'))
);

create table if not exists blocks (
    id integer primary key autoincrement,
    user_id text not null,
    reason text not null,
    expires_at text not null,
    created_at text not null default (datetime('now'))
);

create index if not exists idx_billing_user on billing_ledger(user_id);
create index if not exists idx_blocks_user on blocks(user_id);
