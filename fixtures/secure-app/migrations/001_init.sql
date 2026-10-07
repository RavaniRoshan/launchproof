create table profiles (
  id uuid primary key,
  email text not null
);

create table projects (
  id text primary key,
  owner text not null,
  title text not null
);

alter table profiles enable row level security;
alter table projects enable row level security;

create policy "profiles are self readable" on profiles
  for select using (auth.uid() = id);

create policy "projects are owner readable" on projects
  for select using (auth.uid() = owner);
