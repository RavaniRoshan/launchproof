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

create policy "everyone_reads_projects" on projects using (true);
