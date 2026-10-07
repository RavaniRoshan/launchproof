fetch('/api/admin/stats')
  .then((r) => (r.ok ? r.json() : { users: 0, projects: 0 }))
  .then((stats) => {
    const out = document.getElementById('out');
    if (out) {
      out.textContent = 'Signed in — users: ' + stats.users + ', projects: ' + stats.projects;
    }
  });
