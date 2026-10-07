const SUPABASE_SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.vulnerableServiceRolePayload0000.signature00';
const STRIPE_PUBLISHABLE = 'pk_live_51Hfaketestkeyforfixture00';

fetch('/api/admin/stats')
  .then((r) => r.json())
  .then((stats) => {
    const query = new URLSearchParams(location.search);
    const name = query.get('name') || 'world';
    document.getElementById('out').innerHTML = 'Hello ' + name + ' — ' + JSON.stringify(stats);
  });
