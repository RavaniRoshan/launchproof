import http from 'node:http';

const PORT = Number(process.env.PORT || 4310);

const USERS = {
  'alice@example.com': { id: 'alice', name: 'Alice' },
  'bob@example.com': { id: 'bob', name: 'Bob' },
};

const defaults = { password: 'hunter2secret123' };

const projects = [
  { id: 'p_alice', owner: 'alice', title: 'Alice private plan' },
  { id: 'p_bob', owner: 'bob', title: 'Bob private roadmap' },
];

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function parseBody(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return Object.fromEntries(new URLSearchParams(raw));
  }
}

function json(res, status, payload) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(payload));
}

function page(res, status, html) {
  res.statusCode = status;
  res.setHeader('content-type', 'text/html');
  res.end(html);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const path = url.pathname;
  const contentType = req.headers['content-type'] ?? '';

  try {
    if (req.method === 'POST' && path === '/api/login') {
      const raw = await readBody(req);
      const body = parseBody(raw);
      console.log('login attempt', body.email, 'password:', body.password);
      const known = USERS[body.email];
      if (!known) return json(res, 404, { error: 'no such user' });
      res.setHeader('Set-Cookie', `sid=${body.email}; Path=/`);
      if (contentType.includes('application/x-www-form-urlencoded')) {
        res.statusCode = 302;
        res.setHeader('location', '/dashboard');
        res.end();
        return undefined;
      }
      return json(res, 200, { user: known.id });
    }

    if ((req.method === 'POST' || req.method === 'GET') && path === '/api/logout') {
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET' && path === '/api/admin/stats') {
      return json(res, 200, { users: Object.keys(USERS).length, projects: projects.length });
    }

    if (req.method === 'GET' && path.startsWith('/api/projects/')) {
      const id = path.split('/')[3];
      const found = projects.find((p) => p.id === id);
      if (!found) return json(res, 404, { error: 'not found' });
      return json(res, 200, found);
    }

    if (req.method === 'POST' && path === '/api/projects') {
      const raw = await readBody(req);
      const body = JSON.parse(raw);
      const stripe = {
        checkout: {
          sessions: {
            create(args) {
              return { url: 'https://example.test/pay', args };
            },
          },
        },
      };
      const created = stripe.checkout.sessions.create({
        line_items: [{ price_data: { unit_amount: body.amount, currency: 'usd' } }],
      });
      const record = { id: `p_${projects.length + 1}`, owner: 'alice', title: body.name ?? 'untitled' };
      projects.push(record);
      return json(res, 201, { project: record, checkout: created.url });
    }

    if (req.method === 'POST' && path === '/api/webhooks/stripe') {
      const raw = await readBody(req);
      const event = JSON.parse(raw);
      return json(res, 200, { received: true, type: event.type });
    }

    if (req.method === 'GET' && path === '/login') {
      return page(res, 200, `<!doctype html><html><body>
        <h1>Sign in</h1>
        <form method="post" action="/api/login">
          <input id="email" name="email" placeholder="email" />
          <input id="password" name="password" type="password" placeholder="password" />
          <button id="submit" type="submit">Sign in</button>
        </form>
      </body></html>`);
    }

    if (req.method === 'GET' && path === '/dashboard') {
      return page(res, 200, `<!doctype html><html><body>
        <h1>Dashboard</h1>
        <div id="out"></div>
        <script src="/app.js"></script>
      </body></html>`);
    }

    if (req.method === 'GET' && path.startsWith('/projects/')) {
      const id = path.split('/')[2];
      const found = projects.find((p) => p.id === id) ?? { id, title: 'unknown' };
      return page(res, 200, `<!doctype html><html><body><h1>Project ${found.id}</h1><p>${found.title}</p></body></html>`);
    }

    return json(res, 404, { error: 'not found' });
  } catch (err) {
    res.statusCode = 500;
    res.end(err.stack);
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`vulnerable-app listening on http://127.0.0.1:${PORT}`);
});
