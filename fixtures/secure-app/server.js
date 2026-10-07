import crypto from 'node:crypto';
import http from 'node:http';

const PORT = Number(process.env.PORT || 4311);

const USERS = {
  'alice@example.com': { id: 'alice', password: 'example-alice-pw' },
  'bob@example.com': { id: 'bob', password: 'example-bob-pw' },
};
const prices = { pro_probe_1: 999 };
const projects = [
  { id: 'p_alice', owner: 'alice', title: 'Alice private plan' },
  { id: 'p_bob', owner: 'bob', title: 'Bob private roadmap' },
];
const activeLogins = new Map();

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

function cookiesOf(req) {
  const out = {};
  for (const part of String(req.headers.cookie ?? '').split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return out;
}

function requireUser(req) {
  const token = cookiesOf(req).sid;
  if (!token) return null;
  return activeLogins.get(token) ?? null;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const path = url.pathname;
  const contentType = req.headers['content-type'] ?? '';

  try {
    if (req.method === 'POST' && path === '/api/login') {
      const raw = await readBody(req);
      const body = parseBody(raw);
      const known = USERS[body.email];
      if (!known || known.password !== body.password) return json(res, 401, { error: 'invalid credentials' });
      const token = crypto.randomUUID();
      activeLogins.set(token, known.id);
      res.setHeader('Set-Cookie', `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`);
      if (contentType.includes('application/x-www-form-urlencoded')) {
        res.statusCode = 302;
        res.setHeader('location', '/dashboard');
        res.end();
        return undefined;
      }
      return json(res, 200, { user: known.id });
    }

    if ((req.method === 'POST' || req.method === 'GET') && path === '/api/logout') {
      const token = cookiesOf(req).sid;
      if (token) activeLogins.delete(token);
      res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict');
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET' && path === '/api/admin/stats') {
      const user = requireUser(req);
      if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, { users: Object.keys(USERS).length, projects: projects.length });
    }

    if (req.method === 'GET' && path.startsWith('/api/projects/')) {
      const user = requireUser(req);
      if (!user) return json(res, 401, { error: 'authentication required' });
      const id = path.split('/')[3];
      const found = projects.find((p) => p.id === id);
      if (!found || found.owner !== user) return json(res, 404, { error: 'not found' });
      return json(res, 200, found);
    }

    if (req.method === 'POST' && path === '/api/projects') {
      const user = requireUser(req);
      if (!user) return json(res, 401, { error: 'authentication required' });
      const raw = await readBody(req);
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        return json(res, 400, { error: 'malformed request body' });
      }
      if (typeof prices[body.priceId] !== 'number') return json(res, 400, { error: 'unknown price' });
      const stripe = {
        checkout: {
          sessions: {
            create(args) {
              return { url: 'https://example.test/pay', args };
            },
          },
        },
      };
      const created = stripe.checkout.sessions.create({ line_items: [{ price: body.priceId }] });
      const record = { id: `p_${projects.length + 1}`, owner: user, title: body.name ?? 'untitled' };
      projects.push(record);
      return json(res, 201, { project: record, checkout: created.url });
    }

    if (req.method === 'POST' && path === '/api/webhooks/stripe') {
      const raw = await readBody(req);
      const secret = process.env.STRIPE_WEBHOOK_SECRET ?? '';
      const expected = crypto.createHmac('sha256', secret).update(raw).digest('hex');
      const provided = req.headers['stripe-signature'];
      const ok =
        typeof provided === 'string' &&
        provided.length === expected.length &&
        crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
      if (!ok) return json(res, 400, { error: 'invalid webhook signature' });
      return json(res, 200, { received: true });
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
      if (!requireUser(req)) {
        res.statusCode = 302;
        res.setHeader('location', '/login');
        res.end();
        return undefined;
      }
      return page(res, 200, `<!doctype html><html><body>
        <h1>Dashboard</h1>
        <div id="out"></div>
        <script src="/app.js"></script>
      </body></html>`);
    }

    if (req.method === 'GET' && path.startsWith('/projects/')) {
      const user = requireUser(req);
      if (!user) {
        res.statusCode = 302;
        res.setHeader('location', '/login');
        res.end();
        return undefined;
      }
      const id = path.split('/')[2];
      const found = projects.find((p) => p.id === id);
      if (!found || found.owner !== user) {
        return page(res, 404, '<!doctype html><html><body><h1>Not found</h1></body></html>');
      }
      return page(res, 200, `<!doctype html><html><body><h1>Project ${found.id}</h1><p>${found.title}</p></body></html>`);
    }

    return json(res, 404, { error: 'not found' });
  } catch (err) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: 'internal error' }));
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`secure-app listening on http://127.0.0.1:${PORT}`);
});
