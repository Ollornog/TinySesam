// Example Ex4 (T-105): the settings page of the application, drawn in the browser — surface "headless".
//
// It reads the account's state from /.tinysesam/account.json on this host (spec section 8a) and writes nothing: every
// change is a link to one of TinySesam's action pages (section 8c) with `return` (this page) and `state` (a value
// this page issued and keeps in sessionStorage). Back here, `ts_action`, `ts_result` and `state` say what happened —
// a hint for a message, never a proof: the page reads account.json again. No password, code or key ever reaches it.
(() => {
  const TITLES = {
    username: 'User name',
    email: 'Email address',
    password: 'Password',
    pin: 'PIN',
    totp: 'Authenticator app',
    recovery_codes: 'Recovery codes',
    passkeys: 'Passkeys',
    api_keys: 'API keys',
    app_passwords: 'App passwords',
    sessions: 'Other sessions',
    session_end: 'Session',
    programs: 'Connected programs',
    services: 'Services',
  };
  const RESULTS = { done: 'done', cancelled: 'nothing changed', unavailable: 'not offered here' };
  const KEY = 'ex4.states';

  function issued() {
    try {
      const list = JSON.parse(sessionStorage.getItem(KEY) || '[]');
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  function remember(list) {
    try {
      sessionStorage.setItem(KEY, JSON.stringify(list.slice(-20)));
    } catch {
      // A page without storage still works; it then cannot tell its own results from others.
    }
  }

  /** The href rule of spec section 8: an absolute http(s) URL or a path with exactly one leading slash. */
  function safe(href) {
    if (typeof href !== 'string' || [...href].some((ch) => ch <= ' ' || ch === '\x7f' || ch === '\\')) {
      return null;
    }
    if (href.startsWith('/') && !href.startsWith('//')) {
      return href;
    }
    try {
      const u = new URL(href);
      return u.protocol === 'https:' || u.protocol === 'http:' ? href : null;
    } catch {
      return null;
    }
  }

  /** The address of an action page with the way back to this page and a fresh state of its own. */
  function leave(href) {
    const state = Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, '0')).join(
      '',
    );
    remember([...issued(), state]);
    const u = new URL(href, location.origin);
    u.searchParams.set('return', `${location.origin}/settings`);
    u.searchParams.set('state', state);
    return u.href;
  }

  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      node.setAttribute(k, v);
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  function when(ts) {
    return typeof ts === 'number' ? new Date(ts * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
  }

  /** One row: a text and, where TinySesam offers the action, a link to its page. */
  function row(id, text, href, label) {
    const li = el('li', { id: `row-${id}` });
    li.append(el('span', {}, text));
    const target = safe(href);
    if (target) {
      li.append(el('a', { class: 'act', href: target, 'data-act': id }, label));
    }
    return li;
  }

  function section(title, rows) {
    const box = el('section', {});
    box.append(el('h2', {}, title));
    const list = el('ul', {});
    for (const r of rows) {
      list.append(r);
    }
    box.append(list);
    return box;
  }

  function draw(data) {
    const out = document.getElementById('settings');
    out.replaceChildren();
    const a = data.actions && typeof data.actions === 'object' ? data.actions : {};
    const sign = data.sign_in || {};
    const account = data.account || {};
    const progs = data.programs || {};
    const acc = [row('username', `User name: ${account.username || '?'}`, a.username, 'Change')];
    if (a.email) {
      acc.push(row('email', 'Email address', a.email, 'Change'));
    }
    out.append(section('Account', acc));
    const sec = [];
    if (sign.password !== null && sign.password !== undefined) {
      sec.push(row('password', `Password: ${sign.password}`, a.password, 'Change'));
    }
    if (sign.totp) {
      sec.push(row('totp', `Authenticator app: ${sign.totp.enabled ? 'on' : 'off'}`, a.totp, 'Manage'));
      if (a.recovery_codes) {
        sec.push(
          row('recovery_codes', `Recovery codes left: ${sign.totp.recovery_left}`, a.recovery_codes, 'New codes'),
        );
      }
    }
    if (sign.passkeys) {
      sec.push(row('passkeys', `Passkeys: ${sign.passkeys.count}`, a.passkeys, 'Manage'));
    }
    if (sign.pin !== null && sign.pin !== undefined) {
      sec.push(row('pin', `PIN: ${sign.pin ? 'set' : 'not set'}`, a.pin, 'Manage'));
    }
    out.append(section('Signing in', sec));
    const items = (data.sessions && Array.isArray(data.sessions.items) && data.sessions.items) || [];
    const sess = items.map((s, i) =>
      row(
        `session-${i}`,
        `${s.device || 'unknown device'} · ${s.method} · since ${when(s.created_at)}${s.current ? ' (this one)' : ''}`,
        s.current ? null : s.end,
        'End',
      ),
    );
    sess.push(row('sessions', `${items.length} session(s)`, a.sessions, 'End the others'));
    out.append(section('Sessions', sess));
    const keys = [];
    if (typeof progs.api_keys_active === 'number') {
      keys.push(row('api_keys', `API keys: ${progs.api_keys_active}`, a.api_keys, 'Manage'));
    }
    if (Array.isArray(progs.app_passwords)) {
      keys.push(row('app_passwords', `App passwords: ${progs.app_passwords.length}`, a.app_passwords, 'Manage'));
    }
    if (Array.isArray(progs.oauth)) {
      keys.push(row('programs', `Connected programs: ${progs.oauth.length}`, a.programs, 'Manage'));
    }
    if (Array.isArray(progs.services)) {
      keys.push(row('services', `Services: ${progs.services.length}`, a.services, 'Manage'));
    }
    out.append(section('Programs and keys', keys));
  }

  /** Back from an action page: a message for a result this page asked for, and the address without the three. */
  function result() {
    const q = new URLSearchParams(location.search);
    // Only names this page knows: a value from the address becomes a key of its own tables, never text of its own.
    const action = Object.keys(TITLES).find((k) => k === q.get('ts_action'));
    const outcome = Object.keys(RESULTS).find((k) => k === q.get('ts_result')) || 'unknown';
    if (!q.has('ts_action')) {
      return;
    }
    const state = q.get('state') || '';
    const list = issued();
    const notice = document.getElementById('notice');
    if (list.includes(state)) {
      remember(list.filter((s) => s !== state));
      notice.textContent = `${action ? TITLES[action] : 'Unknown action'}: ${RESULTS[outcome] || 'unknown result'}`;
      notice.dataset.result = outcome;
    } else {
      notice.textContent = 'A result came back that this page did not ask for — ignored.';
      notice.dataset.result = 'foreign';
    }
    notice.dataset.action = action || 'unknown';
    notice.hidden = false;
    history.replaceState(null, '', location.pathname);
  }

  async function load() {
    const out = document.getElementById('settings');
    try {
      const r = await fetch('/.tinysesam/account.json', { cache: 'no-store', credentials: 'same-origin' });
      const data = r.ok ? await r.json() : null;
      if (data?.signed_in !== true) {
        out.replaceChildren(el('p', { id: 'signed-out' }, 'Signed out.'));
        return;
      }
      draw(data);
      out.dataset.loaded = '1';
    } catch {
      out.replaceChildren(el('p', { id: 'failed' }, 'The settings could not be read.'));
    }
  }

  // The state goes on as the link is followed, so every visit to an action page carries a value of its own.
  document.addEventListener('click', (e) => {
    const a = e.target instanceof Element ? e.target.closest('a.act') : null;
    if (a) {
      a.href = leave(a.getAttribute('href'));
    }
  });
  result();
  load();
})();
