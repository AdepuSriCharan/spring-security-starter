const STORAGE_KEYS = {
  accessToken: 'security.explainer.accessToken',
  refreshToken: 'security.explainer.refreshToken',
};

const els = {
  configBadge: document.getElementById('configBadge'),
  tokenBadge: document.getElementById('tokenBadge'),
  googleButtonWrap: document.getElementById('googleButtonWrap'),
  googleButtonStatus: document.getElementById('googleButtonStatus'),
  googleToken: document.getElementById('googleToken'),
  exchangeBtn: document.getElementById('exchangeBtn'),
  loadSampleBtn: document.getElementById('loadSampleBtn'),
  accessTokenView: document.getElementById('accessTokenView'),
  refreshTokenView: document.getElementById('refreshTokenView'),
  copyAccessBtn: document.getElementById('copyAccessBtn'),
  copyRefreshBtn: document.getElementById('copyRefreshBtn'),
  meBtn: document.getElementById('meBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  logoutBtn: document.getElementById('logoutBtn'),
  clearAllBtn: document.getElementById('clearAllBtn'),
  output: document.getElementById('output'),
};

let googleConfig = null;
let googleScriptPromise = null;

function readToken(key) {
  return localStorage.getItem(key) || '';
}

function saveToken(key, value) {
  if (value) {
    localStorage.setItem(key, value);
  } else {
    localStorage.removeItem(key);
  }
  renderStoredTokens();
}

function clearStoredTokens() {
  localStorage.removeItem(STORAGE_KEYS.accessToken);
  localStorage.removeItem(STORAGE_KEYS.refreshToken);
  renderStoredTokens();
}

function renderStoredTokens() {
  const accessToken = readToken(STORAGE_KEYS.accessToken);
  const refreshToken = readToken(STORAGE_KEYS.refreshToken);

  els.accessTokenView.textContent = accessToken || 'No access token yet.';
  els.refreshTokenView.textContent = refreshToken || 'No refresh token yet.';

  if (accessToken && refreshToken) {
    els.tokenBadge.textContent = 'Tokens stored locally';
    els.tokenBadge.className = 'badge badge-ok';
  } else if (accessToken || refreshToken) {
    els.tokenBadge.textContent = 'Partial token state';
    els.tokenBadge.className = 'badge badge-warn';
  } else {
    els.tokenBadge.textContent = 'No tokens stored';
    els.tokenBadge.className = 'badge badge-muted';
  }
}

function setOutput(value) {
  if (typeof value === 'string') {
    els.output.textContent = value;
    return;
  }
  els.output.textContent = JSON.stringify(value, null, 2);
}

function setConfigBadge(kind, text) {
  els.configBadge.textContent = text;
  els.configBadge.className = `badge badge-${kind}`;
}

function isRealClientId(clientId) {
  if (!clientId) return false;
  const placeholderHints = ['GOOGLE_CLIENT_ID', 'your-google', 'your-client-id', 'replace-me'];
  return !placeholderHints.some((hint) => clientId.includes(hint));
}

function getRealClientIds(clientIds) {
  return (clientIds || [])
    .map((clientId) => (typeof clientId === 'string' ? clientId.trim() : ''))
    .filter((clientId) => isRealClientId(clientId));
}

function getPrimaryClientId(clientIds) {
  const realClientIds = getRealClientIds(clientIds);
  return realClientIds.length > 0 ? realClientIds[0] : '';
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json');
  }

  const accessToken = readToken(STORAGE_KEYS.accessToken);
  if (accessToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  const response = await fetch(path, {
    ...options,
    headers,
  });

  const contentType = response.headers.get('content-type') || '';
  const body = contentType.includes('application/json')
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message = typeof body === 'string' ? body : body.message || body.error || 'Request failed';
    throw new Error(`${response.status} ${message}`);
  }

  return body;
}

async function exchangeGoogleToken(idToken) {
  if (!idToken || !idToken.trim()) {
    throw new Error('Paste a Google ID token first.');
  }

  setOutput('Exchanging Google token...');
  const body = await apiFetch('/login/google', {
    method: 'POST',
    body: JSON.stringify({ idToken: idToken.trim() }),
  });

  saveToken(STORAGE_KEYS.accessToken, body.accessToken);
  saveToken(STORAGE_KEYS.refreshToken, body.refreshToken);
  setOutput(body);
}

async function loginWithGoogleCredential(credential) {
  await exchangeGoogleToken(credential);
}

async function loadGoogleButton() {
  const clientId = getPrimaryClientId(googleConfig?.clientIds);
  if (!googleConfig || !googleConfig.enabled || !clientId) {
    els.googleButtonStatus.textContent = 'Google button unavailable. Configure `security.google.client-ids` to enable it.';
    return;
  }

  if (!googleScriptPromise) {
    googleScriptPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector('script[data-google-gis]');
      if (existing) {
        resolve();
        return;
      }

      const script = document.createElement('script');
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      script.dataset.googleGis = 'true';
      script.onload = resolve;
      script.onerror = () => reject(new Error('Could not load Google Sign-In script.'));
      document.head.appendChild(script);
    });
  }

  try {
    await googleScriptPromise;
    if (!window.google || !window.google.accounts || !window.google.accounts.id) {
      throw new Error('Google Sign-In script did not initialize.');
    }

    els.googleButtonStatus.textContent = 'Google button ready.';
    els.googleButtonStatus.className = 'google-placeholder';
    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: (response) => {
        loginWithGoogleCredential(response.credential).catch((error) => {
          setOutput({ error: error.message });
        });
      },
    });
    window.google.accounts.id.renderButton(els.googleButtonWrap, {
      theme: 'outline',
      size: 'large',
      type: 'standard',
      text: 'signin_with',
      shape: 'pill',
      width: 320,
    });
  } catch (error) {
    els.googleButtonStatus.textContent = error.message;
    els.googleButtonStatus.className = 'google-placeholder';
  }
}

async function loadConfig() {
  try {
    const config = await apiFetch('/google-auth-lab/config', { method: 'GET' });
    googleConfig = config;

    if (config.enabled && getPrimaryClientId(config.clientIds)) {
      setConfigBadge('ok', 'Google sign-in enabled');
    } else if (config.enabled) {
      setConfigBadge('warn', 'Google enabled, client IDs missing');
    } else {
      setConfigBadge('warn', 'Google sign-in disabled');
    }

    await loadGoogleButton();
  } catch (error) {
    setConfigBadge('bad', 'Could not load config');
    setOutput({ error: error.message });
    els.googleButtonStatus.textContent = 'Falling back to manual token paste.';
  }
}

async function callMe() {
  const body = await apiFetch('/me', { method: 'GET' });
  setOutput(body);
}

async function refreshSession() {
  const refreshToken = readToken(STORAGE_KEYS.refreshToken);
  if (!refreshToken) {
    throw new Error('No refresh token stored.');
  }

  const body = await apiFetch('/refresh', {
    method: 'POST',
    body: JSON.stringify({ refreshToken }),
  });

  saveToken(STORAGE_KEYS.accessToken, body.accessToken);
  saveToken(STORAGE_KEYS.refreshToken, body.refreshToken);
  setOutput(body);
}

async function logout() {
  const refreshToken = readToken(STORAGE_KEYS.refreshToken);
  if (!refreshToken) {
    throw new Error('No refresh token stored.');
  }

  const body = await apiFetch('/logout', {
    method: 'POST',
    body: JSON.stringify({ refreshToken }),
  });

  clearStoredTokens();
  setOutput(body);
}

function bindUi() {
  els.exchangeBtn.addEventListener('click', async () => {
    try {
      await exchangeGoogleToken(els.googleToken.value);
    } catch (error) {
      setOutput({ error: error.message });
    }
  });

  els.loadSampleBtn.addEventListener('click', () => {
    els.googleToken.value = [
      'This page expects a real Google ID token.',
      'If Google sign-in is configured, click the Google button above.',
      'Otherwise paste the idToken from your mobile app or Google Identity Services flow here.',
    ].join('\n');
  });

  els.copyAccessBtn.addEventListener('click', async () => {
    const token = readToken(STORAGE_KEYS.accessToken);
    if (!token) return setOutput({ error: 'No access token stored yet.' });
    await navigator.clipboard.writeText(token);
    setOutput('Access token copied to clipboard.');
  });

  els.copyRefreshBtn.addEventListener('click', async () => {
    const token = readToken(STORAGE_KEYS.refreshToken);
    if (!token) return setOutput({ error: 'No refresh token stored yet.' });
    await navigator.clipboard.writeText(token);
    setOutput('Refresh token copied to clipboard.');
  });

  els.meBtn.addEventListener('click', async () => {
    try {
      await callMe();
    } catch (error) {
      setOutput({ error: error.message });
    }
  });

  els.refreshBtn.addEventListener('click', async () => {
    try {
      await refreshSession();
    } catch (error) {
      setOutput({ error: error.message });
    }
  });

  els.logoutBtn.addEventListener('click', async () => {
    try {
      await logout();
    } catch (error) {
      setOutput({ error: error.message });
    }
  });

  els.clearAllBtn.addEventListener('click', () => {
    clearStoredTokens();
    setOutput('Local tokens cleared.');
  });
}

function boot() {
  renderStoredTokens();
  bindUi();
  loadConfig();
}

boot();
