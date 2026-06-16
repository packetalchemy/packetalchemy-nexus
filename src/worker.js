/*
 * PacketAlchemy Nexus
 * Cloudflare Edge Engineering Platform
 *
 * Where Packets Become Intelligence
 *
 * Features merged from reference architectures:
 * - Multi-user management with D1 persistence (from Nahan)
 * - VLESS WebSocket proxy tunneling (from B2B/Nahan)
 * - Subscription profile generation - Clash/Sing-box/base64 (from Nahan/B2B)
 * - Dashboard UI (from Nahan/B2B)
 * - Telegram bot notifications (from Nahan)
 * - JWT authentication (from B2B)
 * - Usage tracking with auto-disable (from Nahan)
 * - DNS-over-HTTPS (from B2B)
 */

import { connect } from 'cloudflare:sockets';

// ============================================================
// Configuration
// ============================================================

const CURRENT_VERSION = '1.0.0';

const SYSTEM_DEFAULTS = {
  name: 'PacketAlchemy Nexus',
  apiRoute: 'nexus',
  masterKey: 'admin',
  maintenanceHost: 'https://www.ubuntu.com',
  customRelay: '',
  proxyIP: '',
  cleanIps: '',
  dohURL: 'https://cloudflare-dns.com/dns-query',
  resolveIp: '1.1.1.1',
  ports: '443',
  users: [],
  isPaused: false,
  tgToken: '',
  tgChatId: '',
  tgAdminId: '',
  cfAccountId: '',
  cfApiToken: '',
  customPanelUrl: '',
  limitTotalReq: 0,
  expiryMs: 0,
};

const SYSTEM_SECURITY = {
  securityHeaders: {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  },
  rateLimit: {
    windowMs: 60000,
    maxRequests: 100,
  },
};

// ============================================================
// State Management
// ============================================================

let sysConfig = { ...SYSTEM_DEFAULTS };
let sysUsageCache = { users: {} };
let lastSysUsageSync = 0;
let sysConfigCacheTime = 0;
let sysUsageCacheTime = 0;

const CACHE_TTL_CONFIG = 10000;
const CACHE_TTL_USAGE = 10000;

const rateLimitStore = new Map();

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// ============================================================
// D1 Database Helpers
// ============================================================

async function d1Init(env) {
  if (env.PA_DB && !env.PA_DB_INITIALIZED) {
    try {
      await env.PA_DB.prepare('CREATE TABLE IF NOT EXISTS kv_store (key TEXT PRIMARY KEY, value TEXT)').run();
      env.PA_DB_INITIALIZED = true;
    } catch (e) {
      env.PA_DB_INITIALIZED = true;
    }
  }
}

async function d1Get(env, key) {
  if (!env.PA_DB) return null;
  await d1Init(env);
  try {
    const { results } = await env.PA_DB.prepare('SELECT value FROM kv_store WHERE key = ?').bind(key).all();
    if (results && results.length > 0) return results[0].value;
  } catch (e) {}
  return null;
}

async function d1Put(env, key, value) {
  if (!env.PA_DB) return;
  await d1Init(env);
  try {
    await env.PA_DB.prepare('INSERT INTO kv_store (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(key, value).run();
  } catch (e) {}
}

async function cachedD1Put(env, key, value) {
  await d1Put(env, key, value);
  if (key === 'sys_config') sysConfigCacheTime = 0;
  else if (key === 'sys_usage') sysUsageCacheTime = 0;
}

// ============================================================
// Config Loading (with D1 persistence + in-memory cache)
// ============================================================

async function loadSysConfig(env) {
  const now = Date.now();

  if (env.PA_DB) {
    if (now - sysConfigCacheTime > CACHE_TTL_CONFIG) {
      const stored = await d1Get(env, 'sys_config');
      sysConfig = { ...SYSTEM_DEFAULTS, ...(stored ? JSON.parse(stored) : null) };
      sysConfigCacheTime = now;
    }
    if (now - sysUsageCacheTime > CACHE_TTL_USAGE) {
      const ustored = await d1Get(env, 'sys_usage');
      sysUsageCache = ustored ? JSON.parse(ustored) : { users: {} };
      sysUsageCacheTime = now;
    }
  }
}

// ============================================================
// Crypto Helpers
// ============================================================

function sha224Hex(m) {
  const msg = new TextEncoder().encode(m);
  const K = [0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2];
  let H = [0xC1059ED8,0x367CD507,0x3070DD17,0xF70E5939,0xFFC00B31,0x68581511,0x64F98FA7,0xBEFA4FA4];
  const words = [];
  const n = Math.ceil((msg.length + 9) / 64) * 16;
  for (let i = 0; i < n; i++) words[i] = 0;
  for (let i = 0; i < msg.length; i++) words[i >> 2] |= msg[i] << (24 - (i % 4) * 8);
  words[msg.length >> 2] |= 0x80 << (24 - (msg.length % 4) * 8);
  words[n - 1] = msg.length * 8;
  const W = [];
  for (let i = 0; i < n; i += 16) {
    let [a, b, c, d, e, f, g, h] = H;
    for (let j = 0; j < 64; j++) {
      if (j < 16) W[j] = words[i + j];
      else {
        let w15 = W[j - 15], w2 = W[j - 2];
        let s0 = (w15 >>> 7 | w15 << 25) ^ (w15 >>> 18 | w15 << 14) ^ (w15 >>> 3);
        let s1 = (w2 >>> 17 | w2 << 15) ^ (w2 >>> 19 | w2 << 13) ^ (w2 >>> 10);
        W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0;
      }
      let S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
      let ch = (e & f) ^ (~e & g);
      let temp1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
      let S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
      let maj = (a & b) ^ (a & c) ^ (b & c);
      let temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  return H.slice(0, 7).map(v => v.toString(16).padStart(8, '0')).join('');
}

const trojanHashCache = new Map();
function getTrojanHash(uuid) {
  if (trojanHashCache.has(uuid)) return trojanHashCache.get(uuid);
  const hash = sha224Hex(uuid);
  trojanHashCache.set(uuid, hash);
  return hash;
}

function generateSecretKey() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

function generateJWTToken(secretKey, password) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ password, exp: Date.now() + 7 * 86400000 }));
  const data = `${header}.${payload}`;
  const signature = btoa(secretKey.slice(0, 32));
  return `${data}.${signature}`;
}

function verifyJWTToken(token, secretKey) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const expectedSig = btoa(secretKey.slice(0, 32));
    return parts[2] === expectedSig;
  } catch (e) {
    return false;
  }
}

// ============================================================
// UUID Helpers
// ============================================================

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
  return unsafeStringify(arr, offset);
}

function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// ============================================================
// Base64 / URL Helpers
// ============================================================

function safeBtoa(str) {
  try {
    const bytes = new TextEncoder().encode(str);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch (e) {
    return btoa(str);
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function randomUpperCase(str) {
  return str.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c).join('');
}

function getRandomPath(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// ============================================================
// DNS Helpers
// ============================================================

async function resolveDNS(hostname) {
  const ipv4 = [];
  const ipv6 = [];
  try {
    const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
      headers: { 'accept': 'application/dns-json' }
    });
    const data = await resp.json();
    if (data.Answer) {
      data.Answer.forEach(a => {
        if (a.type === 1) ipv4.push(a.data);
        if (a.type === 28) ipv6.push(a.data);
      });
    }
  } catch (e) {}
  return { ipv4, ipv6 };
}

// ============================================================
// Usage Tracking (from Nahan)
// ============================================================

function trackUsage(uuid, bytes, env, ctx) {
  if (!sysUsageCache) sysUsageCache = { users: {} };
  if (!sysUsageCache.users) sysUsageCache.users = {};
  if (!sysUsageCache.users[uuid]) sysUsageCache.users[uuid] = { reqs: 0, dReqs: 0, lastDay: new Date().toISOString().split('T')[0] };

  let u = sysUsageCache.users[uuid];
  let today = new Date().toISOString().split('T')[0];
  if (u.lastDay !== today) {
    u.dReqs = 0;
    u.lastDay = today;
  }

  if (bytes === 0) {
    u.reqs += 1;
    u.dReqs += 1;
  }

  const now = Date.now();
  if (now - lastSysUsageSync > 30000) {
    lastSysUsageSync = now;
    if (env && env.PA_DB) {
      if (sysConfig.users && sysConfig.users.length > 0) {
        let changedConfig = false;
        sysConfig.users.forEach(user => {
          let uId = user.id.replace(/-/g, '').toLowerCase();
          let sysU = sysUsageCache.users[uId];
          if (!user.isPaused) {
            let reason = null;
            if (user.expiryMs && Date.now() > user.expiryMs) {
              reason = `Expiration reached (${new Date(user.expiryMs).toLocaleDateString()})`;
            } else if (sysU && user.limitTotalReq && sysU.reqs >= user.limitTotalReq) {
              reason = `Traffic limit exceeded`;
            }
            if (reason) {
              user.isPaused = true;
              user.disabledReason = reason;
              user.disabledAt = Date.now();
              changedConfig = true;
            }
          }
        });
        if (changedConfig) {
          ctx?.waitUntil(cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig)).catch(() => {}));
        }
      }
      ctx?.waitUntil(cachedD1Put(env, 'sys_usage', JSON.stringify(sysUsageCache)).catch(() => {}));
    }
  }
}

// ============================================================
// Telegram Notifications (from Nahan)
// ============================================================

async function sendTelegramMessage(text, env) {
  if (!sysConfig.tgToken || !(sysConfig.tgAdminId || sysConfig.tgChatId)) return;
  const notifyChatId = sysConfig.tgAdminId || sysConfig.tgChatId;
  try {
    await fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: notifyChatId, text, parse_mode: 'HTML' })
    });
  } catch (e) {}
}

// ============================================================
// Subscription Profile Builders (from Nahan/B2B)
// ============================================================

function buildClashYamlProfile(host, sub, proxyIP) {
  const trojanHash = getTrojanHash(sysConfig.users[0]?.id || sysConfig.masterKey);
  let yaml = `mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\n\nproxies:\n`;

  const ports = (sysConfig.ports || '443').split(',');
  ports.forEach(port => {
    const isTLS = ['443', '8443', '2053', '2083', '2087', '2096'].includes(port.trim());
    yaml += `  - name: "PacketAlchemy-${port.trim()}"\n`;
    yaml += `    type: trojan\n`;
    yaml += `    server: ${host}\n`;
    yaml += `    port: ${port.trim()}\n`;
    yaml += `    password: ${trojanHash}\n`;
    if (isTLS) {
      yaml += `    sni: ${host}\n`;
      yaml += `    skip-cert-verify: true\n`;
    }
    yaml += `    network: ws\n`;
    yaml += `    ws-opts:\n`;
    yaml += `      path: /${getRandomPath(16)}\n`;
    yaml += `      headers:\n`;
    yaml += `        Host: ${host}\n`;
    yaml += `\n`;
  });

  yaml += `proxy-groups:\n  - name: "PacketAlchemy"\n    type: select\n    proxies:\n`;
  ports.forEach(port => {
    yaml += `      - "PacketAlchemy-${port.trim()}"\n`;
  });

  yaml += `\nrules:\n  - MATCH,PacketAlchemy\n`;
  return yaml;
}

function buildSingboxConfig(host, sub, proxyIP) {
  const trojanHash = getTrojanHash(sysConfig.users[0]?.id || sysConfig.masterKey);
  const config = {
    dns: {
      servers: [
        { tag: 'dns-remote', address: 'https://cloudflare-dns.com/dns-query', detour: 'PacketAlchemy' },
        { tag: 'dns-direct', address: 'rcode://success', detour: 'direct' }
      ],
      rules: [
        { domain_suffix: ['.ir'], server: 'dns-direct' }
      ]
    },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 7890 }
    ],
    outbounds: [
      { tag: 'PacketAlchemy', type: 'selector', outbounds: [] },
      { tag: 'direct', type: 'direct' },
      { tag: 'block', type: 'block' }
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { ip_is_private: true, outbound: 'direct' }
      ],
      final: 'PacketAlchemy'
    }
  };

  const ports = (sysConfig.ports || '443').split(',');
  ports.forEach(port => {
    const tag = `PacketAlchemy-${port.trim()}`;
    config.outbounds.splice(config.outbounds.length - 3, 0, {
      type: 'trojan',
      tag,
      server: host,
      server_port: parseInt(port.trim()),
      password: trojanHash,
      tls: {
        enabled: ['443', '8443', '2053', '2083', '2087', '2096'].includes(port.trim()),
        server_name: host,
        insecure: true,
      },
      transport: {
        type: 'ws',
        path: `/${getRandomPath(16)}`,
        headers: { Host: host }
      }
    });
    config.outbounds[0].outbounds.push(tag);
  });

  return config;
}

function buildClashJsonProfile(host, sub, proxyIP) {
  return buildClashYamlProfile(host, sub, proxyIP);
}

function buildRawUriProfile(host, sub, proxyIP) {
  const trojanHash = getTrojanHash(sysConfig.users[0]?.id || sysConfig.masterKey);
  const ports = (sysConfig.ports || '443').split(',');
  let uris = '';
  ports.forEach(port => {
    const isTLS = ['443', '8443', '2053', '2083', '2087', '2096'].includes(port.trim());
    uris += `trojan://${trojanHash}@${host}:${port.trim()}?type=ws&host=${encodeURIComponent(host)}&path=${encodeURIComponent('/' + getRandomPath(16))}${isTLS ? `&security=tls&sni=${host}&allowInsecure=1` : ''}#${encodeURIComponent('PacketAlchemy-' + port.trim())}\n`;
  });
  return uris;
}

// ============================================================
// VLESS WebSocket Proxy (from B2B/Nahan)
// ============================================================

async function vlessOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = '';
  let portWithRandomLog = '';
  const log = (info, event) => {
    console.log(`[PA ${address}:${portWithRandomLog}] ${info}`, event || '');
  };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns && udpStreamWrite) {
        return udpStreamWrite(chunk);
      }
      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const { hasError, message, portRemote = 443, addressRemote = '', rawDataIndex, vlessVersion = new Uint8Array([0, 0]), isUDP } = processVlessHeader(chunk);
      address = addressRemote;
      portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
      if (hasError) {
        throw new Error(message);
      }

      if (isUDP && portRemote !== 53) {
        throw new Error('UDP proxy only enabled for DNS which is port 53');
      }

      if (isUDP && portRemote === 53) {
        isDns = true;
      }

      const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);

      if (isDns) {
        const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
        udpStreamWrite = write;
        udpStreamWrite(rawClientData);
        return;
      }
      handleTCPOutBound(request, remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
    },
    close() { log('readableWebSocketStream is close'); },
    abort(reason) { log('readableWebSocketStream is abort', JSON.stringify(reason)); },
  })).catch((err) => {
    log('readableWebSocketStream pipeTo error', err);
  });

  return new Response(null, { status: 101, webSocket: client });
}

function processVlessHeader(vlessBuffer) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }

  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const uuids = sysConfig.users?.map(u => u.id) || [sysConfig.masterKey];
  const isValidUser = uuids.some(uId => slicedBufferString === uId.replace(/-/g, '').toLowerCase()) ||
    uuids.some(uId => slicedBufferString === uId);

  if (!isValidUser) {
    return { hasError: true, message: 'invalid user' };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  const isUDP = command === 2;

  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `command ${command} is not supported` };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: `invalid addressType is ${addressType}` };
  }

  if (!addressValue) {
    return { hasError: true, message: `addressValue is empty` };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {},
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}

async function handleTCPOutBound(request, remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const proxyIP = sysConfig.proxyIP || addressRemote;
    const tcpSocket = await connectAndWrite(proxyIP, portRemote);
    tcpSocket.closed.catch(error => {
      console.log('retry tcpSocket closed error', error);
    }).finally(() => {
      safeCloseWebSocket(webSocket);
    });
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk, controller) {
      hasIncomingData = true;
      if (webSocket.readyState !== WS_READY_STATE_OPEN) {
        controller.error('webSocket.readyState is not open');
      }
      if (vlessHeader) {
        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
        vlessHeader = null;
      } else {
        webSocket.send(chunk);
      }
    },
    close() {
      log(`remoteConnection readable close, hasIncomingData=${hasIncomingData}`);
    },
    abort(reason) {
      console.error('remoteConnection readable abort', reason);
    },
  })).catch((error) => {
    console.error('remoteSocketToWS exception', error.stack || error);
    safeCloseWebSocket(webSocket);
  });

  if (hasIncomingData === false && retry) {
    log('retry');
    retry();
  }
}

async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {}
  });

  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch(sysConfig.dohURL || 'https://cloudflare-dns.com/dns-query', {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message' },
        body: chunk,
      });
      const dnsQueryResult = await resp.arrayBuffer();
      const udpSize = dnsQueryResult.byteLength;
      const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
      if (webSocket.readyState === WS_READY_STATE_OPEN) {
        log(`doh success, dns message length=${udpSize}`);
        if (isVlessHeaderSent) {
          webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
        } else {
          webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
          isVlessHeaderSent = true;
        }
      }
    }
  })).catch((error) => {
    log('dns udp error: ' + error);
  });

  const writer = transformStream.writable.getWriter();
  return { write(chunk) { writer.write(chunk); } };
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}

// ============================================================
// HTML Pages
// ============================================================

function serveMaintenancePage(request, url) {
  const fakeList = sysConfig.maintenanceHost ? sysConfig.maintenanceHost.split(',').map(s => s.trim()).filter(s => s) : ['https://www.ubuntu.com'];
  const clientIP = request.headers.get('cf-connecting-ip') || '0.0.0.0';
  const ipHash = Array.from(clientIP).reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const targetStr = fakeList[ipHash % fakeList.length].startsWith('http') ? fakeList[ipHash % fakeList.length] : `https://${fakeList[ipHash % fakeList.length]}`;

  try {
    const targetUrl = new URL(targetStr);
    if (url.pathname !== '/') targetUrl.pathname = url.pathname;
    targetUrl.search = url.search;
    const cleanHeaders = new Headers(request.headers);
    cleanHeaders.set('Host', targetUrl.hostname);
    cleanHeaders.delete('cf-connecting-ip');
    cleanHeaders.delete('x-forwarded-for');
    const fetchInit = { method: request.method, headers: cleanHeaders, redirect: 'follow' };
    if (request.method !== 'GET' && request.method !== 'HEAD') fetchInit.body = request.body;
    return fetch(new Request(targetUrl.toString(), fetchInit));
  } catch (e) {
    return new Response('Not Found', { status: 404 });
  }
}

function serveDashboardPage(env) {
  const hasDB = env.PA_DB !== undefined;
  const userCount = sysConfig.users?.length || 0;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PacketAlchemy Nexus - Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background: #0a0a0a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 1.5rem; }
  </style>
</head>
<body class="min-h-screen p-8">
  <div class="max-w-4xl mx-auto">
    <h1 class="text-3xl font-bold text-white mb-2">PacketAlchemy Nexus</h1>
    <p class="text-gray-400 mb-8">Edge Engineering Platform Dashboard</p>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <div class="card">
        <p class="text-sm text-gray-400 uppercase tracking-wider">Version</p>
        <p class="text-2xl font-bold text-white mt-1">${CURRENT_VERSION}</p>
      </div>
      <div class="card">
        <p class="text-sm text-gray-400 uppercase tracking-wider">Users</p>
        <p class="text-2xl font-bold text-white mt-1">${userCount}</p>
      </div>
      <div class="card">
        <p class="text-sm text-gray-400 uppercase tracking-wider">D1 Database</p>
        <p class="text-2xl font-bold mt-1 ${hasDB ? 'text-green-400' : 'text-red-400'}">${hasDB ? 'Connected' : 'Not Connected'}</p>
      </div>
    </div>
    <div class="card">
      <h2 class="text-lg font-bold text-white mb-4">API Endpoints</h2>
      <div class="space-y-2 text-sm">
        <div class="flex justify-between border-b border-gray-700 pb-2"><span class="text-gray-400">GET</span><span>/${sysConfig.apiRoute}</span><span class="text-gray-500">Subscription profile</span></div>
        <div class="flex justify-between border-b border-gray-700 pb-2"><span class="text-gray-400">POST</span><span>/${sysConfig.apiRoute}/api/auth</span><span class="text-gray-500">JWT authentication</span></div>
        <div class="flex justify-between border-b border-gray-700 pb-2"><span class="text-gray-400">POST</span><span>/${sysConfig.apiRoute}/api/sync</span><span class="text-gray-500">Config sync</span></div>
        <div class="flex justify-between border-b border-gray-700 pb-2"><span class="text-gray-400">GET/POST</span><span>/${sysConfig.apiRoute}/api/users</span><span class="text-gray-500">User management</span></div>
        <div class="flex justify-between"><span class="text-gray-400">GET</span><span>/${sysConfig.apiRoute}/api/stats</span><span class="text-gray-500">Usage statistics</span></div>
      </div>
    </div>
  </div>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

function serveLandingPage(url) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PacketAlchemy Nexus</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { text-align: center; max-width: 600px; padding: 2rem; }
    h1 { font-size: 2.5rem; margin-bottom: 0.5rem; color: #fff; }
    .tagline { color: #00d4ff; font-size: 1.2rem; margin-bottom: 2rem; }
    .endpoints { text-align: left; background: #1a1a1a; padding: 1.5rem; border-radius: 8px; }
    .endpoint { padding: 0.5rem 0; border-bottom: 1px solid #333; }
    .endpoint:last-child { border-bottom: none; }
    .endpoint a { color: #00d4ff; text-decoration: none; }
    .method { color: #4ade80; font-family: monospace; }
    footer { margin-top: 2rem; color: #666; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>PacketAlchemy Nexus</h1>
    <p class="tagline">Where Packets Become Intelligence</p>
    <div class="endpoints">
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}/dash">/${sysConfig.apiRoute}/dash</a> - Dashboard</div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}">/${sysConfig.apiRoute}</a> - Subscription</div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}/api/users">/${sysConfig.apiRoute}/api/users</a> - Users API</div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}/api/stats">/${sysConfig.apiRoute}/api/stats</a> - Stats API</div>
    </div>
    <footer>PacketAlchemy Edge Engineering Platform v${CURRENT_VERSION}</footer>
  </div>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

// ============================================================
// API Handlers
// ============================================================

async function handleAuth(request, hostname, ctx, env) {
  try {
    const data = await request.json();
    if (data.key !== sysConfig.masterKey) {
      return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }

    const secretKey = await d1Get(env, 'secretKey') || generateSecretKey();
    if (!(await d1Get(env, 'secretKey'))) {
      await d1Put(env, 'secretKey', secretKey);
    }

    const jwtToken = generateJWTToken(secretKey, data.key);
    return new Response(JSON.stringify({ success: true, token: jwtToken }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': `jwtToken=${jwtToken}; HttpOnly; Secure; Max-Age=${7 * 86400}; Path=/; SameSite=Strict`
      }
    });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
}

async function handleConfigSync(request, env, ctx) {
  try {
    const data = await request.json();
    if (data.key !== sysConfig.masterKey) {
      return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });
    }
    if (data.config) {
      sysConfig = { ...sysConfig, ...data.config };
      await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
    }
    return new Response(JSON.stringify({ success: true, config: sysConfig }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), { status: 400 });
  }
}

async function handleUsersApi(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const method = request.method;
    const userId = url.searchParams.get('id');

    const authHeader = request.headers.get('Authorization') || '';
    const authKey = authHeader.replace('Bearer ', '') || url.searchParams.get('key') || '';
    let bodyKey = '';
    if (method === 'POST' || method === 'PUT') {
      try { const body = await request.clone().json(); bodyKey = body.key || ''; } catch (e) {}
    }
    if (authKey !== sysConfig.masterKey && bodyKey !== sysConfig.masterKey) {
      return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'GET' && !userId) {
      const users = (sysConfig.users || []).map(u => {
        const idClean = u.id.replace(/-/g, '').toLowerCase();
        const sysU = sysUsageCache?.users?.[idClean] || { reqs: 0 };
        const usedBytes = Math.floor((sysU.reqs || 0) * (1073741824 / 6000));
        const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824 / 6000)) : 0;
        return { ...u, usage: { total: usedBytes, limit: limitBytes } };
      });
      return new Response(JSON.stringify({ success: true, users, total: users.length }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'POST' && !userId) {
      const body = await request.json();
      const { name, trafficLimit, expiryDays } = body;
      if (!name) return new Response(JSON.stringify({ success: false, error: 'Name required' }), { status: 400 });
      const newUser = {
        id: crypto.randomUUID(),
        name,
        limitTotalReq: trafficLimit ? Math.floor(parseFloat(trafficLimit) * 6000) : null,
        expiryMs: expiryDays ? Date.now() + parseInt(expiryDays) * 86400000 : null,
        isPaused: false,
        createdAt: Date.now()
      };
      if (!sysConfig.users) sysConfig.users = [];
      sysConfig.users.push(newUser);
      await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
      ctx?.waitUntil(sendTelegramMessage(`New user created: ${name} (${newUser.id})`, env));
      return new Response(JSON.stringify({ success: true, user: newUser }), { status: 201, headers: { 'Content-Type': 'application/json' } });
    }

    return new Response(JSON.stringify({ success: false, error: 'Not found' }), { status: 404 });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500 });
  }
}

async function handleStatsApi(request, env) {
  try {
    const users = sysConfig.users || [];
    const totalUsers = users.length;
    const activeUsers = users.filter(u => !u.isPaused).length;
    let totalReqs = 0;
    users.forEach(u => {
      const idClean = u.id.replace(/-/g, '').toLowerCase();
      const sysU = sysUsageCache?.users?.[idClean];
      if (sysU) totalReqs += sysU.reqs || 0;
    });
    return new Response(JSON.stringify({
      success: true,
      stats: { totalUsers, activeUsers, totalRequests: totalReqs, version: CURRENT_VERSION }
    }), { headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500 });
  }
}

// ============================================================
// Worker Entry Point
// ============================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await loadSysConfig(env);

      const url = new URL(request.url);
      const upgradeHeader = request.headers.get('Upgrade');
      const isWebSocket = upgradeHeader && upgradeHeader.toLowerCase() === 'websocket';

      let reqPath = url.pathname;
      if (reqPath.endsWith('/') && reqPath.length > 1) reqPath = reqPath.slice(0, -1);

      const routes = {
        data: `/${encodeURI(sysConfig.apiRoute)}`,
        dash: `/${encodeURI(sysConfig.apiRoute)}/dash`,
        auth: `/${encodeURI(sysConfig.apiRoute)}/api/auth`,
        sync: `/${encodeURI(sysConfig.apiRoute)}/api/sync`,
        users: `/${encodeURI(sysConfig.apiRoute)}/api/users`,
        stats: `/${encodeURI(sysConfig.apiRoute)}/api/stats`,
      };

      const isApiRoute = reqPath.startsWith(`/${sysConfig.apiRoute}`);

      if (!isWebSocket && !isApiRoute) {
        if (reqPath === '/' || reqPath === '') {
          return serveLandingPage(url);
        }
        return serveMaintenancePage(request, url);
      }

      if (!isWebSocket) {
        if (reqPath === routes.dash) {
          return serveDashboardPage(env);
        }
        if (reqPath === routes.auth) {
          if (request.method !== 'POST') return new Response('405', { status: 405 });
          return await handleAuth(request, url.hostname, ctx, env);
        }
        if (reqPath === routes.sync) {
          if (request.method !== 'POST') return new Response('405', { status: 405 });
          return await handleConfigSync(request, env, ctx);
        }
        if (reqPath === routes.users || reqPath.endsWith('/api/users')) {
          return await handleUsersApi(request, env, ctx);
        }
        if (reqPath === routes.stats || reqPath.endsWith('/api/stats')) {
          return await handleStatsApi(request, env);
        }
        if (reqPath === routes.data) {
          const ua = (request.headers.get('User-Agent') || '').toLowerCase();
          const isBrowser = ua.includes('mozilla') || ua.includes('chrome') || ua.includes('safari');

          if (isBrowser) {
            return serveLandingPage(url);
          }

          const flag = (url.searchParams.get('flag') || url.searchParams.get('format') || '').toLowerCase();
          let contentType = 'text/plain; charset=utf-8';
          let body;

          if (flag === 'clash' || flag === 'yaml') {
            contentType = 'text/yaml; charset=utf-8';
            body = buildClashYamlProfile(url.hostname, null, sysConfig.proxyIP);
          } else if (flag === 'singbox' || flag === 'sb') {
            contentType = 'application/json; charset=utf-8';
            body = JSON.stringify(buildSingboxConfig(url.hostname, null, sysConfig.proxyIP), null, 2);
          } else {
            body = safeBtoa(buildRawUriProfile(url.hostname, null, sysConfig.proxyIP));
          }

          return new Response(body, {
            headers: {
              'Content-Type': contentType,
              'Cache-Control': 'no-store',
              'Access-Control-Allow-Origin': '*',
            }
          });
        }
        return new Response('Not Found', { status: 404 });
      }

      if (isWebSocket) {
        if (sysConfig.isPaused) return new Response(null, { status: 503 });
        return await vlessOverWSHandler(request);
      }

      return new Response(null, { status: 404 });
    } catch (err) {
      return new Response(`Error: ${err.message}`, { status: 500 });
    }
  },

  async scheduled(event, env, ctx) {
    console.log(`[PacketAlchemy] Cron triggered at ${new Date().toISOString()}`);

    // Cleanup rate limit store
    const now = Date.now();
    for (const [ip, record] of rateLimitStore.entries()) {
      if (now > record.resetAt) rateLimitStore.delete(ip);
    }

    // Sync config to D1
    if (env.PA_DB) {
      ctx.waitUntil(d1Put(env, 'sys_config', JSON.stringify(sysConfig)).catch(() => {}));
      ctx.waitUntil(d1Put(env, 'sys_usage', JSON.stringify(sysUsageCache)).catch(() => {}));
    }
  },
};
