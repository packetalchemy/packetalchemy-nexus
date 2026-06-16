/*
 * PacketAlchemy Nexus - Complete Edge Gateway
 * Cloudflare Worker | VLESS | Trojan | Shadowsocks | Fragment | Multi-User | Dashboard
 *
 * Where Packets Become Intelligence
 * Version: 3.0.0
 *
 * Features merged from:
 * - Nahan: Multi-user, Telegram bot, subscriber portal, panic mode, config sync
 * - B2B (BPB): VLESS WS, fragment configs, subscription gen, Sing-box/Xray configs
 * - Nova Proxy: Shadowsocks, SOCKS5/HTTP chain, gRPC, SNI fragment, WARP,
 *              DNS providers, health check, load balancing, QR codes,
 *              Loon/Surge/Quantumult formats, per-ISP clean-IP
 */

import { connect } from 'cloudflare:sockets';

const CURRENT_VERSION = '3.0.0';

const SYSTEM_DEFAULTS = {
  name: 'PacketAlchemy Nexus',
  apiRoute: 'nexus',
  masterKey: 'admin',
  maintenanceHost: 'https://www.ubuntu.com, https://www.docker.com',
  proxyIP: '',
  cleanIps: '',
  dohURL: 'https://cloudflare-dns.com/dns-query',
  resolveIp: '1.1.1.1',
  ports: '443',
  remoteDNS: 'https://cloudflare-dns.com/dns-query',
  localDNS: '1.1.1.1',
  fragmentMin: '100',
  fragmentMax: '200',
  intervalMin: '5',
  intervalMax: '10',
  blockAds: false,
  bypassLAN: false,
  blockPorn: false,
  users: [],
  isPaused: false,
  tgToken: '',
  tgChatId: '',
  tgAdminId: '',
  cfAccountId: '',
  cfApiToken: '',
  customPanelUrl: '',
  customRelay: '',
  limitTotalReq: 0,
  expiryMs: 0,
  linkedPanels: [],
  slaveNodes: '',
  allowSyncWorker: false,
  silentAlerts: false,
  tgBotLang: 'en',
  // Nova Proxy features
  socks5: '',
  httpProxy: '',
  httpsProxy: '',
  turnProxy: '',
  sstpProxy: '',
  warpEnabled: false,
  warpLicense: '',
  warpEndpoint: 'engage.cloudflareclient.com:2408',
  sniFragment: false,
  sniFragmentMin: '50',
  sniFragmentMax: '100',
  sniFragmentSleep: '10',
  dnsProvider: 'cloudflare',
  blockMalware: false,
  bestSub: false,
  maskUrl: 'https://www.nginx.com',
  debugLog: false,
};

const HTTP_PORTS = ['80', '8080', '2052', '2082', '2086', '2095', '8880'];
const HTTPS_PORTS = ['443', '8443', '2053', '2083', '2087', '2096'];

let sysConfig = { ...SYSTEM_DEFAULTS };
let sysUsageCache = { users: {} };
let lastSysUsageSync = 0;
let sysConfigCacheTime = 0;
let sysUsageCacheTime = 0;
let isolateStartTime = Date.now();
let activeConnections = 0;
let tgState = {};

const CACHE_TTL_CONFIG = 10000;
const CACHE_TTL_USAGE = 10000;
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
    } catch (e) { env.PA_DB_INITIALIZED = true; }
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
// Crypto & Hash Helpers
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
      else { let w15 = W[j - 15], w2 = W[j - 2]; let s0 = (w15 >>> 7 | w15 << 25) ^ (w15 >>> 18 | w15 << 14) ^ (w15 >>> 3); let s1 = (w2 >>> 17 | w2 << 15) ^ (w2 >>> 19 | w2 << 13) ^ (w2 >>> 10); W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0; }
      let S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7); let ch = (e & f) ^ (~e & g); let temp1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
      let S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10); let maj = (a & b) ^ (a & c) ^ (b & c); let temp2 = (S0 + maj) >>> 0;
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
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function generateJWTToken(secretKey, password) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ data: { password }, exp: Math.floor(Date.now() / 1000) + 7 * 86400 }));
  const sig = btoa(secretKey.slice(0, 32));
  return `Bearer ${header}.${payload}.${sig}`;
}

// ============================================================
// UUID / Base64 / URL Helpers
// ============================================================

const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) { return unsafeStringify(arr, offset); }

function isValidUUID(uuid) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid); }

function safeBtoa(str) {
  try { const bytes = new TextEncoder().encode(str); let binary = ''; for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]); return btoa(binary); }
  catch (e) { return btoa(str); }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try { base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/'); const decode = atob(base64Str); return { earlyData: Uint8Array.from(decode, c => c.charCodeAt(0)).buffer, error: null }; }
  catch (error) { return { earlyData: null, error }; }
}

function randomUpperCase(str) { return str.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c).join(''); }

function getRandomPath(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
  return result;
}

// ============================================================
// DNS Helpers
// ============================================================

async function resolveDNS(hostname) {
  const ipv4 = [], ipv6 = [];
  try {
    const [v4Res, v6Res] = await Promise.all([
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, { headers: { accept: 'application/dns-json' } }),
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=AAAA`, { headers: { accept: 'application/dns-json' } }),
    ]);
    const v4 = await v4Res.json(), v6 = await v6Res.json();
    if (v4.Answer) v4.Answer.forEach(a => { if (a.type === 1) ipv4.push(a.data); if (a.type === 28) ipv6.push(a.data); });
    if (v6.Answer) v6.Answer.forEach(a => { if (a.type === 1) ipv4.push(a.data); if (a.type === 28) ipv6.push(a.data); });
  } catch (e) {}
  return { ipv4, ipv6 };
}

// ============================================================
// DNS Provider Selection (Nova Proxy)
// ============================================================

const DNS_PROVIDERS = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/dns-query',
  quad9: 'https://dns.quad9.net/dns-query',
  adguard: 'https://dns.adguard.com/dns-query',
  mullvad: 'https://dns.mullvad.net/dns-query',
  controllD: 'https://api.controld.com/p2p',
};

function getDohURL(provider) {
  return DNS_PROVIDERS[provider] || DNS_PROVIDERS.cloudflare;
}

// ============================================================
// Shadowsocks Support (Nova Proxy)
// ============================================================

function getShadowsocksConfig(host, port) {
  const cipher = 'aes-128-gcm';
  const password = sysConfig.users?.[0]?.id?.replace(/-/g, '') || 'packetalchemy';
  const config = {
    server: host,
    server_port: parseInt(port),
    method: cipher,
    password: password,
    plugin: 'v2ray-plugin',
    plugin_opts: 'tls;host=' + host,
  };
  return config;
}

function getShadowsocksUri(host, port) {
  const cipher = 'aes-128-gcm';
  const password = sysConfig.users?.[0]?.id?.replace(/-/g, '') || 'packetalchemy';
  const userInfo = btoa(`${cipher}:${password}`);
  return `ss://${userInfo}@${host}:${port}?plugin=v2ray-plugin%3Btls%3Bhost%3D${host}#PacketAlchemy-SS-${port}`;
}

// ============================================================
// SOCKS5 Chain Proxy (Nova Proxy)
// ============================================================

async function connectViaSOCKS5(targetHost, targetPort, socks5Address) {
  if (!socks5Address) return connect({ hostname: targetHost, port: targetPort });
  const [socksHost, socksPort] = socks5Address.split(':');
  const socksSocket = connect({ hostname: socksHost, port: parseInt(socksPort) || 1080 });
  const writer = socksSocket.writable.getWriter();
  const reader = socksSocket.readable.getReader();
  const encoder = new TextEncoder();
  await writer.write(encoder.encode([0x05, 0x01, 0x00]));
  const authResponse = await reader.read();
  const connectCmd = new Uint8Array([0x05, 0x01, 0x00, 0x03]);
  const hostBytes = encoder.encode(targetHost);
  const portBytes = new Uint8Array(2);
  portBytes[0] = (targetPort >> 8) & 0xff;
  portBytes[1] = targetPort & 0xff;
  const connectPacket = new Uint8Array(connectCmd.length + 1 + hostBytes.length + 2);
  connectPacket.set(connectCmd);
  connectPacket[4] = hostBytes.length;
  connectPacket.set(hostBytes, 5);
  connectPacket.set(portBytes, 5 + hostBytes.length);
  await writer.write(connectPacket);
  await reader.read();
  writer.releaseLock();
  reader.releaseLock();
  return socksSocket;
}

// ============================================================
// Health Check (Nova Proxy)
// ============================================================

async function healthCheck(host, port) {
  const start = Date.now();
  try {
    const socket = connect({ hostname: host, port: parseInt(port) });
    const writer = socket.writable.getWriter();
    await writer.write(new Uint8Array(0));
    writer.releaseLock();
    await socket.closed;
    return { status: 'ok', latency: Date.now() - start };
  } catch (e) {
    return { status: 'error', latency: Date.now() - start, error: e.message };
  }
}

// ============================================================
// Load Balancer (Nova Proxy)
// ============================================================

async function loadBalance(hosts, port) {
  const results = await Promise.allSettled(hosts.map(host => healthCheck(host, port)));
  const healthy = results
    .map((r, i) => ({ host: hosts[i], ...(r.status === 'fulfilled' ? r.value : { status: 'error', latency: Infinity }) }))
    .filter(r => r.status === 'ok')
    .sort((a, b) => a.latency - b.latency);
  return healthy.length > 0 ? healthy[0].host : hosts[0];
}

// ============================================================
// QR Code Generator (Nova Proxy)
// ============================================================

function generateQRCodeSVG(text, size = 200) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(text)}`;
}

// ============================================================
// Subscription Format Builders (Nova Proxy)
// ============================================================

function buildLoonConfig(host, uuid) {
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  let config = '[Proxy]\n';
  ports.forEach((port, i) => {
    const isHTTPS = HTTPS_PORTS.includes(port);
    config += `PacketAlchemy-${port} = trojan, ${host}, ${port}, password=${trojanHash}${isHTTPS ? `, tls=true, sni=${host}, skip-cert-verify=true` : ''}, ws=true, ws-path=/${getRandomPath(16)}, ws-headers=Host:${host}\n`;
  });
  config += '\n[Remote Filter]\nPacketAlchemy = name, regex, PacketAlchemy\n';
  config += '\n[Rule]\nPacketAlchemy, DIRECT\n';
  return config;
}

function buildSurgeConfig(host, uuid) {
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  let config = '[General]\nloglevel = notify\nskip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local\n\n[Proxy]\n';
  ports.forEach(port => {
    const isHTTPS = HTTPS_PORTS.includes(port);
    config += `PacketAlchemy-${port} = trojan, ${host}, ${port}, password=${trojanHash}${isHTTPS ? `, tls=true, sni=${host}, skip-cert-verify=true` : ''}, ws=true, ws-path=/${getRandomPath(16)}\n`;
  });
  config += '\n[Rule]\nFINAL,PacketAlchemy,DIRECT\n';
  return config;
}

function buildQuantumultXConfig(host, uuid) {
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  let config = '[proxy]\n';
  ports.forEach(port => {
    const isHTTPS = HTTPS_PORTS.includes(port);
    config += `trojan=${host}, ${port}, password=${trojanHash}${isHTTPS ? `, over-tls=true, tls-hostname=${host}, skip-cert-verify=1` : ''}, obfs=ws, obfs-path=/${getRandomPath(16)}, obfs-header=Host:${host}\n`;
  });
  config += '\n[filter]\nFINAL, PacketAlchemy\n';
  return config;
}

// ============================================================
// Best Subscription Generator (Nova Proxy)
// ============================================================

function buildBestSub(host, uuid) {
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  let configs = [];
  ports.forEach(port => {
    const isHTTPS = HTTPS_PORTS.includes(port);
    const path = '/' + getRandomPath(16);
    configs.push(`trojan://${trojanHash}@${host}:${port}?type=ws&host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}${isHTTPS ? `&security=tls&sni=${host}&allowInsecure=1` : ''}#PacketAlchemy-${port}`);
  });
  return safeBtoa(configs.join('\n'));
}

// ============================================================
// Per-ISP Clean IP Optimizer (Nova Proxy)
// ============================================================

async function getCleanIPsForISP(host) {
  const resolved = await resolveDNS(host);
  const cleanIPs = [];
  if (sysConfig.cleanIps) {
    cleanIPs.push(...sysConfig.cleanIps.split(',').map(ip => ip.trim()).filter(Boolean));
  }
  if (resolved.ipv4.length > 0) cleanIPs.push(...resolved.ipv4);
  return [...new Set(cleanIPs)];
}

// ============================================================
// Usage Tracking (Nahan)
// ============================================================

function trackUsage(uuid, bytes, env, ctx) {
  if (!sysUsageCache) sysUsageCache = { users: {} };
  if (!sysUsageCache.users) sysUsageCache.users = {};
  const today = new Date().toISOString().split('T')[0];
  if (!sysUsageCache.users[uuid]) sysUsageCache.users[uuid] = { reqs: 0, dReqs: 0, lastDay: today };
  let u = sysUsageCache.users[uuid];
  if (u.lastDay !== today) { u.dReqs = 0; u.lastDay = today; }
  if (bytes === 0) { u.reqs += 1; u.dReqs += 1; }

  const now = Date.now();
  if (now - lastSysUsageSync > 30000) {
    lastSysUsageSync = now;
    if (env && env.PA_DB && sysConfig.users) {
      let changedConfig = false;
      sysConfig.users.forEach(user => {
        let uId = user.id.replace(/-/g, '').toLowerCase();
        let sysU = sysUsageCache.users[uId];
        if (!user.isPaused) {
          let reason = null;
          if (user.expiryMs && Date.now() > user.expiryMs) reason = `Expiration reached`;
          else if (sysU && user.limitTotalReq && sysU.reqs >= user.limitTotalReq) reason = `Traffic limit exceeded`;
          if (reason) { user.isPaused = true; user.disabledReason = reason; user.disabledAt = Date.now(); changedConfig = true; }
        }
      });
      if (changedConfig) ctx?.waitUntil(cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig)).catch(() => {}));
      ctx?.waitUntil(cachedD1Put(env, 'sys_usage', JSON.stringify(sysUsageCache)).catch(() => {}));
    }
  }
}

// ============================================================
// Telegram Bot (Nahan)
// ============================================================

async function sendTelegramMessage(text, env) {
  if (!sysConfig.tgToken || !(sysConfig.tgAdminId || sysConfig.tgChatId)) return;
  try {
    await fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: sysConfig.tgAdminId || sysConfig.tgChatId, text, parse_mode: 'HTML' })
    });
  } catch (e) {}
}

async function handleTelegramWebhook(request, env, hostName, ctx) {
  try {
    const update = await request.json();
    const tgApi = `https://api.telegram.org/bot${sysConfig.tgToken}`;
    const callerId = update.callback_query?.from?.id?.toString() || update.message?.from?.id?.toString();
    const adminId = sysConfig.tgAdminId || sysConfig.tgChatId;
    if (!adminId || callerId !== adminId.toString()) return new Response('OK', { status: 200 });

    const msg = update.message;
    if (msg && msg.text) {
      const text = msg.text.toLowerCase();
      if (text === '/start' || text === '/menu') {
        const isPaused = sysConfig.isPaused || false;
        const users = sysConfig.users || [];
        const activeCount = users.filter(u => !u.isPaused).length;
        const kb = {
          inline_keyboard: [
            [{ text: '👥 Users', callback_data: 'sys_users' }, { text: '📊 Stats', callback_data: 'sys_stats' }],
            [{ text: isPaused ? '▶️ Resume' : '⏸️ Pause', callback_data: 'sys_toggle' }],
            [{ text: '🔑 Dashboard', web_app: { url: `https://${hostName}/${sysConfig.apiRoute}/dash` } }],
          ]
        };
        await fetch(`${tgApi}/sendMessage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: callerId, text: `PacketAlchemy Nexus v${CURRENT_VERSION}\n\nStatus: ${isPaused ? 'Paused' : 'Active'}\nUsers: ${users.length} (${activeCount} active)\nStreams: ${activeConnections}`, reply_markup: kb })
        });
      } else if (text === '/status') {
        const upSec = Math.floor((Date.now() - isolateStartTime) / 1000);
        await fetch(`${tgApi}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: callerId, text: `Uptime: ${Math.floor(upSec/3600)}h ${Math.floor((upSec%3600)/60)}m\nConnections: ${activeConnections}\nVersion: ${CURRENT_VERSION}` }) });
      }
    }

    if (update.callback_query) {
      const cb = update.callback_query;
      const chatId = cb.message?.chat?.id;
      const data = cb.data;
      if (data === 'sys_toggle') {
        sysConfig.isPaused = !sysConfig.isPaused;
        if (env.PA_DB) await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
        await fetch(`${tgApi}/answerCallbackQuery`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ callback_query_id: cb.id, text: sysConfig.isPaused ? 'Paused' : 'Resumed' }) });
      } else if (data === 'sys_users') {
        const users = sysConfig.users || [];
        const text = users.length === 0 ? 'No users' : users.map((u, i) => `${i + 1}. ${u.name} (${u.isPaused ? 'Paused' : 'Active'})`).join('\n');
        await fetch(`${tgApi}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: chatId, text: `Users:\n${text}` }) });
      } else if (data === 'sys_stats') {
        const users = sysConfig.users || [];
        let totalReqs = 0;
        users.forEach(u => { const id = u.id.replace(/-/g, '').toLowerCase(); const sysU = sysUsageCache?.users?.[id]; if (sysU) totalReqs += sysU.reqs || 0; });
        await fetch(`${tgApi}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: chatId, text: `Users: ${users.length}\nTotal Reqs: ${totalReqs}\nStreams: ${activeConnections}` }) });
      }
    }

    return new Response('OK', { status: 200 });
  } catch (e) { return new Response('OK', { status: 200 }); }
}

// ============================================================
// VLESS Header Processing (B2B)
// ============================================================

function processVlessHeader(vlessBuffer) {
  if (vlessBuffer.byteLength < 24) return { hasError: true, message: 'invalid data' };
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);
  const uuids = sysConfig.users?.map(u => u.id) || [];
  if (uuids.length === 0) return { hasError: true, message: 'no users configured' };
  const isValidUser = uuids.some(uId => slicedBufferString === uId) || uuids.some(uId => slicedBufferString === uId.replace(/-/g, '').toLowerCase());
  if (!isValidUser) return { hasError: true, message: 'invalid user' };

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 19 + optLength))[0];
  const isUDP = command === 2;
  if (command !== 1 && command !== 2) return { hasError: true, message: `command ${command} not supported` };

  const portIndex = 19 + optLength;
  const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];
  let addressLength = 0, addressValueIndex = addressIndex + 1, addressValue = '';

  switch (addressType) {
    case 1: addressLength = 4; addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 4)).join('.'); break;
    case 2: addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
    case 3: addressLength = 16; const dv = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + 16)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16)); addressValue = ipv6.join(':'); break;
    default: return { hasError: true, message: `invalid addressType ${addressType}` };
  }
  if (!addressValue) return { hasError: true, message: 'empty address' };
  return { hasError: false, addressRemote: addressValue, addressType, portRemote, rawDataIndex: addressValueIndex + addressLength, vlessVersion: version, isUDP };
}

// ============================================================
// WebSocket Stream Helpers (B2B)
// ============================================================

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => { if (!readableStreamCancel) controller.enqueue(event.data); });
      webSocketServer.addEventListener('close', () => { safeCloseWebSocket(webSocketServer); controller.close(); });
      webSocketServer.addEventListener('error', (err) => { log('ws error'); controller.error(err); });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel(reason) { log(`canceled: ${reason}`); readableStreamCancel = true; safeCloseWebSocket(webSocketServer); }
  });
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
    tcpSocket.closed.catch(error => console.log('retry closed', error)).finally(() => safeCloseWebSocket(webSocket));
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
  let vlessHeader = vlessResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      hasIncomingData = true;
      if (webSocket.readyState !== WS_READY_STATE_OPEN) throw new Error('ws not open');
      if (vlessHeader) { webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer()); vlessHeader = null; }
      else webSocket.send(chunk);
    },
    close() { log(`remote close, data=${hasIncomingData}`); },
    abort(reason) { console.error('remote abort', reason); },
  })).catch(error => { console.error('pipe error', error); safeCloseWebSocket(webSocket); });
  if (hasIncomingData === false && retry) { log('retry'); retry(); }
}

async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index += 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    }
  });
  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch(sysConfig.dohURL || 'https://cloudflare-dns.com/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: chunk });
      const dnsResult = await resp.arrayBuffer();
      const udpSize = dnsResult.byteLength;
      const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
      if (webSocket.readyState === WS_READY_STATE_OPEN) {
        if (isVlessHeaderSent) webSocket.send(await new Blob([udpSizeBuffer, dnsResult]).arrayBuffer());
        else { webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsResult]).arrayBuffer()); isVlessHeaderSent = true; }
      }
    }
  })).catch(error => log('dns udp error: ' + error));
  const writer = transformStream.writable.getWriter();
  return { write(chunk) { writer.write(chunk); } };
}

function safeCloseWebSocket(socket) {
  try { if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close(); }
  catch (error) { console.error('safeClose error', error); }
}

// ============================================================
// VLESS WebSocket Handler (B2B)
// ============================================================

async function vlessOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  activeConnections++;

  let address = '', portWithRandomLog = '';
  const log = (info, event) => console.log(`[PA ${address}:${portWithRandomLog}] ${info}`, event || '');
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = { value: null };
  let udpStreamWrite = null, isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
      if (remoteSocketWapper.value) { const writer = remoteSocketWapper.value.writable.getWriter(); await writer.write(chunk); writer.releaseLock(); return; }
      const { hasError, message, portRemote = 443, addressRemote = '', rawDataIndex, vlessVersion = new Uint8Array([0, 0]), isUDP } = processVlessHeader(chunk);
      address = addressRemote; portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'}`;
      if (hasError) throw new Error(message);
      if (isUDP && portRemote !== 53) throw new Error('UDP only for DNS');
      if (isUDP && portRemote === 53) isDns = true;
      const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);
      if (isDns) { const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log); udpStreamWrite = write; udpStreamWrite(rawClientData); return; }
      handleTCPOutBound(request, remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
    },
    close() { activeConnections = Math.max(0, activeConnections - 1); log('ws stream closed'); },
    abort(reason) { activeConnections = Math.max(0, activeConnections - 1); log('ws abort', JSON.stringify(reason)); },
  })).catch(err => log('pipe error', err));

  return new Response(null, { status: 101, webSocket: client });
}

// ============================================================
// Subscription Builders (Nahan/B2B)
// ============================================================

function getTargetUser(reqPath, url) {
  const hasMultiUser = sysConfig.users && sysConfig.users.length > 0;
  let targetUser = null;
  if (hasMultiUser) {
    const targetSub = url.searchParams.get('sub');
    if (targetSub) targetUser = sysConfig.users.find(u => u.name.toLowerCase() === targetSub.toLowerCase() || u.id === targetSub);
  } else {
    targetUser = { id: sysConfig.users?.[0]?.id || sysConfig.masterKey, name: 'Default' };
  }
  return { targetUser, hasMultiUser };
}

function getSubUserInfo(targetUser) {
  if (!targetUser) return '';
  const idClean = targetUser.id.replace(/-/g, '').toLowerCase();
  const sysU = sysUsageCache?.users?.[idClean] || { reqs: 0, dReqs: 0 };
  const usedBytes = Math.floor((sysU.reqs || 0) * (1073741824 / 6000));
  const limitBytes = targetUser.limitTotalReq ? Math.floor(targetUser.limitTotalReq * (1073741824 / 6000)) : 0;
  const expireSec = targetUser.expiryMs ? Math.floor(targetUser.expiryMs / 1000) : 0;
  return `upload=0; download=${usedBytes}; total=${limitBytes}; expire=${expireSec}`;
}

function buildUriProfile(host, targetSub) {
  const { targetUser } = getTargetUser('', { searchParams: targetSub ? new URLSearchParams(`sub=${targetSub}`) : new URLSearchParams() });
  const uuid = targetUser?.id || sysConfig.users?.[0]?.id;
  if (!uuid) return '';
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  let uris = '';
  ports.forEach(port => {
    const isHTTPS = HTTPS_PORTS.includes(port);
    uris += `trojan://${trojanHash}@${host}:${port}?type=ws&host=${encodeURIComponent(host)}&path=${encodeURIComponent('/' + getRandomPath(16))}${isHTTPS ? `&security=tls&sni=${host}&allowInsecure=1` : ''}#${encodeURIComponent('PacketAlchemy-' + port)}\n`;
  });
  return uris;
}

function buildClashYamlProfile(host, targetSub) {
  const { targetUser } = getTargetUser('', { searchParams: targetSub ? new URLSearchParams(`sub=${targetSub}`) : new URLSearchParams() });
  const uuid = targetUser?.id || sysConfig.users?.[0]?.id;
  if (!uuid) return '';
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  let yaml = 'mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\n\nproxies:\n';
  ports.forEach(port => {
    const isHTTPS = HTTPS_PORTS.includes(port);
    yaml += `  - name: "PacketAlchemy-${port}"\n    type: trojan\n    server: ${host}\n    port: ${port}\n    password: ${trojanHash}\n`;
    if (isHTTPS) yaml += `    sni: ${host}\n    skip-cert-verify: true\n`;
    yaml += `    network: ws\n    ws-opts:\n      path: /${getRandomPath(16)}\n      headers:\n        Host: ${host}\n\n`;
  });
  yaml += 'proxy-groups:\n  - name: "PacketAlchemy"\n    type: select\n    proxies:\n';
  ports.forEach(port => yaml += `      - "PacketAlchemy-${port}"\n`);
  yaml += '\nrules:\n  - MATCH,PacketAlchemy\n';
  return yaml;
}

function buildSingboxConfig(host, targetSub) {
  const { targetUser } = getTargetUser('', { searchParams: targetSub ? new URLSearchParams(`sub=${targetSub}`) : new URLSearchParams() });
  const uuid = targetUser?.id || sysConfig.users?.[0]?.id;
  if (!uuid) return {};
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  const config = {
    dns: { servers: [{ tag: 'dns-remote', address: sysConfig.remoteDNS || 'https://cloudflare-dns.com/dns-query', detour: 'PacketAlchemy' }, { tag: 'dns-direct', address: 'rcode://success', detour: 'direct' }], rules: [{ domain_suffix: ['.ir'], server: 'dns-direct' }] },
    inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 7890 }],
    outbounds: [{ tag: 'PacketAlchemy', type: 'selector', outbounds: [] }, { tag: 'direct', type: 'direct' }, { tag: 'block', type: 'block' }],
    route: { rules: [{ protocol: 'dns', outbound: 'dns-out' }, { ip_is_private: true, outbound: 'direct' }], final: 'PacketAlchemy' }
  };
  ports.forEach(port => {
    const tag = `PacketAlchemy-${port}`;
    config.outbounds.splice(config.outbounds.length - 3, 0, { type: 'trojan', tag, server: host, server_port: parseInt(port), password: trojanHash, tls: { enabled: HTTPS_PORTS.includes(port), server_name: host, insecure: true }, transport: { type: 'ws', path: `/${getRandomPath(16)}`, headers: { Host: host } } });
    config.outbounds[0].outbounds.push(tag);
  });
  return config;
}

// ============================================================
// Fragment Config Builder (B2B)
// ============================================================

function buildFragmentXrayConfig(host, uuid) {
  const trojanHash = getTrojanHash(uuid);
  const ports = (sysConfig.ports || '443').split(',').map(p => p.trim());
  const configs = [];

  ports.forEach(port => {
    const isHTTPS = HTTPS_PORTS.includes(port);
    configs.push({
      address: `PacketAlchemy-Frag-${port}`,
      config: {
        log: { loglevel: 'warning' },
        dns: { servers: [sysConfig.remoteDNS || 'https://cloudflare-dns.com/dns-query', { address: sysConfig.localDNS || '1.1.1.1', domains: ['geosite:category-ir', 'domain:.ir'], expectIPs: ['geoip:ir'], port: 53 }] },
        routing: { domainStrategy: 'AsIs', rules: [{ inboundTag: ['dns-in'], outboundTag: 'dns-out', type: 'field' }, { ip: [sysConfig.localDNS || '1.1.1.1'], outboundTag: 'direct', port: '53', type: 'field' }, ...(sysConfig.bypassLAN ? [{ ip: ['geoip:private'], outboundTag: 'direct', type: 'field' }] : []), { outboundTag: 'proxy', type: 'field', network: 'tcp,udp' }] },
        inbounds: [{ port: 10809, protocol: 'socks', settings: { udp: true }, tag: 'dns-in' }, { port: 10808, protocol: 'http' }],
        outbounds: [{ protocol: 'freedom', settings: { fragment: { packets: 'tlshello', length: `${sysConfig.fragmentMin || '100'}-${sysConfig.fragmentMax || '200'}`, interval: `${sysConfig.intervalMin || '5'}-${sysConfig.intervalMax || '10'}` } }, tag: 'proxy' }, { protocol: 'blackhole', tag: 'block' }, { protocol: 'freedom', tag: 'direct', settings: { domainStrategy: 'UseIP' } }],
        remarks: `PacketAlchemy - Frag ${port} ${isHTTPS ? '(TLS)' : '(HTTP)'}`,
      }
    });
  });

  configs.push({
    address: 'PacketAlchemy - Best Fragment',
    config: {
      log: { loglevel: 'warning' },
      dns: { servers: [sysConfig.remoteDNS || 'https://cloudflare-dns.com/dns-query'] },
      routing: { domainStrategy: 'AsIs', rules: [{ balancerTag: 'all', type: 'field', network: 'tcp,udp' }] },
      inbounds: [{ port: 10809, protocol: 'socks', settings: { udp: true }, tag: 'dns-in' }, { port: 10808, protocol: 'http' }],
      outbounds: [{ protocol: 'freedom', tag: 'proxy' }, { protocol: 'blackhole', tag: 'block' }, { protocol: 'freedom', tag: 'direct' }],
      balancers: [{ tag: 'all', selector: ['out'] }],
      observatory: { probeInterval: '3m', subjectSelector: ['out'] },
      remarks: 'PacketAlchemy - Best Fragment',
    }
  });

  return configs;
}

// ============================================================
// Subscriber Portal Page (Nahan)
// ============================================================

function serveSubscriberPortal(host, targetUser, url) {
  if (!targetUser) return serveMaintenancePage(null, url);
  const idClean = targetUser.id.replace(/-/g, '').toLowerCase();
  const sysU = sysUsageCache?.users?.[idClean] || { reqs: 0, dReqs: 0, lastDay: '' };
  const todayDate = new Date().toISOString().split('T')[0];
  const totalReqs = sysU.reqs || 0;
  const dailyReqs = sysU.lastDay === todayDate ? (sysU.dReqs || 0) : 0;
  const totalGb = (totalReqs / 6000).toFixed(2);
  const limitTotalGb = targetUser.limitTotalReq ? (targetUser.limitTotalReq / 6000).toFixed(2) : 'Unlimited';
  const dailyGb = (dailyReqs / 6000).toFixed(2);
  const limitDailyGb = targetUser.limitDailyReq ? (targetUser.limitDailyReq / 6000).toFixed(2) : 'Unlimited';
  const totalPercent = targetUser.limitTotalReq ? Math.min(100, (totalReqs / targetUser.limitTotalReq) * 100).toFixed(1) : 0;

  let expiryDateTxt = 'Never';
  let isExpired = false;
  if (targetUser.expiryMs) {
    expiryDateTxt = new Date(targetUser.expiryMs).toLocaleDateString();
    if (Date.now() > targetUser.expiryMs) isExpired = true;
  }

  let statusText = 'Active';
  let statusColor = '#4ade80';
  if (targetUser.isPaused) { statusText = 'Paused'; statusColor = '#fbbf24'; }
  else if (isExpired) { statusText = 'Expired'; statusColor = '#ef4444'; }
  else if (targetUser.limitTotalReq && totalReqs >= targetUser.limitTotalReq) { statusText = 'Limit Exceeded'; statusColor = '#f87171'; }

  const subUrl = `http://${host}/${sysConfig.apiRoute}?sub=${encodeURIComponent(targetUser.name)}`;
  const subUrlClash = `http://${host}/${sysConfig.apiRoute}?sub=${encodeURIComponent(targetUser.name)}&flag=clash`;
  const subUrlSingbox = `http://${host}/${sysConfig.apiRoute}?sub=${encodeURIComponent(targetUser.name)}&flag=singbox`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${targetUser.name} - PacketAlchemy</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>body{background:linear-gradient(135deg,#0a0a0a,#1a1a2e,#0a0a0a);color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}</style>
</head>
<body class="min-h-screen py-10 px-4 flex flex-col items-center justify-center">
  <div class="w-full max-w-2xl rounded-3xl p-6 md:p-8 space-y-6" style="background:rgba(15,20,40,0.8);border:1px solid rgba(0,212,255,0.25);box-shadow:0 10px 40px rgba(0,0,0,0.4);">
    <div class="flex items-center justify-between pb-4 border-b border-white/10">
      <div><h1 class="text-2xl font-bold text-white">${targetUser.name}</h1><p class="text-xs text-gray-400 font-mono">${targetUser.id}</p></div>
      <span class="px-4 py-2 rounded-xl text-xs font-bold" style="background:${statusColor}20;color:${statusColor};border:1px solid ${statusColor}40;">${statusText}</span>
    </div>
    <div class="grid grid-cols-3 gap-4">
      <div class="bg-black/30 rounded-2xl p-4"><p class="text-xs text-gray-400">Total Usage</p><p class="text-xl font-bold text-white mt-1">${totalGb}<span class="text-xs text-gray-400"> / ${limitTotalGb} GB</span></p>${targetUser.limitTotalReq ? `<div class="w-full bg-gray-800 rounded-full h-1.5 mt-2"><div class="h-1.5 rounded-full" style="width:${totalPercent}%;background:${statusColor}"></div></div>` : ''}</div>
      <div class="bg-black/30 rounded-2xl p-4"><p class="text-xs text-gray-400">Daily Usage</p><p class="text-xl font-bold text-white mt-1">${dailyGb}<span class="text-xs text-gray-400"> / ${limitDailyGb} GB</span></p></div>
      <div class="bg-black/30 rounded-2xl p-4"><p class="text-xs text-gray-400">Expiration</p><p class="text-lg font-bold text-white mt-1">${expiryDateTxt}</p></div>
    </div>
    <div><h2 class="text-lg font-bold mb-3">Subscription Links</h2>
      <div class="space-y-3">
        <div class="bg-black/30 p-4 rounded-xl"><p class="text-xs text-cyan-400 font-bold mb-2">Auto-Detect (Universal)</p><div class="flex"><input type="text" readonly value="${subUrl}" class="flex-1 bg-black/50 border border-white/10 px-3 py-2 rounded-l-lg text-xs font-mono text-gray-400 truncate"><button onclick="navigator.clipboard.writeText('${subUrl}');this.textContent='Copied!'" class="px-4 bg-cyan-600 hover:bg-cyan-700 text-white rounded-r-lg text-xs font-bold">Copy</button></div></div>
        <div class="bg-black/30 p-4 rounded-xl"><p class="text-xs text-green-400 font-bold mb-2">Clash / Meta</p><div class="flex"><input type="text" readonly value="${subUrlClash}" class="flex-1 bg-black/50 border border-white/10 px-3 py-2 rounded-l-lg text-xs font-mono text-gray-400 truncate"><button onclick="navigator.clipboard.writeText('${subUrlClash}');this.textContent='Copied!'" class="px-4 bg-green-600 hover:bg-green-700 text-white rounded-r-lg text-xs font-bold">Copy</button></div></div>
        <div class="bg-black/30 p-4 rounded-xl"><p class="text-xs text-purple-400 font-bold mb-2">Sing-box</p><div class="flex"><input type="text" readonly value="${subUrlSingbox}" class="flex-1 bg-black/50 border border-white/10 px-3 py-2 rounded-l-lg text-xs font-mono text-gray-400 truncate"><button onclick="navigator.clipboard.writeText('${subUrlSingbox}');this.textContent='Copied!'" class="px-4 bg-purple-600 hover:bg-purple-700 text-white rounded-r-lg text-xs font-bold">Copy</button></div></div>
      </div>
    </div>
    <p class="text-center text-xs text-gray-500">PacketAlchemy Nexus v${CURRENT_VERSION}</p>
  </div>
</body>
</html>`;
}

// ============================================================
// Maintenance Page (Nahan)
// ============================================================

function serveMaintenancePage(request, url) {
  const fakeList = sysConfig.maintenanceHost ? sysConfig.maintenanceHost.split(',').map(s => s.trim()).filter(s => s) : ['https://www.ubuntu.com'];
  const clientIP = request?.headers?.get('cf-connecting-ip') || '0.0.0.0';
  const ipHash = Array.from(clientIP).reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const targetStr = fakeList[ipHash % fakeList.length].startsWith('http') ? fakeList[ipHash % fakeList.length] : `https://${fakeList[ipHash % fakeList.length]}`;
  try {
    const targetUrl = new URL(targetStr);
    if (url.pathname !== '/') targetUrl.pathname = url.pathname;
    targetUrl.search = url.search;
    const cleanHeaders = new Headers(request?.headers || {});
    cleanHeaders.set('Host', targetUrl.hostname);
    cleanHeaders.delete('cf-connecting-ip');
    cleanHeaders.delete('x-forwarded-for');
    const fetchInit = { method: request?.method || 'GET', headers: cleanHeaders, redirect: 'follow' };
    if (request?.method !== 'GET' && request?.method !== 'HEAD') fetchInit.body = request.body;
    return fetch(new Request(targetUrl.toString(), fetchInit));
  } catch (e) { return new Response('Not Found', { status: 404 }); }
}

// ============================================================
// Dashboard Page (Nahan/B2B)
// ============================================================

function serveDashboardPage(env) {
  const users = sysConfig.users || [];
  const activeCount = users.filter(u => !u.isPaused).length;
  const pausedCount = users.filter(u => u.isPaused).length;
  let totalReqs = 0;
  users.forEach(u => { const id = u.id.replace(/-/g, '').toLowerCase(); const sysU = sysUsageCache?.users?.[id]; if (sysU) totalReqs += sysU.reqs || 0; });

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PacketAlchemy Nexus - Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>body{background:#0a0a0a;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}</style>
</head>
<body class="min-h-screen p-6 md:p-10">
  <div class="max-w-5xl mx-auto">
    <h1 class="text-3xl font-bold text-white mb-1">PacketAlchemy Nexus</h1>
    <p class="text-gray-400 mb-8">Edge Engineering Platform Dashboard</p>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4"><p class="text-xs text-gray-400 uppercase">Version</p><p class="text-2xl font-bold text-white mt-1">${CURRENT_VERSION}</p></div>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4"><p class="text-xs text-gray-400 uppercase">Users</p><p class="text-2xl font-bold text-white mt-1">${users.length}</p><p class="text-xs text-gray-500">${activeCount} active, ${pausedCount} paused</p></div>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4"><p class="text-xs text-gray-400 uppercase">Total Reqs</p><p class="text-2xl font-bold text-white mt-1">${totalReqs.toLocaleString()}</p></div>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4"><p class="text-xs text-gray-400 uppercase">Connections</p><p class="text-2xl font-bold text-white mt-1">${activeConnections}</p></div>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 class="text-lg font-bold text-white mb-4">Protocols</h2>
        <div class="space-y-2 text-sm">
          <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">VLESS</span><span class="text-green-400">WebSocket</span></div>
          <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">Trojan</span><span class="text-green-400">WebSocket</span></div>
          <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">Shadowsocks</span><span class="text-green-400">AES-128-GCM</span></div>
          <div class="flex justify-between"><span class="text-gray-400">Transport</span><span class="text-cyan-400">WS / gRPC / HTTP</span></div>
        </div>
      </div>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 class="text-lg font-bold text-white mb-4">Features</h2>
        <div class="space-y-2 text-sm">
          <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">Fragment</span><span class="text-green-400">${sysConfig.fragmentMin}-${sysConfig.fragmentMax}</span></div>
          <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">SNI Fragment</span><span class="${sysConfig.sniFragment ? 'text-green-400' : 'text-gray-500'}">${sysConfig.sniFragment ? 'Enabled' : 'Disabled'}</span></div>
          <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">AdBlock</span><span class="${sysConfig.blockAds ? 'text-green-400' : 'text-gray-500'}">${sysConfig.blockAds ? 'On' : 'Off'}</span></div>
          <div class="flex justify-between"><span class="text-gray-400">WARP</span><span class="${sysConfig.warpEnabled ? 'text-green-400' : 'text-gray-500'}">${sysConfig.warpEnabled ? 'Enabled' : 'Disabled'}</span></div>
        </div>
      </div>
    </div>
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
      <h2 class="text-lg font-bold text-white mb-4">Subscription Formats</h2>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
        <a href="/${sysConfig.apiRoute}?flag=raw" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-cyan-400 font-bold">Base64</span><p class="text-gray-500 text-xs mt-1">Universal</p></a>
        <a href="/${sysConfig.apiRoute}?flag=clash" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-green-400 font-bold">Clash</span><p class="text-gray-500 text-xs mt-1">Meta / Mihomo</p></a>
        <a href="/${sysConfig.apiRoute}?flag=singbox" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-purple-400 font-bold">Sing-box</span><p class="text-gray-500 text-xs mt-1">Hiddify</p></a>
        <a href="/${sysConfig.apiRoute}?flag=loon" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-yellow-400 font-bold">Loon</span><p class="text-gray-500 text-xs mt-1">iOS</p></a>
        <a href="/${sysConfig.apiRoute}?flag=surge" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-blue-400 font-bold">Surge</span><p class="text-gray-500 text-xs mt-1">macOS/iOS</p></a>
        <a href="/${sysConfig.apiRoute}?flag=qx" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-orange-400 font-bold">Quantumult</span><p class="text-gray-500 text-xs mt-1">QX</p></a>
        <a href="/${sysConfig.apiRoute}?flag=ss" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-red-400 font-bold">Shadowsocks</span><p class="text-gray-500 text-xs mt-1">SS URI</p></a>
        <a href="/${sysConfig.apiRoute}?flag=frag" class="block p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-center"><span class="text-pink-400 font-bold">Fragment</span><p class="text-gray-500 text-xs mt-1">Xray Config</p></a>
      </div>
    </div>
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
      <h2 class="text-lg font-bold text-white mb-4">API Endpoints</h2>
      <div class="space-y-2 text-sm">
        <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">POST</span><span class="text-cyan-400">/${sysConfig.apiRoute}/api/auth</span><span class="text-gray-500">JWT auth</span></div>
        <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">POST</span><span class="text-cyan-400">/${sysConfig.apiRoute}/api/sync</span><span class="text-gray-500">Config sync</span></div>
        <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">GET/POST</span><span class="text-cyan-400">/${sysConfig.apiRoute}/api/users</span><span class="text-gray-500">User CRUD</span></div>
        <div class="flex justify-between border-b border-gray-800 pb-2"><span class="text-gray-400">GET</span><span class="text-cyan-400">/${sysConfig.apiRoute}/api/stats</span><span class="text-gray-500">Statistics</span></div>
        <div class="flex justify-between"><span class="text-gray-400">POST</span><span class="text-cyan-400">/${sysConfig.apiRoute}/tg</span><span class="text-gray-500">Telegram webhook</span></div>
      </div>
    </div>
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h2 class="text-lg font-bold text-white mb-4">Users (${users.length})</h2>
      ${users.length === 0 ? '<p class="text-gray-500">No users yet. Create one via API.</p>' :
      `<div class="overflow-x-auto"><table class="w-full text-sm"><thead><tr class="text-left text-gray-400 border-b border-gray-800"><th class="pb-2">Name</th><th class="pb-2">ID</th><th class="pb-2">Status</th><th class="pb-2">Expiry</th><th class="pb-2">Subscription</th></tr></thead><tbody>${users.map(u => `<tr class="border-b border-gray-800/50"><td class="py-2 text-white">${u.name}</td><td class="py-2 text-gray-400 font-mono text-xs">${u.id.substring(0, 8)}...</td><td class="py-2"><span class="px-2 py-0.5 rounded text-xs ${u.isPaused ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'}">${u.isPaused ? 'Paused' : 'Active'}</span></td><td class="py-2 text-gray-400 text-xs">${u.expiryMs ? new Date(u.expiryMs).toLocaleDateString() : 'Never'}</td><td class="py-2"><a href="/${sysConfig.apiRoute}?sub=${encodeURIComponent(u.name)}" class="text-cyan-400 text-xs hover:underline">Link</a></td></tr>`).join('')}</tbody></table></div>`}
    </div>
  </div>
</body>
</html>`;
}

// ============================================================
// Landing Page
// ============================================================

function serveLandingPage(url) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PacketAlchemy Nexus</title>
  <style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}.container{text-align:center;max-width:600px;padding:2rem}h1{font-size:2.5rem;margin-bottom:.5rem;color:#fff}.tagline{color:#00d4ff;font-size:1.2rem;margin-bottom:2rem}.endpoints{text-align:left;background:#1a1a1a;padding:1.5rem;border-radius:8px}.endpoint{padding:.5rem 0;border-bottom:1px solid #333}.endpoint:last-child{border-bottom:none}.endpoint a{color:#00d4ff;text-decoration:none}.method{color:#4ade80;font-family:monospace;display:inline-block;width:50px}footer{margin-top:2rem;color:#666;font-size:.9rem}.section{color:#8b5cf6;font-weight:bold;margin-top:1rem;font-size:.9rem}</style>
</head>
<body>
  <div class="container">
    <h1>PacketAlchemy Nexus</h1>
    <p class="tagline">Where Packets Become Intelligence</p>
    <div class="endpoints">
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}/dash">Dashboard</a></div>
      <p class="section">Subscription Formats</p>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=raw">Raw (base64)</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=clash">Clash / Meta</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=singbox">Sing-box</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=loon">Loon</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=surge">Surge</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=qx">Quantumult X</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=ss">Shadowsocks</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=frag">Fragment (Xray)</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}?flag=best">Best Config</a></div>
      <p class="section">API</p>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}/api/stats?key=${sysConfig.masterKey}">System Stats</a></div>
      <div class="endpoint"><span class="method">GET</span> <a href="/${sysConfig.apiRoute}/api/users?key=${sysConfig.masterKey}">Users API</a></div>
    </div>
    <footer>PacketAlchemy Edge Engineering Platform v${CURRENT_VERSION}</footer>
  </div>
</body>
</html>`;
}

// ============================================================
// API Handlers (Nahan/B2B)
// ============================================================

async function handleAuth(request, hostname, ctx, env) {
  try {
    const data = await request.json();
    if (data.key !== sysConfig.masterKey) return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    ctx?.waitUntil(sendTelegramMessage(`Panel login from ${request.headers.get('cf-connecting-ip') || 'unknown'}`, env));
    const netInfo = { ip: request.headers.get('cf-connecting-ip'), colo: request.cf?.colo, loc: (request.cf?.city || 'Unknown') + ', ' + (request.cf?.country || 'Unknown') };
    return new Response(JSON.stringify({ success: true, config: sysConfig, network: netInfo, version: CURRENT_VERSION, uptime: Math.floor((Date.now() - isolateStartTime) / 1000) }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  } catch (e) { return new Response(JSON.stringify({ success: false }), { status: 400 }); }
}

async function handleConfigSync(request, env, ctx) {
  try {
    const data = await request.json();
    if (data.key !== sysConfig.masterKey) return new Response(JSON.stringify({ success: false }), { status: 401 });
    if (data.config) {
      sysConfig = { ...sysConfig, ...data.config };
      await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
    }
    if (data.resetUUID) {
      const uuidClean = data.resetUUID.replace(/-/g, '').toLowerCase();
      if (sysUsageCache.users[uuidClean]) { sysUsageCache.users[uuidClean].reqs = 0; sysUsageCache.users[uuidClean].dReqs = 0; }
      await cachedD1Put(env, 'sys_usage', JSON.stringify(sysUsageCache));
    }
    if (sysConfig.slaveNodes && sysConfig.slaveNodes.trim() && data.config && !data.fromMaster) {
      const nodes = sysConfig.slaveNodes.split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean);
      const currentHost = new URL(request.url).hostname;
      nodes.forEach(node => {
        if (node !== currentHost) {
          ctx?.waitUntil(fetch(`https://${node}/${sysConfig.apiRoute}/api/sync`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: sysConfig.masterKey, config: sysConfig, fromMaster: true }) }).catch(() => {}));
        }
      });
    }
    if (sysConfig.tgToken && ctx) {
      const hookUrl = `https://${new URL(request.url).hostname}/${sysConfig.apiRoute}/tg`;
      ctx.waitUntil(fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/setWebhook`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: hookUrl }) }).catch(() => {}));
    }
    return new Response(JSON.stringify({ success: true, config: sysConfig }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  } catch (e) { return new Response(JSON.stringify({ success: false }), { status: 400 }); }
}

async function handleUsersApi(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const method = request.method;
    const userId = url.searchParams.get('id');
    const authHeader = request.headers.get('Authorization') || '';
    const authKey = authHeader.replace('Bearer ', '') || url.searchParams.get('key') || '';
    let bodyKey = '';
    if (method === 'POST' || method === 'PUT' || method === 'DELETE') { try { const body = await request.clone().json(); bodyKey = body.key || ''; } catch (e) {} }
    if (authKey !== sysConfig.masterKey && bodyKey !== sysConfig.masterKey) return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });

    if (method === 'GET' && !userId) {
      const users = (sysConfig.users || []).map(u => {
        const idClean = u.id.replace(/-/g, '').toLowerCase();
        const sysU = sysUsageCache?.users?.[idClean] || { reqs: 0, dReqs: 0 };
        const usedBytes = Math.floor((sysU.reqs || 0) * (1073741824 / 6000));
        const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824 / 6000)) : 0;
        const isExpired = u.expiryMs && Date.now() > u.expiryMs;
        let status = 'active';
        if (u.isPaused && u.disabledReason) status = 'auto-disabled';
        else if (u.isPaused) status = 'paused';
        else if (isExpired) status = 'expired';
        return { ...u, usage: { total: usedBytes, limit: limitBytes }, status, subscriptionUrl: `http://${url.hostname}/${sysConfig.apiRoute}?sub=${encodeURIComponent(u.name)}` };
      });
      return new Response(JSON.stringify({ success: true, users, total: users.length }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'GET' && userId) {
      const u = (sysConfig.users || []).find(usr => usr.id === userId || usr.name.toLowerCase() === userId.toLowerCase());
      if (!u) return new Response(JSON.stringify({ success: false, error: 'User not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      const idClean = u.id.replace(/-/g, '').toLowerCase();
      const sysU = sysUsageCache?.users?.[idClean] || { reqs: 0, dReqs: 0 };
      const usedBytes = Math.floor((sysU.reqs || 0) * (1073741824 / 6000));
      const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824 / 6000)) : 0;
      return new Response(JSON.stringify({ success: true, user: { ...u, usage: { total: usedBytes, limit: limitBytes }, subscriptionUrl: `http://${url.hostname}/${sysConfig.apiRoute}?sub=${encodeURIComponent(u.name)}` } }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'POST' && !userId) {
      const body = await request.json();
      const { name, trafficLimit, expiryDays, dailyLimit, notes } = body;
      if (!name) return new Response(JSON.stringify({ success: false, error: 'Name required' }), { status: 400 });
      const newUser = {
        id: crypto.randomUUID(), name,
        limitTotalReq: trafficLimit ? Math.floor(parseFloat(trafficLimit) * 6000) : null,
        limitDailyReq: dailyLimit ? Math.floor(parseFloat(dailyLimit) * 6000) : null,
        expiryMs: expiryDays ? Date.now() + parseInt(expiryDays) * 86400000 : null,
        notes: notes || '', isPaused: false, createdAt: Date.now()
      };
      if (!sysConfig.users) sysConfig.users = [];
      sysConfig.users.push(newUser);
      await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
      ctx?.waitUntil(sendTelegramMessage(`New user: ${name} (${newUser.id})`, env));
      return new Response(JSON.stringify({ success: true, user: newUser, subscriptionUrl: `http://${url.hostname}/${sysConfig.apiRoute}?sub=${encodeURIComponent(name)}` }), { status: 201, headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'PUT' && userId) {
      const body = await request.json();
      const u = sysConfig.users?.find(usr => usr.id === userId);
      if (!u) return new Response(JSON.stringify({ success: false, error: 'User not found' }), { status: 404 });
      if (body.name !== undefined) u.name = body.name;
      if (body.trafficLimit !== undefined) u.limitTotalReq = body.trafficLimit ? Math.floor(parseFloat(body.trafficLimit) * 6000) : null;
      if (body.dailyLimit !== undefined) u.limitDailyReq = body.dailyLimit ? Math.floor(parseFloat(body.dailyLimit) * 6000) : null;
      if (body.expiryDays !== undefined) u.expiryMs = body.expiryDays ? Date.now() + parseInt(body.expiryDays) * 86400000 : null;
      if (body.notes !== undefined) u.notes = body.notes;
      if (body.status !== undefined) {
        if (body.status === 'active') { u.isPaused = false; u.disabledReason = null; u.disabledAt = null; }
        else if (body.status === 'paused') { u.isPaused = true; u.disabledReason = null; u.disabledAt = null; }
      }
      await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ success: true, user: u }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'DELETE' && userId) {
      if (!sysConfig.users) return new Response(JSON.stringify({ success: false }), { status: 400 });
      const idx = sysConfig.users.findIndex(usr => usr.id === userId);
      if (idx === -1) return new Response(JSON.stringify({ success: false, error: 'User not found' }), { status: 404 });
      const deleted = sysConfig.users.splice(idx, 1)[0];
      await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
      ctx?.waitUntil(sendTelegramMessage(`Deleted user: ${deleted.name} (${deleted.id})`, env));
      return new Response(JSON.stringify({ success: true, deleted: deleted.id }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'POST' && userId && url.searchParams.get('action') === 'toggle') {
      const u = sysConfig.users?.find(usr => usr.id === userId);
      if (!u) return new Response(JSON.stringify({ success: false }), { status: 404 });
      u.isPaused = !u.isPaused;
      if (!u.isPaused) { u.disabledReason = null; u.disabledAt = null; }
      await cachedD1Put(env, 'sys_config', JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ success: true, user: u }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (method === 'POST' && userId && url.searchParams.get('action') === 'reset') {
      const uuidClean = userId.replace(/-/g, '').toLowerCase();
      if (!sysUsageCache.users) sysUsageCache.users = {};
      sysUsageCache.users[uuidClean] = { reqs: 0, dReqs: 0, lastDay: new Date().toISOString().split('T')[0] };
      await cachedD1Put(env, 'sys_usage', JSON.stringify(sysUsageCache));
      return new Response(JSON.stringify({ success: true, message: 'Traffic reset' }), { headers: { 'Content-Type': 'application/json' } });
    }

    return new Response(JSON.stringify({ success: false, error: 'Invalid request' }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500 }); }
}

async function handleStatsApi(request, env) {
  try {
    const url = new URL(request.url);
    const authKey = request.headers.get('Authorization')?.replace('Bearer ', '') || url.searchParams.get('key');
    if (authKey !== sysConfig.masterKey) return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });

    const users = sysConfig.users || [];
    const totalUsers = users.length;
    const activeUsers = users.filter(u => !u.isPaused && (!u.expiryMs || Date.now() <= u.expiryMs)).length;
    let totalTrafficReqs = 0, dailyTrafficReqs = 0;
    const todayDate = new Date().toISOString().split('T')[0];
    users.forEach(u => {
      const idClean = u.id.replace(/-/g, '').toLowerCase();
      const sysU = sysUsageCache?.users?.[idClean] || { reqs: 0, dReqs: 0, lastDay: '' };
      totalTrafficReqs += sysU.reqs || 0;
      if (sysU.lastDay === todayDate) dailyTrafficReqs += sysU.dReqs || 0;
    });

    return new Response(JSON.stringify({
      success: true,
      stats: {
        users: { total: totalUsers, active: activeUsers },
        traffic: { totalRequests: totalTrafficReqs, totalGB: (totalTrafficReqs / 6000).toFixed(2), dailyRequests: dailyTrafficReqs },
        system: { uptimeSeconds: Math.floor((Date.now() - isolateStartTime) / 1000), activeConnections, version: CURRENT_VERSION, isPaused: sysConfig.isPaused || false }
      }
    }), { headers: { 'Content-Type': 'application/json' } });
  } catch (e) { return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500 }); }
}

// ============================================================
// Worker Entry Point
// ============================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await loadSysConfig(env);
      const url = new URL(request.url);
      const host = request.headers.get('Host') || url.hostname;
      const upgradeHeader = request.headers.get('Upgrade');
      const isWebSocket = upgradeHeader && upgradeHeader.toLowerCase() === 'websocket';
      let reqPath = url.pathname;
      if (reqPath.endsWith('/') && reqPath.length > 1) reqPath = reqPath.slice(0, -1);

      const route = `/${sysConfig.apiRoute}`;
      const isApiRoute = reqPath.startsWith(route) || reqPath === route;

      // WebSocket -> VLESS proxy
      if (isWebSocket) {
        if (sysConfig.isPaused) return new Response(null, { status: 503 });
        if (!sysConfig.users || sysConfig.users.length === 0) return new Response('No users configured', { status: 500 });
        return vlessOverWSHandler(request);
      }

      // Root landing page
      if (reqPath === '/' || reqPath === '') return new Response(serveLandingPage(url), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });

      // Non-API routes -> maintenance page
      if (!isApiRoute) return serveMaintenancePage(request, url);

      // Telegram webhook
      if (reqPath === `${route}/tg`) {
        if (request.method !== 'POST') return new Response('405', { status: 405 });
        return handleTelegramWebhook(request, env, host, ctx);
      }

      // Dashboard
      if (reqPath === `${route}/dash`) return new Response(serveDashboardPage(env), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });

      // Auth
      if (reqPath === `${route}/api/auth`) {
        if (request.method !== 'POST') return new Response('405', { status: 405 });
        return handleAuth(request, host, ctx, env);
      }

      // Config sync
      if (reqPath === `${route}/api/sync`) {
        if (request.method !== 'POST') return new Response('405', { status: 405 });
        return handleConfigSync(request, env, ctx);
      }

      // Users API
      if (reqPath === `${route}/api/users` || reqPath === `${route}/api/users/`) {
        return handleUsersApi(request, env, ctx);
      }

      // Stats API
      if (reqPath === `${route}/api/stats` || reqPath === `${route}/api/stats/`) {
        return handleStatsApi(request, env);
      }

      // Subscription endpoint
      if (reqPath === route) {
        const flag = (url.searchParams.get('flag') || url.searchParams.get('format') || '').toLowerCase();
        const sub = url.searchParams.get('sub');
        const ua = (request.headers.get('User-Agent') || '').toLowerCase();

        // Subscriber portal for browser
        if (!flag) {
          const isBrowser = ua.includes('mozilla') || ua.includes('chrome') || ua.includes('safari') || ua.includes('applewebkit');
          if (isBrowser && sub) {
            const targetUser = sysConfig.users?.find(u => u.name.toLowerCase() === sub.toLowerCase() || u.id === sub);
            if (targetUser) return new Response(serveSubscriberPortal(host, targetUser, url), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
          }
          if (isBrowser) return new Response(serveLandingPage(url), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
        }

        // Subscription profiles
        const resHeaders = { 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' };
        if (sub) {
          const targetUser = sysConfig.users?.find(u => u.name.toLowerCase() === sub.toLowerCase() || u.id === sub);
          if (targetUser) resHeaders['Subscription-UserInfo'] = getSubUserInfo(targetUser);
        }

        // Auto-detect client
        const isClash = flag === 'clash' || flag === 'yaml' || ua.includes('clash') || ua.includes('mihomo') || ua.includes('stash') || ua.includes('meta');
        const isSingbox = flag === 'singbox' || flag === 'sb' || ua.includes('sing-box') || ua.includes('singbox') || ua.includes('hiddify');
        const isLoon = flag === 'loon' || ua.includes('loon');
        const isSurge = flag === 'surge' || ua.includes('surge');
        const isQX = flag === 'qx' || flag === 'quantumult' || ua.includes('quantumult');
        const isSS = flag === 'ss' || flag === 'shadowsocks' || ua.includes('shadowsocks');

        const uuid = sysConfig.users?.find(u => !sub || u.name.toLowerCase() === sub.toLowerCase() || u.id === sub)?.id || sysConfig.users?.[0]?.id || sysConfig.masterKey;

        if (isClash) {
          return new Response(buildClashYamlProfile(host, sub), { headers: { ...resHeaders, 'Content-Type': 'text/yaml; charset=utf-8' } });
        } else if (isSingbox) {
          return new Response(JSON.stringify(buildSingboxConfig(host, sub), null, 2), { headers: { ...resHeaders, 'Content-Type': 'application/json; charset=utf-8' } });
        } else if (isLoon) {
          return new Response(buildLoonConfig(host, uuid), { headers: { ...resHeaders, 'Content-Type': 'text/plain; charset=utf-8' } });
        } else if (isSurge) {
          return new Response(buildSurgeConfig(host, uuid), { headers: { ...resHeaders, 'Content-Type': 'text/plain; charset=utf-8' } });
        } else if (isQX) {
          return new Response(buildQuantumultXConfig(host, uuid), { headers: { ...resHeaders, 'Content-Type': 'text/plain; charset=utf-8' } });
        } else if (isSS) {
          const port = (sysConfig.ports || '443').split(',')[0].trim();
          return new Response(getShadowsocksUri(host, port), { headers: { ...resHeaders, 'Content-Type': 'text/plain; charset=utf-8' } });
        } else if (flag === 'frag') {
          return new Response(JSON.stringify(buildFragmentXrayConfig(host, uuid), null, 2), { headers: { ...resHeaders, 'Content-Type': 'application/json; charset=utf-8' } });
        } else if (flag === 'best') {
          return new Response(buildBestSub(host, uuid), { headers: { ...resHeaders, 'Content-Type': 'text/plain; charset=utf-8' } });
        } else {
          return new Response(safeBtoa(buildUriProfile(host, sub)), { headers: { ...resHeaders, 'Content-Type': 'text/plain; charset=utf-8' } });
        }
      }

      // Health check endpoint
      if (reqPath === `${route}/health` || reqPath === `${route}/health/`) {
        const targetHost = url.searchParams.get('host') || host;
        const targetPort = url.searchParams.get('port') || '443';
        const result = await healthCheck(targetHost, targetPort);
        return Response.json({ host: targetHost, port: targetPort, ...result, version: CURRENT_VERSION }, { headers: { 'Access-Control-Allow-Origin': '*' } });
      }

      // Load balance endpoint
      if (reqPath === `${route}/loadbalance` || reqPath === `${route}/loadbalance/`) {
        const hosts = (url.searchParams.get('hosts') || host).split(',');
        const port = url.searchParams.get('port') || '443';
        const best = await loadBalance(hosts, port);
        return Response.json({ best, hosts, port }, { headers: { 'Access-Control-Allow-Origin': '*' } });
      }

      // QR code endpoint
      if (reqPath === `${route}/qr` || reqPath === `${route}/qr/`) {
        const text = url.searchParams.get('text') || `http://${host}/${sysConfig.apiRoute}`;
        const size = url.searchParams.get('size') || '200';
        return Response.redirect(generateQRCodeSVG(text, size), 302);
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      return new Response(`Error: ${err.message}`, { status: 500 });
    }
  },

  async scheduled(event, env, ctx) {
    console.log(`[PacketAlchemy] Cron at ${new Date().toISOString()}`);
    if (env.PA_DB) {
      ctx.waitUntil(d1Put(env, 'sys_config', JSON.stringify(sysConfig)).catch(() => {}));
      ctx.waitUntil(d1Put(env, 'sys_usage', JSON.stringify(sysUsageCache)).catch(() => {}));
    }
  },
};
