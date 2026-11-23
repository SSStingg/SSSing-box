let CUR_PROTO = 'vless';
let NODES = [];       // /api/inbounds flat list (with links)
let USAGE = {};       // id -> usage node from /api/usage
let CHAINS = [];
let BNODES = [];
let POLL = null;
let PING_POLL = null;

function $(id){ return document.getElementById(id); }
function toast(msg, isErr){
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast on' + (isErr ? ' err' : '');
  clearTimeout(t._h);
  t._h = setTimeout(()=>{ t.className = 'toast'; }, 3200);
}
async function api(path, method, body, timeoutMs){
  const opt = { method: method || 'GET', headers: {'Content-Type':'application/json'} };
  if (body !== undefined) opt.body = JSON.stringify(body);
  const ctl = new AbortController();
  const ms = timeoutMs === undefined ? 15000 : timeoutMs;
  const to = ms > 0 ? setTimeout(() => ctl.abort(), ms) : null;
  opt.signal = ctl.signal;
  let r;
  try {
    r = await fetch((window.PANEL_BASE || '') + path, opt);
  } catch(e){
    if (e && e.name === 'AbortError') throw new Error('请求超时，请稍后再试');
    throw e;
  } finally { if (to) clearTimeout(to); }
  let j = {};
  try { j = await r.json(); } catch(e){}
  if (r.status === 401){ showLogin(); throw new Error('未登录'); }
  if (!j.ok) throw new Error(j.error || ('请求失败 ' + r.status));
  return j.data;
}
function fmtBytes(n){
  if (n == null) return '-';
  const u = ['B','KB','MB','GB','TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length-1){ v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + u[i];
}
function fmtRate(n){ return fmtBytes(n) + '/s'; }
function fmtDur(sec){
  if (!sec) return '-';
  const d = Math.floor(sec/86400), h = Math.floor(sec%86400/3600), m = Math.floor(sec%3600/60);
  if (d > 0) return d + '天' + h + '小时';
  if (h > 0) return h + '小时' + m + '分';
  return m + '分';
}
function fmtPct(p){ return (p == null ? 0 : p).toFixed(p >= 10 ? 0 : 2) + '%'; }
function uuidv4(){
  const b = new Uint8Array(16); crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2,'0')).join('');
  return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
}
function escHtml(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escAttr(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function copyText(idOrVal, val){
  const text = val !== undefined ? val : $(idOrVal).value;
  const done = ()=> toast('已复制到剪贴板');
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(done).catch(()=>fallbackCopy(text, done));
  } else fallbackCopy(text, done);
}
function fallbackCopy(text, done){
  const ta = document.createElement('textarea');
  ta.value = text; document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch(e){ toast('复制失败，请手动复制', true); }
  document.body.removeChild(ta);
}
function effAddr(n){
  return panelCertDomain(PANEL_CERT_ID) || n.address;
}

// ---------- modal ----------
let MODAL_LOCKED = false;
function openModal(html, wide){
  $('modalBox').innerHTML = html;
  $('modalBox').className = 'modal' + (wide ? ' wide' : '');
  $('overlay').className = 'overlay on';
}
function closeModal(){ if (MODAL_LOCKED) return; $('overlay').className = 'overlay'; }
$('overlay').addEventListener('click', e => { if (e.target.id === 'overlay' && !MODAL_LOCKED) closeModal(); });
function confirmModal(title, bodyHtml, okText, onOk){
  openModal(`<h4>${escHtml(title)}</h4><div style="color:var(--txt-secondary);line-height:1.7">${bodyHtml}</div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn red" id="cfmOk">${escHtml(okText)}</button></div>
    <div class="msg" id="cfmMsg"></div>`);
  $('cfmOk').onclick = async ()=>{
    $('cfmOk').disabled = true;
    try { await onOk(); closeModal(); } catch(e){ $('cfmMsg').className = 'msg err'; $('cfmMsg').textContent = e.message; $('cfmOk').disabled = false; }
  };
}

// ---------- 法律声明（首次登录弹窗） ----------
const DISCLAIMER_KEY = 'sssingbox_disclaimer_ack';
function disclaimerAcked(){
  try { return !!localStorage.getItem(DISCLAIMER_KEY); } catch(e){ return false; }
}
function showDisclaimer(){
  if (disclaimerAcked()) return;
  MODAL_LOCKED = true;
  openModal(`<h4>合规与使用须知</h4>
    <div style="color:var(--txt-secondary);font-size:14px;line-height:1.8">
    <p style="margin:0 0 10px">SSSing-box 是一个 sing-box 代理管理面板，仅供网络安全学习、研究与测试使用。</p>
    <p style="margin:0 0 10px">请勿将本项目用于绕过网络审查、规避检测、非法访问受限内容，或任何违反所在国家和地区法律法规的用途。</p>
    <p style="margin:0">本项目禁止中国大陆地区用户部署与使用。如您是中国大陆居民，请勿使用本项目，并立即停止访问。</p>
    </div>
    <div class="foot" style="justify-content:center"><button class="btn" id="disclaimerAck">已知晓，本人非中国大陆居民</button></div>`);
  $('disclaimerAck').onclick = ()=>{
    try { localStorage.setItem(DISCLAIMER_KEY, '1'); } catch(e){}
    MODAL_LOCKED = false;
    closeModal();
  };
}

// ---------- views / auth ----------
function showView(name){
  document.querySelectorAll('.view').forEach(v => v.classList.remove('on'));
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('on', b.dataset.view === name));
  $('view-' + name).classList.add('on');
  if (name === 'status') refreshStatus();
  if (name === 'inbounds'){ refreshStatus(); loadChains(); }
  if (name === 'settings') loadSettings();
}
function hideAllAuth(){
  $('setupView').style.display = 'none';
  $('loginView').style.display = 'none';
  $('appView').style.display = 'none';
}
function randomUsername(){
  const first = 'abcdefghjkmnpqrstuvwxyz', rest = first + '23456789';
  let s = first[Math.floor(Math.random() * first.length)];
  for (let i = 0; i < 7; i++) s += rest[Math.floor(Math.random() * rest.length)];
  return s;
}
function showSetup(){
  hideAllAuth();
  if ($('setupUser') && !$('setupUser').value) $('setupUser').value = randomUsername();
  $('setupView').style.display = 'flex';
  if (POLL){ clearInterval(POLL); POLL = null; }
  if (PING_POLL){ clearInterval(PING_POLL); PING_POLL = null; }
}
function showLogin(){
  LOGIN_TMP = '';
  if ($('login2faWrap')) $('login2faWrap').style.display = 'none';
  hideAllAuth();
  $('loginView').style.display = 'flex';
  if (POLL){ clearInterval(POLL); POLL = null; }
  if (PING_POLL){ clearInterval(PING_POLL); PING_POLL = null; }
}
function showApp(){
  hideAllAuth();
  $('appView').style.display = 'block';
  showDisclaimer();
  refreshAll();
  if (!POLL) POLL = setInterval(()=>{ if ($('view-status').classList.contains('on')) refreshStatus(); }, 5000);
  if (!PING_POLL) PING_POLL = setInterval(refreshBNodePing, 3000);
}
async function doSetup(){
  $('setupErr').textContent = '';
  let u = $('setupUser').value.trim();
  if (!u){ u = randomUsername(); $('setupUser').value = u; }
  const p = $('setupPass').value, p2 = $('setupPass2').value;
  if (p !== p2){ $('setupErr').textContent = '两次输入的密码不一致'; return; }
  try {
    const r = await api('/api/setup', 'POST', { username: u, password: p, password2: p2 });
    if (r && r.panel_path && !window.PANEL_BASE){
      location.href = '/' + r.panel_path + '/';
      return;
    }
    showApp();
  } catch(e){ $('setupErr').textContent = e.message; }
}
let LOGIN_TMP = '';
async function doLogin(){
  $('loginErr').textContent = '';
  $('login2faWrap').style.display = 'none';
  try {
    const r = await api('/api/login', 'POST', { username: $('loginUser').value.trim(), password: $('loginPass').value, remember: $('loginRemember').checked });
    if (r.need_2fa){ LOGIN_TMP = r.tmp; $('login2faWrap').style.display = ''; $('login2fa').focus(); return; }
    showApp();
  } catch(e){ $('loginErr').textContent = e.message; }
}
async function doLogin2fa(){
  $('loginErr').textContent = '';
  try {
    await api('/api/login/2fa', 'POST', { tmp: LOGIN_TMP, code: $('login2fa').value.trim() });
    LOGIN_TMP = ''; $('login2fa').value = '';
    showApp();
  } catch(e){ $('loginErr').textContent = e.message; }
}
async function doLogout(){
  try { await api('/api/logout', 'POST', {}); } catch(e){}
  showLogin();
}
$('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('login2fa').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin2fa(); });
$('loginUser').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('setupPass2').addEventListener('keydown', e => { if (e.key === 'Enter') doSetup(); });

// ---------- rings (compact) ----------
function ringHTML(pct, cls){
  const C = 201.1;
  const off = C * (1 - Math.min(100, Math.max(0, pct)) / 100);
  const color = pct >= 90 ? 'bad' : pct >= 75 ? 'warn' : '';
  return `<svg width="76" height="76" viewBox="0 0 76 76">
    <circle class="bg" cx="38" cy="38" r="32" fill="none" stroke-width="8"/>
    <circle class="fg ${cls || color}" cx="38" cy="38" r="32" fill="none" stroke-width="8"
      stroke-dasharray="${C}" stroke-dashoffset="${off}"/>
  </svg><div class="num">${fmtPct(pct)}</div>`;
}
function renderSystem(d){
  const s = d.system;
  $('ringCpu').innerHTML = ringHTML(s.cpu_percent);
  $('ringMem').innerHTML = ringHTML(s.mem_percent);
  $('ringSwap').innerHTML = ringHTML(s.swap_percent);
  $('ringDisk').innerHTML = ringHTML(s.disk_percent);
  $('capCpu').textContent = s.cpu_cores + ' Cores';
  $('capMem').textContent = fmtBytes(s.mem_used) + ' / ' + fmtBytes(s.mem_total);
  $('capSwap').textContent = fmtBytes(s.swap_used) + ' / ' + fmtBytes(s.swap_total);
  $('capDisk').textContent = fmtBytes(s.disk_used) + ' / ' + fmtBytes(s.disk_total);
  $('kvLoad').textContent = s.load1.toFixed(2) + ' | ' + s.load5.toFixed(2) + ' | ' + s.load15.toFixed(2);
  $('kvUptime').textContent = fmtDur(s.uptime_sec);
  $('kvPanelMem').textContent = fmtBytes(s.panel_mem);
  $('kvPubIp').textContent = d.public_ip || '-';
  $('kvPubIp6').textContent = d.public_ipv6 || '-';
  $('kvPubIp6Row').style.display = d.public_ipv6 ? '' : 'none';
  $('sysSub').textContent = '面板已运行 ' + fmtDur(d.panel_uptime_sec);
}

// ---------- cores ----------
let CORE_LIST = [];
const CORE_INSTALL = {};
async function refreshCores(){
  const list = await api('/api/cores');
  CORE_LIST = list;
  const el = $('coreRows');
  if (!list.length){ el.innerHTML = '<div class="empty">暂无内核信息</div>'; return; }
  el.innerHTML = list.map(c => {
    const nm = escAttr(c.name), tt = escAttr(c.title);
    return `
    <div class="row core-row">
      <span class="dot ${c.running ? 'on' : 'off'}"></span>
      <div class="grow"><div class="t">${escHtml(c.title)}</div>
        <div class="s">${c.installed ? ('已安装 ' + escHtml(c.version) + (c.has_update ? ' · 有新版本 ' + escHtml(c.latest) : '')) : '未下载，不占空间'}${c.note ? ' · ' + escHtml(c.note) : ''}${c.name === 'sing-box' ? ' · 通用代理内核' : ''}</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">
        ${CORE_INSTALL[c.name]
          ? `<button class="btn small" data-install-core="${nm}" disabled>${escHtml(CORE_INSTALL[c.name])}</button>`
          : (c.installed
            ? `${c.no_update ? '' : `<button class="btn ghost small" data-core="${nm}" onclick="openVerDialog(this.dataset.core)">版本/更新</button>`}
               <button class="btn ghost small" data-core="${nm}" onclick="restartCore(this.dataset.core)">重启</button>
               <button class="btn ghost small" data-core="${nm}" onclick="showCoreLog(this.dataset.core)">日志</button>`
            : `<button class="btn small" data-install-core="${nm}" data-core="${nm}" onclick="installCore(this.dataset.core,'',this)">下载安装</button>`)}
      </div>
    </div>`;
  }).join('');
}
function pollCoreProgress(name, setText){
  let busy = false;
  return setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
      const p = await api('/api/cores/progress');
      const phase = p && p[name];
      if (phase === 'installing'){ CORE_INSTALL[name] = '安装中…'; setText('安装中…'); }
      else if (phase === 'downloading'){ CORE_INSTALL[name] = '下载中…'; setText('下载中…'); }
    } catch(_){}
    finally { busy = false; }
  }, 800);
}
function coreInstallBtn(name){
  return document.querySelector('[data-install-core="' + CSS.escape(name) + '"]');
}
async function installCore(name, version, btn){
  if (CORE_INSTALL[name]) return;
  CORE_INSTALL[name] = '下载中…';
  if (btn){ btn.disabled = true; btn.textContent = '下载中…'; }
  const timer = pollCoreProgress(name, t => { const b = coreInstallBtn(name) || btn; if (b) b.textContent = t; });
  try {
    const r = await api('/api/cores/' + encodeURIComponent(name) + '/install', 'POST', { version: version || '' }, 600000);
    toast(name + ' 已安装 ' + r.version);
  } catch(e){ toast(e.message, true); }
  clearInterval(timer);
  delete CORE_INSTALL[name];
  refreshCores(); refreshStatus();
}
// coreTitle：按名字从内核列表取显示标题。onclick 只传名字，标题不在 HTML/JS 字符串里拼。
function coreTitle(name){
  const c = CORE_LIST.find(x => x.name === name);
  return c ? c.title : name;
}
async function openVerDialog(name){
  VER_SHOW_ALL = false;
  const nm = escAttr(name);
  openModal(`<div class="ver-head"><h4>${escHtml(coreTitle(name))} · 选择版本安装</h4><button class="btn ghost sm" id="verAllBtn" data-core="${nm}" onclick="toggleVerAll(this.dataset.core)">显示所有内核</button></div><div class="ver-list" id="verList"><div class="muted" style="padding:14px">正在获取版本…</div></div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button></div><div class="msg" id="verMsg"></div>`);
  loadVerList(name);
}
async function loadVerList(name){
  $('verList').innerHTML = '<div class="muted" style="padding:14px">正在获取版本…</div>';
  try {
    const vers = await api('/api/cores/' + encodeURIComponent(name) + '/versions' + (VER_SHOW_ALL ? '?all=1' : ''));
    if (!vers.length){ $('verList').innerHTML = '<div class="muted" style="padding:14px">没有可用版本</div>'; return; }
    const nm = escAttr(name);
    $('verList').innerHTML = vers.map(v =>
      `<button data-core="${nm}" data-ver="${escAttr(v)}" onclick="installCoreVer(this)">${escHtml(v)}${isPreTag(v) ? ' <span class="tag-pre">测试版</span>' : ''}</button>`).join('');
  } catch(e){ $('verMsg').className = 'msg err'; $('verMsg').textContent = e.message; }
}
function isPreTag(v){ return String(v).indexOf('-') > 0; }
let VER_SHOW_ALL = false;
function toggleVerAll(name){
  VER_SHOW_ALL = !VER_SHOW_ALL;
  $('verAllBtn').textContent = VER_SHOW_ALL ? '只显示正式版' : '显示所有内核';
  loadVerList(name);
}
async function installCoreVer(btn){
  const name = btn.dataset.core, ver = btn.dataset.ver;
  if (CORE_INSTALL[name]) return;
  CORE_INSTALL[name] = '下载中…';
  btn.disabled = true; btn.textContent = '下载中…';
  const timer = pollCoreProgress(name, t => { btn.textContent = t; });
  try {
    const r = await api('/api/cores/' + encodeURIComponent(name) + '/install', 'POST', { version: ver }, 600000);
    toast(name + ' 已安装 ' + r.version);
    closeModal(); refreshCores(); refreshStatus();
  } catch(e){
    $('verMsg').className = 'msg err'; $('verMsg').textContent = e.message;
    btn.disabled = false; btn.textContent = ver;
  }
  clearInterval(timer);
  delete CORE_INSTALL[name];
}
async function restartCore(name){
  try { await api('/api/cores/' + encodeURIComponent(name) + '/restart', 'POST', {}); toast(name + ' 已重启'); refreshStatus(); }
  catch(e){ toast(e.message, true); }
}
async function showCoreLog(name){
  try {
    const log = await api('/api/cores/' + encodeURIComponent(name) + '/log');
    const nm = escAttr(name);
    openModal(`<h4>${escHtml(coreTitle(name))} · 运行日志（最近 100 行）</h4><div class="muted" style="padding:2px 0 12px">日志文件位于面板数据目录 cores/ 下；单文件超过 10MB 自动截取最新 2000 行。</div><pre class="log">${escHtml(log || '(暂无日志)')}</pre>
      <div class="foot"><button class="btn ghost" data-core="${nm}" onclick="clearCoreLog(this.dataset.core)">清空日志</button><button class="btn ghost" onclick="closeModal()">关闭</button></div>`, true);
  } catch(e){ toast(e.message, true); }
}
async function clearCoreLog(name){
  try { await api('/api/cores/' + encodeURIComponent(name) + '/clear-log', 'POST', {}); toast('日志已清理'); showCoreLog(name); }
  catch(e){ toast(e.message, true); }
}

// ---------- usage: status view (view-only) + inbound list rows ----------
async function refreshStatus(){
  try {
    const sys = await api('/api/system');
    renderSystem(sys);
  } catch(e){ console.warn('refreshStatus /api/system 失败：', e); }
  try {
    const u = await api('/api/usage');
    renderUsage(u);
  } catch(e){ console.warn('refreshStatus /api/usage 失败：', e); }
  try { await refreshCores(); } catch(e){ console.warn('refreshStatus refreshCores 失败：', e); }
}
function protoBadge(p){
  if (p === 'vless') return '<span class="badge">VLESS</span>';
  if (p === 'hy2') return '<span class="badge hy2">HY2</span>';
  if (p === 'vmess') return '<span class="badge">VMess</span>';
  if (p === 'trojan') return '<span class="badge">Trojan</span>';
  if (p === 'wireguard') return '<span class="badge">WG</span>';
  if (p === 'dokodemo') return '<span class="badge">DOKO</span>';
  if (p === 'ss') return '<span class="badge">SS</span>';
  if (p === 'socks') return '<span class="badge">SOCKS</span>';
  if (p === 'http') return '<span class="badge">HTTP</span>';
  if (p === 'tuic') return '<span class="badge">TUIC</span>';
  if (p === 'anytls') return '<span class="badge">AnyTLS</span>';
  if (p === 'naive') return '<span class="badge">Naive</span>';
  if (p === 'snell') return '<span class="badge">Snell</span>';
  if (p === 'shadowtls') return '<span class="badge">ShadowTLS</span>';
  if (p === 'hysteria2') return '<span class="badge hy2">HY2</span>';
  return '<span class="badge">' + escHtml(p) + '</span>';
}
function nodeCfg(id){
  const n = NODES.find(x => x.id === id);
  if (!n || !n.config) return null;
  try { return JSON.parse(n.config); } catch(e){ return null; }
}
function protoFull(p, cfg){
  if (p === 'vless'){
    const mode = (cfg && cfg.mode) || 'reality';
    let s = mode === 'reality' ? 'sing-box · VLESS + Reality + TCP' :
      mode === 'ws' ? 'sing-box · VLESS + WS + TLS' :
      mode === 'h2' ? 'sing-box · VLESS + H2 + TLS' :
      mode === 'httpupgrade' ? 'sing-box · VLESS + HTTPUpgrade + TLS' : 'sing-box · VLESS';
    if (mode === 'reality' && cfg && cfg.flow) s += ' + ' + cfg.flow;
    return s;
  }
  if (p === 'hy2'){
    let s = 'sing-box · Hysteria2 + QUIC/UDP + TLS';
    if (cfg && cfg.obfs_type) s += ' + ' + cfg.obfs_type;
    return s;
  }
  if (p === 'vmess'){
    const mode = (cfg && cfg.mode) || 'tcp';
    return mode === 'cf' ? 'sing-box · VMess + WS + TLS（Cloudflare）' :
      mode === 'http' ? 'sing-box · VMess + HTTP' :
      mode === 'quic' ? 'sing-box · VMess + QUIC + TLS' :
      mode === 'h2' ? 'sing-box · VMess + H2 + TLS' :
      mode === 'httpupgrade' ? 'sing-box · VMess + HTTPUpgrade + TLS' : 'sing-box · VMess + TCP';
  }
  if (p === 'trojan'){
    const mode = (cfg && cfg.mode) || 'reality';
    return mode === 'cf' ? 'sing-box · Trojan + WS + TLS（Cloudflare）' :
      mode === 'h2' ? 'sing-box · Trojan + H2 + TLS' :
      mode === 'httpupgrade' ? 'sing-box · Trojan + HTTPUpgrade + TLS' : 'sing-box · Trojan + Reality + TCP';
  }
  if (p === 'wireguard') return 'sing-box · WireGuard + UDP';
  if (p === 'dokodemo') return 'Dokodemo-door（已退役，sing-box 不支持）';
  if (p === 'ss') return 'sing-box · Shadowsocks + ' + (cfg && cfg.method ? cfg.method : '');
  if (p === 'socks') return 'sing-box · SOCKS5 + 账号密码';
  if (p === 'http') return 'sing-box · HTTP + 账号密码';
  if (p === 'tuic') return 'sing-box · TUIC + QUIC/UDP + TLS';
  if (p === 'anytls') return 'sing-box · AnyTLS + TCP + TLS';
  if (p === 'naive') return 'sing-box · Naive + TCP + TLS（需 CA 证书）';
  if (p === 'snell'){
    const ver = (cfg && cfg.version) || 5;
    return ver === 6 ? 'sing-box · Snell v6 + TCP + 流量整形' : 'sing-box · Snell v5 + TCP + HTTP 混淆';
  }
  if (p === 'shadowtls') return 'sing-box · ShadowTLS v3 + SS2022 + TCP + 真 TLS 握手';
  if (p === 'hysteria2') return 'Hysteria2';
  return p || '';
}
function quotaText(n){
  if (!n.quota_mode || !n.quota_bytes) return '';
  const used = n.quota_mode === 'down' ? n.total_down : (n.total_up + n.total_down);
  const pct = Math.round(used / n.quota_bytes * 100);
  return ' · 限额 ' + fmtBytes(n.quota_bytes) + (n.quota_mode === 'down' ? '（下行）' : '（合计）') + '，已用 ' + pct + '%';
}
function scrollTraffic(){
  const sc = $('trafficScroll');
  if (sc) sc.scrollBy({ top: 120, behavior: 'smooth' });
}
function renderUsage(u){
  const nodes = u.nodes || [];
  USAGE = {};
  nodes.forEach(n => { USAGE[n.id] = n; });
  let rtUp = 0, rtDown = 0, tcp = 0, udp = 0, udpKnown = false;
  const el = $('trafficRows');
  const sc = $('trafficScroll');
  const keepScroll = sc ? sc.scrollTop : 0;
  if (!nodes.length){
    el.innerHTML = '<div class="empty">还没有节点，去“节点与分流”创建一个吧</div>';
  } else {
    el.innerHTML = nodes.map(n => {
      rtUp += n.rate_up; rtDown += n.rate_down; tcp += n.tcp_conns;
      if (n.udp_conns >= 0){ udp += n.udp_conns; udpKnown = true; }
      return `<div class="row">
        <span class="dot ${n.running ? 'on' : 'off'}"></span>
        <div class="grow"><div class="t">${escHtml(n.name)} ${protoBadge(n.protocol)}</div>
          <div class="s">${escHtml(effAddr(n))}:${n.port} · ${n.enabled ? (n.running ? '运行中' : '核心未启动') : '已停用'}${escHtml(quotaText(n))}</div>
          <div class="s2">${escHtml(protoFull(n.protocol, nodeCfg(n.id)))}</div></div>
        <div class="nums">今日 <b>${fmtBytes(n.today_up)} ↑ / ${fmtBytes(n.today_down)} ↓</b><br>本月 <b>${fmtBytes(n.month_up)} ↑ / ${fmtBytes(n.month_down)} ↓</b> · 总 <b>${fmtBytes(n.total_up + n.total_down)}</b></div>
      </div>`;
    }).join('');
  }
  if (sc){
    sc.scrollTop = keepScroll;
    const more = $('trafficMore');
    if (more) more.style.display = (nodes.length > 3 && sc.scrollHeight > sc.clientHeight + 8) ? '' : 'none';
    sc.onscroll = () => {
      if (more) more.style.display = (sc.scrollHeight - sc.scrollTop - sc.clientHeight > 8) ? '' : 'none';
    };
  }
  $('rtUp').textContent = fmtRate(rtUp);
  $('rtDown').textContent = fmtRate(rtDown);
  $('rtTcp').textContent = tcp;
  $('rtUdp').textContent = udpKnown ? udp : '-';
  $('totToday').textContent = fmtBytes(u.totals.today_up) + ' ↑ / ' + fmtBytes(u.totals.today_down) + ' ↓';
  $('totMonth').textContent = fmtBytes(u.totals.month_up) + ' ↑ / ' + fmtBytes(u.totals.month_down) + ' ↓';
  $('totAll').textContent = fmtBytes(u.totals.total_up) + ' ↑ / ' + fmtBytes(u.totals.total_down) + ' ↓';
  $('statsErr').textContent = u.stats_error ? ('流量统计异常：' + u.stats_error) : '';
  renderLocalRows();
}
function renderLocalRows(){
  const el = $('localRows');
  if (!el) return;
  if (!NODES.length){
    el.innerHTML = '<div class="empty">还没有本地节点，点击左上角“＋ 新建代理入站”快速部署</div>';
    $('localSub').textContent = '';
    return;
  }
  $('localSub').textContent = '共 ' + NODES.length + ' 个节点';
  el.innerHTML = NODES.map(n => {
    const u = USAGE[n.id];
    const today = u ? (fmtBytes(u.today_up) + ' ↑ / ' + fmtBytes(u.today_down) + ' ↓') : '-';
    const total = u ? fmtBytes(u.total_up + u.total_down) : '-';
    const uq = u ? quotaText(u) : '';
    let cfg = null;
    try { cfg = n.config ? JSON.parse(n.config) : null; } catch(e){}
    const isDomainMode = (n.protocol === 'trojan' && cfg && (cfg.mode === 'cf' || cfg.mode === 'h2' || cfg.mode === 'httpupgrade')) ||
      (n.protocol === 'vless' && cfg && (cfg.mode === 'ws' || cfg.mode === 'h2' || cfg.mode === 'httpupgrade')) ||
      (n.protocol === 'vmess' && cfg && cfg.mode && cfg.mode !== 'tcp') || n.protocol === 'naive';
    const sniWordShown = isDomainMode ? '域名' : sniWord(n.protocol);
    const hideSni = n.protocol === 'ss' || n.protocol === 'socks' || n.protocol === 'http' || n.protocol === 'wireguard' || n.protocol === 'dokodemo' || n.protocol === 'snell' || n.protocol === 'shadowtls' || (n.protocol === 'vmess' && (!cfg || !cfg.mode || cfg.mode === 'tcp'));
    const sniPart = hideSni ? '' : ` · ${sniWordShown} ${escHtml(n.sni)}`;
    const certHint = (n.protocol === 'naive' && cfg && !cfg.cert_file) ? ' · 缺 CA 证书，点 ⋮ 上传' : '';
    const nid = escAttr(n.id);
    return `<div class="nrow">
      <button class="menu-btn" title="操作菜单" onclick="openNodeMenu(this,'${nid}')">⋮</button>
      <input type="checkbox" class="switch" ${n.enabled ? 'checked' : ''} title="${n.enabled ? '停用' : '启用'}" onchange="toggleNode('${nid}', this.checked)">
      <div style="min-width:0"><div class="t">${escHtml(n.name)}</div>
        <div class="s">${escHtml(effAddr(n))}:${n.port}${sniPart} · ${n.enabled ? (u && u.running === false ? '核心未启动' : '运行中') : '已停用'}${escHtml(uq)}${certHint}</div>
        <div class="s" style="color:var(--primary);font-weight:500">${escHtml(protoFull(n.protocol, cfg))}</div></div>
      <div class="cell"><b>${n.port}</b></div>
      <div class="cell">${protoBadge(n.protocol)}</div>
      <div class="cell hide-m"><b>${today}</b></div>
      <div class="cell hide-m"><b>${total}</b></div>
    </div>`;
  }).join('');
}
function nodeById(id){
  return NODES.find(x => x.id === id) || USAGE[id] || null;
}
function showLink(id){
  const n = nodeById(id);
  if (!n) return;
  const link = n.link || '';
  const extra = n.tme_link ? `<div style="margin-top:12px"><label>t.me 链接</label><div class="input-row"><input id="lkTme" readonly value="${escAttr(n.tme_link)}"><button class="btn ghost small" onclick="copyText('lkTme')">复制</button></div></div>` : '';
  const linkField = (n.protocol === 'wireguard' || n.protocol === 'naive')
    ? `<label>${n.protocol === 'naive' ? 'Naive 配置（参考客户端 JSON 配置，不是 URL，别贴进 URL 导入框）' : 'WireGuard 配置（贴进官方客户端，或扫下方二维码）'}</label><textarea id="lkMain" readonly rows="11" style="width:100%" class="mono">${escHtml(link)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain')">复制配置</button></div>`
    : `<label>节点链接</label><div class="input-row"><input id="lkMain" readonly value="${escAttr(link)}"><button class="btn ghost small" onclick="copyText('lkMain')">复制</button></div>`;
  const link6Field = !n.link6 ? '' : ((n.protocol === 'wireguard' || n.protocol === 'naive')
    ? `<div style="margin-top:12px"><label>${n.protocol === 'wireguard' ? 'WireGuard 配置 IPv6' : 'Naive 配置 IPv6'}</label><textarea id="lkMain6" readonly rows="11" style="width:100%" class="mono">${escHtml(n.link6)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain6')">复制配置</button></div></div>`
    : `<div style="margin-top:12px"><label>节点链接 IPv6</label><div class="input-row"><input id="lkMain6" readonly value="${escAttr(n.link6)}"><button class="btn ghost small" onclick="copyText('lkMain6')">复制</button></div></div>`);
  openModal(`<h4>${escHtml(n.name)} · 连接凭证与二维码</h4>
    ${linkField}
    ${link6Field}
    ${extra}
    <div class="qr-box"><img src="${escAttr((window.PANEL_BASE||'') + '/api/inbounds/' + encodeURIComponent(n.id) + '/qr')}" alt="二维码"></div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button></div>`);
}
function openNodeMenu(btn, id){
  const n = nodeById(id);
  if (!n) return;
  const nid = escAttr(id);
  openDropdown(btn, `
    <button onclick="closeDropdown();openEditNodeModal('${nid}')">${MI.edit}编辑配置</button>
    <button onclick="closeDropdown();showLink('${nid}')">${MI.link}连接链接 / 二维码</button>
    ${n.protocol === 'naive' ? `<button onclick="closeDropdown();openCertModal('${nid}')">${MI.upload}上传 CA 证书</button>` : ''}
    <button onclick="closeDropdown();resetNodeTraffic('${nid}')">${MI.reset}重置统计流量</button>
    <button class="danger" onclick="closeDropdown();delNode('${nid}')">${MI.trash}删除此节点</button>`);
}
const MI = {
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>',
  link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg>',
  reset: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>',
};
function closeDropdown(){
  const d = $('rowDropdown');
  if (d) d.remove();
  document.removeEventListener('mousedown', dropdownOutside, true);
  document.removeEventListener('keydown', dropdownEsc, true);
  window.removeEventListener('scroll', closeDropdown, true);
}
function dropdownOutside(e){
  const d = $('rowDropdown');
  if (d && !d.contains(e.target) && !e.target.closest('.menu-btn')) closeDropdown();
}
function dropdownEsc(e){ if (e.key === 'Escape') closeDropdown(); }
function openDropdown(btn, itemsHtml){
  const cur = $('rowDropdown');
  if (cur && cur._btn === btn){ closeDropdown(); return; }
  closeDropdown();
  const d = document.createElement('div');
  d.id = 'rowDropdown';
  d.className = 'dropdown';
  d._btn = btn;
  d.innerHTML = itemsHtml;
  document.body.appendChild(d);
  const r = btn.getBoundingClientRect();
  const w = d.offsetWidth, h = d.offsetHeight;
  let left = r.left;
  if (left + w > window.innerWidth - 8) left = window.innerWidth - w - 8;
  if (left < 8) left = 8;
  let top = r.bottom + 6;
  if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 6);
  d.style.left = left + 'px';
  d.style.top = top + 'px';
  document.addEventListener('mousedown', dropdownOutside, true);
  document.addEventListener('keydown', dropdownEsc, true);
  window.addEventListener('scroll', closeDropdown, true);
}
function openCertModal(id){
  const n = nodeById(id);
  if (!n) return;
  openModal(`<h4>${escHtml(n.name)} · 上传 CA 证书</h4>
    <div class="hint" style="margin:0 0 12px">Naive 必须用 CA 证书：证书上的域名要和节点域名一致，且解析到这台服务器。证书和私钥配对校验通过才保存，保存后立即重启生效。</div>
    <div><label>证书内容（PEM）</label><textarea id="cfCert" rows="7" style="width:100%" class="mono" placeholder="-----BEGIN CERTIFICATE-----"></textarea></div>
    <div style="margin-top:12px"><label>私钥内容（PEM）</label><textarea id="cfKey" rows="7" style="width:100%" class="mono" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="certSaveBtn" onclick="uploadCert('${escAttr(id)}')">上传并启动</button></div>
    <div class="msg" id="certMsg"></div>`, true);
}
async function uploadCert(id){
  const btn = $('certSaveBtn'); btn.disabled = true;
  try {
    await api('/api/inbounds/' + encodeURIComponent(id) + '/cert', 'POST', { cert: $('cfCert').value.trim(), key: $('cfKey').value.trim() });
    toast('证书已上传，节点已启动'); closeModal();
    await refreshStatus(); await loadChains();
  } catch(e){
    $('certMsg').className = 'msg err'; $('certMsg').textContent = e.message;
    btn.disabled = false;
  }
}
function sniLabel(p, mode){
  if (p === 'hy2' || p === 'tuic' || p === 'anytls') return 'TLS SNI（自签证书域名）';
  if (p === 'naive') return '真实域名（CA 证书域名）';
  if (p === 'vmess') return mode && mode !== 'tcp' ? '域名' : '域名（CF 模式必填）';
  if (p === 'trojan') return (mode === 'cf' || mode === 'h2' || mode === 'httpupgrade') ? '域名' : '伪装域名（Reality SNI）';
  if (p === 'vless') return (mode === 'ws' || mode === 'h2' || mode === 'httpupgrade') ? '域名（TLS 证书域名）' : '伪装域名（Reality SNI）';
  return '伪装域名（Reality SNI）';
}
function sniWord(p){
  if (p === 'hy2' || p === 'tuic' || p === 'anytls') return 'SNI';
  if (p === 'naive') return '域名';
  return '伪装';
}
function sniHintEdit(p, mode){
  if (p === 'snell') return 'Snell 不走 TLS，没有 SNI/伪装域名；抗识别靠 v5 的 HTTP 混淆或 v6 的流量整形。';
  if (p === 'shadowtls') return 'ShadowTLS 没有 SNI 行：握手站域名在下方高级配置里改，握手直接转发给它（真证书、真页面）。';
  if (p === 'hy2') return 'Hy2 是 QUIC/UDP + 真 TLS：面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1，证书不校验真伪）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。改 SNI 后证书要重建，旧链接失效。';
  if (p === 'tuic') return 'TUIC 是 QUIC/UDP + 真 TLS：面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 allow_insecure=1）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。改 SNI 后证书要重建，旧链接失效。';
  if (p === 'anytls') return 'AnyTLS 是 TCP + 真 TLS：面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。改 SNI 后证书要重建，旧链接失效。';
  if (p === 'naive') return 'Naive 的域名必须是真实域名：CA 证书上的名字就是它，且要解析到这台服务器。改域名后要重新上传对应证书，旧链接失效。';
  if (p === 'vless') return (mode === 'ws' || mode === 'h2' || mode === 'httpupgrade') ? 'VLESS TLS 档的域名就是链接里的地址，必须解析到这台服务器；面板按这个域名生成自签证书，客户端要允许不验证证书。改域名后证书要重建，旧链接失效。' : 'VLESS 改伪装域名时目标地址会跟着换，除非你之前手动改过它。';
  if (p === 'vmess') return (mode && mode !== 'tcp') ? 'VMess 直连档的域名就是链接里的地址（HTTP 档除外：HTTP 档链接地址是服务器 IP，域名只做 Host 头），TLS 档面板按这个域名生成自签证书，客户端要允许不验证证书。CF 档的域名在下方传输方式里改。' : 'VMess TCP 档不需要域名。';
  if (p === 'trojan') return mode === 'cf' ? 'Trojan CF 档的域名在下方传输方式里改。' : (mode === 'h2' || mode === 'httpupgrade') ? 'Trojan TLS 档的域名就是链接里的地址，必须解析到这台服务器；面板按这个域名生成自签证书，客户端要允许不验证证书。改域名后证书要重建，旧链接失效。' : 'Trojan Reality 档改伪装域名时目标地址会跟着换，除非你之前手动改过它；CF 档的域名在下方传输方式里改。';
  return 'VLESS 改伪装域名时目标地址会跟着换，除非你之前手动改过它。';
}
function openEditNodeModal(id){
  const n = nodeById(id);
  if (!n) return;
  let cfg = null;
  try { cfg = n.config ? JSON.parse(n.config) : null; } catch(e){}
  cfg = cfg || {};
  const qGB = n.quota_bytes ? (n.quota_bytes / 1073741824).toFixed(2).replace(/\.00$/, '') : '';
  let adv = '';
  if (n.protocol === 'vless'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>传输方式</label><select id="eVlessMode"><option value="reality" ${(!cfg.mode || cfg.mode === 'reality') ? 'selected' : ''}>Reality + TCP</option><option value="ws" ${cfg.mode === 'ws' ? 'selected' : ''}>WS + TLS</option><option value="h2" ${cfg.mode === 'h2' ? 'selected' : ''}>H2 + TLS</option><option value="httpupgrade" ${cfg.mode === 'httpupgrade' ? 'selected' : ''}>HTTPUpgrade + TLS</option></select></div>
      <div><label>路径（TLS 档）</label><input id="eVlessPath" value="${escAttr(cfg.path || '')}" placeholder="留空自动生成"></div>
      <div><label>UUID</label><input id="eUuid" value="${escAttr(cfg.uuid || '')}" placeholder="留空保持原值"></div>
      <div><label>流控（Reality 档）</label><select id="eFlow"><option value="xtls-rprx-vision" ${cfg.flow === 'xtls-rprx-vision' ? 'selected' : ''}>xtls-rprx-vision</option><option value="" ${!cfg.flow ? 'selected' : ''}>无</option></select></div>
      <div><label>目标地址（dest，Reality 档）</label><input id="eDest" value="${escAttr(cfg.dest || '')}" placeholder="留空保持原值"></div>
      <div><label>ShortId（Reality 档）</label><input id="eShortId" value="${escAttr(cfg.short_id || '')}" placeholder="留空保持原值"></div>
      <div><label>客户端指纹</label><select id="eFp">${['chrome','firefox','safari','random'].map(f => `<option value="${f}" ${cfg.fingerprint === f ? 'selected' : ''}>${f}</option>`).join('')}</select></div>
      <div><label>SpiderX</label><input id="eSpiderX" value="${escAttr(cfg.spider_x || '/')}"></div>
      <div><label>监听地址</label><input id="eListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'hy2'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>密码</label><input id="eHPass" value="" placeholder="留空保持原值"></div>
      <div><label>混淆类型</label><select id="eHObfs"><option value="" ${!cfg.obfs_type ? 'selected' : ''}>无</option><option value="salamander" ${cfg.obfs_type === 'salamander' ? 'selected' : ''}>salamander</option></select></div>
      <div><label>混淆密码</label><input id="eHObfsPass" value="" placeholder="留空保持原值"></div>
      <div><label>上行限速（Mbps，留空不限）</label><input id="eHUp" value="${escAttr(cfg.up_mbps || '')}"></div>
      <div><label>下行限速（Mbps，留空不限）</label><input id="eHDown" value="${escAttr(cfg.down_mbps || '')}"></div>
      <div><label>监听地址</label><input id="eHListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
      <div><label><input type="checkbox" id="eHHop" ${cfg.hop_ports ? 'checked' : ''} onchange="document.getElementById('eHHopPorts').disabled=!this.checked"> 端口跳跃（默认关）</label></div>
      <div><label>跳跃端口段</label><input id="eHHopPorts" value="${escAttr(cfg.hop_ports || '')}" placeholder="如 20000-40000" ${cfg.hop_ports ? '' : 'disabled'}></div>
      <div class="full muted">开启后内核把该 UDP 段的流量转发到本节点端口，客户端按段内跳端口连接；不开启的客户端仍走主端口。云厂商安全组里也要放行这段 UDP（面板改不了安全组）。</div>
    </div></details>`;
  } else if (n.protocol === 'vmess'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>UUID</label><input id="eVUuid" value="${escAttr(cfg.uuid || '')}" placeholder="留空保持原值"></div>
      <div><label>传输方式</label><select id="eVMode">${[['tcp','TCP 直连'],['cf','WS + Cloudflare'],['http','HTTP 明文'],['quic','QUIC + TLS'],['h2','H2 + TLS'],['httpupgrade','HTTPUpgrade + TLS']].map(([v, t]) => `<option value="${v}" ${(cfg.mode || 'tcp') === v ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
      <div><label>域名（非 TCP 档）</label><input id="eVDomain" value="${escAttr(cfg.domain || n.sni || '')}" placeholder="CF/TLS 档必填，直连档就是 SNI"></div>
      <div><label>路径（CF/HTTP/H2/HTTPUpgrade 档）</label><input id="eVPath" value="${escAttr(cfg.path || '')}" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eVListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'ss'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>加密方法</label><select id="eSSMethod">${['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','aes-256-gcm','chacha20-ietf-poly1305'].map(m => `<option value="${m}" ${cfg.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select></div>
      <div><label>密码</label><input id="eSSPass" value="" placeholder="留空保持原值（换方法时留空自动生成对应密钥）"></div>
      <div><label>监听地址</label><input id="eSListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'socks'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eSKUser" value="${escAttr(cfg.user || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eSKPass" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eSKListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'http'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eHTUser" value="${escAttr(cfg.user || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eHTPass" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eHTListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'trojan'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>密码</label><input id="eTPass" value="" placeholder="留空保持原值"></div>
      <div><label>传输方式</label><select id="eTMode">${[['reality','Reality 直连'],['cf','WS + Cloudflare'],['h2','H2 + TLS'],['httpupgrade','HTTPUpgrade + TLS']].map(([v, t]) => `<option value="${v}" ${(cfg.mode || 'reality') === v ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
      <div><label>域名（CF/TLS 档）</label><input id="eTDomain" value="${escAttr(cfg.domain || n.sni || '')}" placeholder="CF/TLS 档必填"></div>
      <div><label>路径（CF/TLS 档）</label><input id="eTPath" value="${escAttr(cfg.path || '')}" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eTListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'wireguard'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>客户端地址</label><input id="eWGIP" value="${escAttr(cfg.client_ip || '')}" placeholder="如 10.0.0.2/32，留空保持原值"></div>
      <div><label>监听地址</label><input id="eWGListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details><div class="hint">密钥建节点时已生成，编辑不换密钥；要换密钥就删了重建（克隆也会换全套密钥）。</div>`;
  } else if (n.protocol === 'tuic'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>UUID</label><input id="eTUuid" value="${escAttr(cfg.uuid || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eTPw" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eTListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'anytls'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eAName" value="${escAttr(cfg.name || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eAPw" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eAListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details>`;
  } else if (n.protocol === 'naive'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>用户名</label><input id="eNUser" value="${escAttr(cfg.username || '')}" placeholder="留空保持原值"></div>
      <div><label>密码</label><input id="eNPw" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eNListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details><div class="hint">证书在节点菜单“上传 CA 证书”里换；换域名后要重新上传对应证书。</div>`;
  } else if (n.protocol === 'snell'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>版本</label><select id="eSnVersion"><option value="5" ${(cfg.version || 5) === 5 ? 'selected' : ''}>v5（默认）</option><option value="6" ${cfg.version === 6 ? 'selected' : ''}>v6</option></select></div>
      <div><label>PSK</label><input id="eSnPsk" value="" placeholder="留空保持原值"></div>
      <div><label>混淆（v5）</label><select id="eSnObfs"><option value="http" ${(cfg.obfs_mode || 'http') === 'http' ? 'selected' : ''}>http</option><option value="none" ${cfg.obfs_mode === 'none' ? 'selected' : ''}>none</option></select></div>
      <div><label>混淆 Host（v5）</label><input id="eSnObfsHost" value="${escAttr(cfg.obfs_host || '')}" placeholder="留空随机推荐"></div>
      <div><label>流量整形（v6）</label><select id="eSnMode">${['default','unshaped','unsafe-raw'].map(m => `<option value="${m}" ${(cfg.mode || 'default') === m ? 'selected' : ''}>${m}</option>`).join('')}</select></div>
      <div><label>监听地址</label><input id="eSnListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details><div class="hint">切到 v6 时 PSK 必须是 12-255 字节，太短会报错；v5 的混淆只在 v5 生效。</div>`;
  } else if (n.protocol === 'shadowtls'){
    adv = `<details class="adv"><summary>高级配置</summary><div class="form-grid">
      <div><label>握手站域名</label><div class="input-row"><input id="eStHandshake" value="${escAttr(cfg.handshake || '')}" placeholder="默认 gateway.icloud.com"><button class="btn ghost small" onclick="randomHandshake('eStHandshake')">随机</button></div></div>
      <div><label>密码</label><input id="eStPass" value="" placeholder="留空保持原值"></div>
      <div><label>监听地址</label><input id="eStListen" value="${escAttr(cfg.listen || '')}" placeholder="留空保持原值"></div>
    </div></details><div class="hint">内层 SS 的密码和回环端口由面板管理，编辑不改；strict 模式固定开启。</div>`;
  }
  const noSni = ['vmess', 'ss', 'socks', 'http', 'wireguard', 'dokodemo', 'snell', 'shadowtls'].includes(n.protocol);
  openModal(`<h4>编辑节点：${escHtml(n.name)}</h4>
    <div class="hint" style="margin:0 0 12px;color:var(--primary);font-weight:600">${escHtml(protoFull(n.protocol, cfg))}</div>
    <div class="form-grid">
      <div><label>节点名</label><input id="eName" value="${escAttr(n.name)}"></div>
      <div><label>节点IP</label><input id="eAddr" value="${escAttr(n.address)}"></div>
      <div><label>端口</label><input id="ePort" type="number" value="${n.port}"></div>
      ${noSni ? '' : `<div><label>${sniLabel(n.protocol, cfg.mode)}</label><input id="eSni" value="${escAttr(n.sni)}"></div>`}
    </div>
    <div class="hint">${sniHintEdit(n.protocol, cfg.mode)}</div>
    ${adv}
    <details class="adv"><summary>流量限额设置</summary><div class="form-grid">
      <div><label>限额模式</label><select id="eQMode"><option value="" ${!n.quota_mode ? 'selected' : ''}>不限</option><option value="total" ${n.quota_mode === 'total' ? 'selected' : ''}>总流量（上下行合计）</option><option value="down" ${n.quota_mode === 'down' ? 'selected' : ''}>下行总流量（只计出口）</option></select></div>
      <div><label>限额（G，面板的 GB）</label><input id="eQGB" type="number" step="any" value="${escAttr(qGB)}" placeholder="如 1000"></div>
    </div><div class="hint">服务器单项计算流量的，填“下行总流量”。达到限额前 1G 自动停用（填 1000G，到 999G 停），停了手动再开。</div></details>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="editSaveBtn" onclick="saveEditNode('${escAttr(id)}')">保存修改</button></div>
    <div class="msg" id="editMsg"></div>`, true);
}
async function saveEditNode(id){
  const btn = $('editSaveBtn'); btn.disabled = true;
  const port = parseInt($('ePort').value, 10);
  const n = nodeById(id);
  const body = {
    name: $('eName').value.trim(),
    address: $('eAddr').value.trim(),
    port: isNaN(port) ? undefined : port,
    sni: $('eSni') ? $('eSni').value.trim() : undefined,
    advanced: {},
  };
  if (n && n.protocol === 'vless'){
    const adv = {};
    if ($('eUuid').value.trim()) adv.uuid = $('eUuid').value.trim();
    adv.mode = $('eVlessMode').value;
    if ($('eVlessPath').value.trim()) adv.path = $('eVlessPath').value.trim();
    adv.flow = $('eFlow').value;
    if ($('eDest').value.trim()) adv.dest = $('eDest').value.trim();
    if ($('eShortId').value.trim()) adv.short_id = $('eShortId').value.trim();
    adv.fingerprint = $('eFp').value;
    adv.spider_x = $('eSpiderX').value || '/';
    if ($('eListen').value.trim()) adv.listen = $('eListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'hy2'){
    const adv = {};
    if ($('eHPass').value.trim()) adv.password = $('eHPass').value.trim();
    adv.obfs_type = $('eHObfs').value;
    if ($('eHObfsPass').value.trim()) adv.obfs_password = $('eHObfsPass').value.trim();
    adv.up_mbps = $('eHUp').value.trim();
    adv.down_mbps = $('eHDown').value.trim();
    if ($('eHHop')) adv.hop_ports = $('eHHop').checked ? $('eHHopPorts').value.trim() : '';
    if ($('eHListen').value.trim()) adv.listen = $('eHListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'vmess'){
    const adv = {};
    if ($('eVUuid').value.trim()) adv.uuid = $('eVUuid').value.trim();
    adv.mode = $('eVMode').value;
    if ($('eVPath').value.trim()) adv.path = $('eVPath').value.trim();
    if ($('eVListen').value.trim()) adv.listen = $('eVListen').value.trim();
    body.advanced = adv;
    body.sni = adv.mode === 'tcp' ? '' : $('eVDomain').value.trim();
  } else if (n && n.protocol === 'ss'){
    const adv = { method: $('eSSMethod').value };
    if ($('eSSPass').value.trim()) adv.password = $('eSSPass').value.trim();
    if ($('eSListen').value.trim()) adv.listen = $('eSListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'socks'){
    const adv = {};
    if ($('eSKUser').value.trim()) adv.user = $('eSKUser').value.trim();
    if ($('eSKPass').value.trim()) adv.pass = $('eSKPass').value.trim();
    if ($('eSKListen').value.trim()) adv.listen = $('eSKListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'http'){
    const adv = {};
    if ($('eHTUser').value.trim()) adv.user = $('eHTUser').value.trim();
    if ($('eHTPass').value.trim()) adv.pass = $('eHTPass').value.trim();
    if ($('eHTListen').value.trim()) adv.listen = $('eHTListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'trojan'){
    const adv = {};
    if ($('eTPass').value.trim()) adv.password = $('eTPass').value.trim();
    adv.mode = $('eTMode').value;
    if ($('eTPath').value.trim()) adv.path = $('eTPath').value.trim();
    if ($('eTListen').value.trim()) adv.listen = $('eTListen').value.trim();
    body.advanced = adv;
    body.sni = (adv.mode === 'cf' || adv.mode === 'h2' || adv.mode === 'httpupgrade') ? $('eTDomain').value.trim() : $('eSni') ? $('eSni').value.trim() : undefined;
  } else if (n && n.protocol === 'wireguard'){
    const adv = {};
    if ($('eWGIP').value.trim()) adv.client_ip = $('eWGIP').value.trim();
    if ($('eWGListen').value.trim()) adv.listen = $('eWGListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'tuic'){
    const adv = {};
    if ($('eTUuid').value.trim()) adv.uuid = $('eTUuid').value.trim();
    if ($('eTPw').value.trim()) adv.password = $('eTPw').value.trim();
    if ($('eTListen').value.trim()) adv.listen = $('eTListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'anytls'){
    const adv = {};
    if ($('eAName').value.trim()) adv.name = $('eAName').value.trim();
    if ($('eAPw').value.trim()) adv.password = $('eAPw').value.trim();
    if ($('eAListen').value.trim()) adv.listen = $('eAListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'naive'){
    const adv = {};
    if ($('eNUser').value.trim()) adv.username = $('eNUser').value.trim();
    if ($('eNPw').value.trim()) adv.password = $('eNPw').value.trim();
    if ($('eNListen').value.trim()) adv.listen = $('eNListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'snell'){
    const adv = { version: parseInt($('eSnVersion').value, 10) };
    if ($('eSnPsk').value.trim()) adv.psk = $('eSnPsk').value.trim();
    adv.obfs_mode = $('eSnObfs').value;
    if ($('eSnObfsHost').value.trim()) adv.obfs_host = $('eSnObfsHost').value.trim();
    adv.mode = $('eSnMode').value;
    if ($('eSnListen').value.trim()) adv.listen = $('eSnListen').value.trim();
    body.advanced = adv;
  } else if (n && n.protocol === 'shadowtls'){
    const adv = {};
    if ($('eStHandshake').value.trim()) adv.handshake = $('eStHandshake').value.trim();
    if ($('eStPass').value.trim()) adv.password = $('eStPass').value.trim();
    if ($('eStListen').value.trim()) adv.listen = $('eStListen').value.trim();
    body.advanced = adv;
  }
  const qMode = $('eQMode') ? $('eQMode').value : '';
  const qGB = $('eQGB') ? parseFloat($('eQGB').value) : NaN;
  body.quota_mode = qMode;
  body.quota_bytes = qMode && !isNaN(qGB) && qGB > 0 ? Math.round(qGB * 1073741824) : 0;
  try {
    await api('/api/inbounds/' + encodeURIComponent(id), 'PUT', body);
    toast('节点配置已保存'); closeModal();
    await refreshStatus(); await loadChains();
  } catch(e){
    $('editMsg').className = 'msg err'; $('editMsg').textContent = e.message;
    btn.disabled = false;
  }
}
function resetNodeTraffic(id){
  const n = nodeById(id);
  if (!n) return;
  confirmModal('重置流量', `确定重置 <b>${escHtml(n.name)}</b> 的流量吗？累计流量和今日流量都会清零。`, '确认重置', async ()=>{
    await api('/api/inbounds/' + encodeURIComponent(id) + '/reset-traffic', 'POST', {});
    toast('流量已重置'); refreshStatus();
  });
}
async function toggleNode(id, enable){
  try {
    await api('/api/inbounds/' + encodeURIComponent(id), 'PUT', { enabled: enable });
    const list = await api('/api/inbounds');
    NODES = Array.isArray(list) ? list : [];
    renderLocalRows();
    refreshStatus();
  }
  catch(e){ toast(e.message, true); try { const list = await api('/api/inbounds'); NODES = Array.isArray(list) ? list : []; } catch(_){} renderLocalRows(); }
}
function delNode(id){
  const n = nodeById(id);
  if (!n) return;
  confirmModal('删除节点', `确定删除 <b>${escHtml(n.name)}</b> 吗？配置、累计用量以及绑定它的链式分流规则都会一起删掉。`, '确认删除', async ()=>{
    await api('/api/inbounds/' + encodeURIComponent(id), 'DELETE');
    toast('节点已删除'); refreshStatus(); loadChains();
  });
}

// ---------- add inbound (popup) ----------
function addFormHTML(){
  return `<h4>新建代理入站</h4>
    <div class="tabs" id="protoTabs">
      <button data-proto="vless" class="on" onclick="setProto('vless')">VLESS<span class="tab-star">★</span></button>
      <button data-proto="hy2" onclick="setProto('hy2')">Hysteria2<span class="tab-star">★</span></button>
      <button data-proto="vmess" onclick="setProto('vmess')">VMess</button>
      <button data-proto="trojan" onclick="setProto('trojan')">Trojan</button>
      <button data-proto="tuic" onclick="setProto('tuic')">TUIC</button>
      <button data-proto="anytls" onclick="setProto('anytls')">AnyTLS</button>
      <button data-proto="naive" onclick="setProto('naive')">Naive</button>
      <button data-proto="snell" onclick="setProto('snell')">Snell</button>
      <button data-proto="shadowtls" onclick="setProto('shadowtls')">ShadowTLS</button>
      <button data-proto="ss" onclick="setProto('ss')">SS</button>
      <button data-proto="socks" onclick="setProto('socks')">SOCKS</button>
      <button data-proto="http" onclick="setProto('http')">HTTP</button>
      <button data-proto="wireguard" onclick="setProto('wireguard')">WireGuard</button>
    </div>
    <div class="hint" id="protoStack" style="margin:0 0 14px;color:var(--primary);font-weight:600">默认 · VLESS + Reality + TCP + xtls-rprx-vision</div>
    <div class="form-grid">
      <div>
        <label>监听端口</label>
        <div class="input-row">
          <input id="fPort" type="number" placeholder="留空自动建议" oninput="checkPort443Warning()">
          <button class="btn ghost small" onclick="fillSuggestPort()">自动建议</button>
        </div>
        <div class="hint" id="portHint"></div>
      </div>
      <div id="sniRow">
        <label id="sniLabel">伪装域名（Reality SNI）</label>
        <div class="input-row">
          <input id="fSni" placeholder="留空自动推荐">
          <button class="btn ghost small" onclick="randomSni()">换一个</button>
        </div>
        <div class="hint" id="sniHint">默认从精选清单里推荐，点“换一个”随机换。</div>
      </div>
      <div>
        <label>节点备注名</label>
        <input id="fName" placeholder="留空自动生成，如 VLESS-8443">
      </div>
      <div>
        <label>节点连接 IP</label>
        <input id="fAddr" placeholder="留空自动取公网 IP">
      </div>
    </div>
    <div id="vlessOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>传输方式</label><select id="vlMode" onchange="setProto('vless')">
          <option value="reality">Reality + TCP（默认，和 Trojan 同套）</option>
          <option value="ws">WS + TLS</option>
          <option value="h2">H2 + TLS</option>
          <option value="httpupgrade">HTTPUpgrade + TLS</option>
        </select></div>
        <div id="vlPathRow" style="display:none"><label>路径</label><input id="vlPath" placeholder="留空自动生成"></div>
      </div>
      <div class="hint" id="vlHint" style="display:none">TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书（链接里 allowInsecure=1）。</div>
    </div>
    <div id="vmessOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>传输方式</label><select id="vMode" onchange="setProto('vmess')">
          <option value="tcp">TCP 直连</option>
          <option value="cf">WS + Cloudflare（域名套 CF）</option>
          <option value="http">HTTP 明文</option>
          <option value="quic">QUIC + TLS</option>
          <option value="h2">H2 + TLS</option>
          <option value="httpupgrade">HTTPUpgrade + TLS</option>
        </select></div>
        <div id="vDomainRow" style="display:none"><label id="vDomainLabel">域名（已接入 Cloudflare，橙色云朵）</label><input id="vDomain" placeholder="如 example.com，必填"></div>
        <div id="vPathRow" style="display:none"><label>路径</label><input id="vPath" placeholder="留空自动生成"></div>
      </div>
      <div class="hint" id="vHint" style="display:none">CF 模式：访客连 CF:源站端口，CF 按同端口转发到源站（所以链接端口就是源站端口，不是 443）；域名必须已接入 CF（橙色云朵）并解析到这台服务器 IP；源站端口必须是 CF 允许的端口（443/2053/2083/2087/2096/8443）。源站是 WS+TLS 自签证书：区 SSL 模式是 Full 才能用（Strict 不接受自签，得用源站证书，面板暂不支持）。没有 CF 域名就用 TCP 直连。</div>
      <div class="hint" id="vTlsHint" style="display:none">TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书。QUIC 档没有路径。</div>
      <div class="hint" id="vHttpHint" style="display:none">HTTP 档是明文 HTTP 传输：链接地址是服务器 IP，域名只做 Host 头约束（客户端发这个 Host 才能连上）。</div>
    </div>
    <div id="ssOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>加密方法</label><select id="ssMethod">
          <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm（默认，最新）</option>
          <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
          <option value="aes-256-gcm">aes-256-gcm（兼容最广）</option>
          <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
        </select></div>
        <div><label>密码</label><input id="ssPass" placeholder="留空自动生成（2022 方法自动生成对应长度密钥）"></div>
      </div>
    </div>
    <div id="socksOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>用户名</label><input id="skUser" placeholder="留空自动生成"></div>
        <div><label>密码</label><input id="skPass" placeholder="留空自动生成"></div>
      </div>
      <div class="hint">SOCKS5 带账号密码，UDP 转发已开启。</div>
    </div>
    <div id="httpOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>用户名</label><input id="htUser" placeholder="留空自动生成"></div>
        <div><label>密码</label><input id="htPass" placeholder="留空自动生成"></div>
      </div>
      <div class="hint">HTTP 代理带账号密码，客户端用 HTTP 代理或 CONNECT 方式走它。</div>
    </div>
    <div id="trojanOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>传输方式</label><select id="tMode" onchange="setProto('trojan')">
          <option value="reality">Reality 直连（默认，和 VLESS 同套）</option>
          <option value="cf">WS + Cloudflare（域名套 CF）</option>
          <option value="h2">H2 + TLS</option>
          <option value="httpupgrade">HTTPUpgrade + TLS</option>
        </select></div>
        <div><label>密码</label><input id="tPass" placeholder="留空自动生成"></div>
        <div id="tDomainRow" style="display:none"><label id="tDomainLabel">域名（已接入 Cloudflare，橙色云朵）</label><input id="tDomain" placeholder="如 example.com，必填"></div>
        <div id="tPathRow" style="display:none"><label>路径</label><input id="tPath" placeholder="留空自动生成"></div>
      </div>
      <div class="hint" id="tHint" style="display:none">CF 模式和 VMess CF 同机制：访客连 CF:源站端口，源站 WS+TLS 自签证书，区 SSL 模式要是 Full（Strict 不接受自签）。</div>
      <div class="hint" id="tTlsHint" style="display:none">TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书。</div>
    </div>
    <div id="tuicOpts" style="display:none">
      <div class="hint" style="margin-top:12px">TUIC 走 QUIC/UDP + 真 TLS：面板按伪装域名生成自签证书，客户端握手时 SNI 就是它（链接里 allow_insecure=1）。拥塞算法固定 bbr，零 RTT 默认关闭（防重放）。</div>
    </div>
    <div id="anytlsOpts" style="display:none">
      <div class="hint" style="margin-top:12px">AnyTLS 走 TCP + 真 TLS：面板按伪装域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1）。抗封锁思路和 Trojan 类似，但协议更轻。</div>
    </div>
    <div id="naiveOpts" style="display:none">
      <div class="hint" style="margin-top:12px">Naive 是 Chromium 真浏览器网络栈的代理，抗封锁最像正常浏览，但必须用真实域名 + CA 证书（自签不行）。建好节点后，在节点菜单里“上传 CA 证书”，上传后节点才能启动；链接交付的是参考客户端 JSON 配置，不是 URL。</div>
    </div>
    <div id="snellOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>版本</label><select id="snVersion" onchange="setProto('snell')">
          <option value="5">v5（默认，稳定，客户端支持最广）</option>
          <option value="6">v6（流量整形内置，还是 beta）</option>
        </select></div>
        <div><label>PSK（密码）</label><input id="snPsk" placeholder="留空自动生成"></div>
        <div id="snObfsRow"><label>混淆</label><select id="snObfs" onchange="setProto('snell')">
          <option value="http">http（默认，伪装成普通 HTTP）</option>
          <option value="none">none（不混淆）</option>
        </select></div>
        <div id="snObfsHostRow"><label>混淆 Host</label><input id="snObfsHost" placeholder="留空随机推荐"></div>
        <div id="snModeRow" style="display:none"><label>流量整形（v6）</label><select id="snMode">
          <option value="default">default（加密 + 整形，默认）</option>
          <option value="unshaped">unshaped（只加密，不整形）</option>
          <option value="unsafe-raw">unsafe-raw（不加密，仅调试）</option>
        </select></div>
      </div>
      <div class="hint">Snell 是 Surge 的轻量协议，走 TCP。v5 用 HTTP 混淆防特征识别；v6 把混淆换成 PSK 派生的流量整形，PSK 必须是 12-255 字节。UDP 中继 v3 以上自动支持，不用配。</div>
    </div>
    <div id="shadowtlsOpts" style="display:none">
      <div class="form-grid" style="margin-top:12px">
        <div><label>握手站域名</label><div class="input-row"><input id="stHandshake" placeholder="默认 gateway.icloud.com"><button class="btn ghost small" onclick="randomHandshake('stHandshake')">随机</button></div></div>
        <div><label>密码</label><input id="stPass" placeholder="留空自动生成"></div>
      </div>
      <div class="hint">ShadowTLS v3 + 内层 SS2022：握手直接转发给握手站（真证书、真页面，主动探测看到的是真站），strict 模式强制开；内层 SS 的密码和回环端口由面板自动配好，不对外暴露。分享链接为面板自定 shadowtls:// 格式（可直接粘贴到另一台面板做 B 节点）；通用客户端请使用 Sing-box JSON 或 Clash YAML 订阅。</div>
    </div>
    <div id="wgOpts" style="display:none">
      <div class="hint" style="margin-top:12px">WireGuard 走 UDP：面板给每个节点生成两对密钥（服务端一对、客户端一对），客户端公钥直接写进服务端，建好就能用。创建成功后在节点行“链接”里复制完整配置，贴进官方 WireGuard 客户端（或扫二维码）。</div>
    </div>

    <details class="adv" id="advVless">
      <summary>高级配置</summary>
      <div class="form-grid">
        <div><label>UUID</label><div class="input-row"><input id="aUuid" placeholder="留空自动生成"><button class="btn ghost small" onclick="document.getElementById('aUuid').value=uuidv4()">随机</button></div></div>
        <div><label>流控</label><select id="aFlow"><option value="xtls-rprx-vision">xtls-rprx-vision</option><option value="">无</option></select></div>
        <div><label>目标地址（dest）</label><input id="aDest" placeholder="留空跟随伪装域名，如 www.samsung.com:443"></div>
        <div><label>ShortId</label><input id="aShortId" placeholder="留空自动生成"></div>
        <div><label>客户端指纹</label><select id="aFp"><option value="chrome">chrome</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="random">random</option></select></div>
        <div><label>SpiderX</label><input id="aSpiderX" value="/" placeholder="/"></div>
        <div><label>监听地址</label><input id="aListen" placeholder="默认 0.0.0.0"></div>
      </div>
    </details>
    <details class="adv" id="advHy2" style="display:none">
      <summary>高级配置</summary>
      <div class="form-grid">
        <div><label>密码</label><input id="hPass" placeholder="留空自动生成"></div>
        <div><label>混淆类型</label><select id="hObfs"><option value="">无</option><option value="salamander">salamander</option></select></div>
        <div><label>混淆密码</label><input id="hObfsPass" placeholder="混淆类型选 salamander 时填写"></div>
        <div><label>上行限速（Mbps，留空不限）</label><input id="hUp" placeholder="如 100"></div>
        <div><label>下行限速（Mbps，留空不限）</label><input id="hDown" placeholder="如 100"></div>
        <div><label>监听地址</label><input id="hListen" placeholder="默认全部地址"></div>
        <div><label><input type="checkbox" id="hHop" onchange="document.getElementById('hHopPorts').disabled=!this.checked"> 端口跳跃（默认关）</label></div>
        <div><label>跳跃端口段</label><input id="hHopPorts" placeholder="如 20000-40000" disabled></div>
        <div class="full muted">开启后内核把该 UDP 段的流量转发到本节点端口，客户端按段内跳端口连接；不开启的客户端仍走主端口。云厂商安全组里也要放行这段 UDP（面板改不了安全组）。</div>
      </div>
    </details>

    <details class="adv"><summary>流量限额设置</summary><div class="form-grid">
      <div><label>限额模式</label><select id="qMode"><option value="">不限</option><option value="total">总流量（上下行合计）</option><option value="down">下行总流量（只计出口）</option></select></div>
      <div><label>限额（G，面板的 GB）</label><input id="qGB" type="number" step="any" placeholder="如 1000"></div>
    </div><div class="hint">服务器单项计算流量的，填“下行总流量”。达到限额前 1G 自动停用（填 1000G，到 999G 停），停了手动再开。</div></details>

    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="btnCreate" onclick="createInbound()">创建节点</button></div>
    <div class="msg" id="createMsg"></div>`;
}
function openAddModal(){
  CUR_PROTO = 'vless';
  openModal(addFormHTML(), true);
  fillSuggestPort(true);
}
function setProto(p){
  CUR_PROTO = p;
  document.querySelectorAll('#protoTabs button').forEach(b => b.classList.toggle('on', b.dataset.proto === p));
  $('advVless').style.display = p === 'vless' ? '' : 'none';
  $('advHy2').style.display = p === 'hy2' ? '' : 'none';
  const vlessMode = p === 'vless' ? $('vlMode').value : '';
  const trojanMode = p === 'trojan' ? $('tMode').value : '';
  const trojanDomain = p === 'trojan' && trojanMode !== 'reality';
  $('sniRow').style.display = (p === 'vless' || p === 'hy2' || p === 'tuic' || p === 'anytls' || p === 'naive' || (p === 'trojan' && !trojanDomain)) ? '' : 'none';
  $('vlessOpts').style.display = p === 'vless' ? '' : 'none';
  $('vmessOpts').style.display = p === 'vmess' ? '' : 'none';
  $('trojanOpts').style.display = p === 'trojan' ? '' : 'none';
  $('tuicOpts').style.display = p === 'tuic' ? '' : 'none';
  $('anytlsOpts').style.display = p === 'anytls' ? '' : 'none';
  $('naiveOpts').style.display = p === 'naive' ? '' : 'none';
  $('snellOpts').style.display = p === 'snell' ? '' : 'none';
  $('shadowtlsOpts').style.display = p === 'shadowtls' ? '' : 'none';
  $('wgOpts').style.display = p === 'wireguard' ? '' : 'none';
  $('ssOpts').style.display = p === 'ss' ? '' : 'none';
  $('socksOpts').style.display = p === 'socks' ? '' : 'none';
  $('httpOpts').style.display = p === 'http' ? '' : 'none';
  if (p === 'vless'){
    const tls = vlessMode !== 'reality';
    $('vlPathRow').style.display = tls ? '' : 'none';
    $('vlHint').style.display = tls ? '' : 'none';
    $('sniLabel').textContent = sniLabel('vless', vlessMode);
    $('fSni').placeholder = tls ? '留空用服务器 IP' : '留空自动推荐';
    $('protoStack').textContent = protoFull('vless', { mode: vlessMode, flow: $('aFlow') ? $('aFlow').value : 'xtls-rprx-vision' });
  } else if (p === 'vmess'){
    const mode = $('vMode').value;
    const cf = mode === 'cf';
    const tls = mode === 'quic' || mode === 'h2' || mode === 'httpupgrade';
    $('vDomainRow').style.display = mode === 'tcp' ? 'none' : '';
    $('vDomainLabel').textContent = cf ? '域名（已接入 Cloudflare，橙色云朵）' : (mode === 'http' ? '域名（HTTP Host 头）' : '域名（须解析到本机）');
    if (cf) $('vDomain').placeholder = '如 example.com，必填'; else if (tls) $('vDomain').placeholder = '留空用服务器 IP';
    $('vPathRow').style.display = (cf || mode === 'http' || mode === 'h2' || mode === 'httpupgrade') ? '' : 'none';
    $('vHint').style.display = cf ? '' : 'none';
    $('vTlsHint').style.display = tls ? '' : 'none';
    $('vHttpHint').style.display = mode === 'http' ? '' : 'none';
    $('protoStack').textContent = protoFull('vmess', { mode: mode });
  } else if (p === 'trojan'){
    $('tDomainRow').style.display = trojanDomain ? '' : 'none';
    $('tDomainLabel').textContent = trojanMode === 'cf' ? '域名（已接入 Cloudflare，橙色云朵）' : '域名（须解析到本机）';
    if (trojanMode === 'cf') $('tDomain').placeholder = '如 example.com，必填'; else if (trojanDomain) $('tDomain').placeholder = '留空用服务器 IP';
    $('tPathRow').style.display = trojanDomain ? '' : 'none';
    $('tHint').style.display = trojanMode === 'cf' ? '' : 'none';
    $('tTlsHint').style.display = (trojanMode === 'h2' || trojanMode === 'httpupgrade') ? '' : 'none';
    $('protoStack').textContent = protoFull('trojan', { mode: trojanMode });
  } else if (p === 'snell'){
    const ver = $('snVersion').value;
    const v6 = ver === '6';
    $('snObfsRow').style.display = v6 ? 'none' : '';
    $('snObfsHostRow').style.display = (v6 || $('snObfs').value !== 'http') ? 'none' : '';
    $('snModeRow').style.display = v6 ? '' : 'none';
    $('protoStack').textContent = protoFull('snell', { version: parseInt(ver, 10) });
  } else if (p === 'shadowtls'){
    $('protoStack').textContent = protoFull('shadowtls', null);
  } else {
    $('sniLabel').textContent = sniLabel(p);
    $('protoStack').textContent = protoFull(p, null);
  }
  $('sniHint').textContent = (p === 'hy2' || p === 'tuic' || p === 'anytls')
    ? '面板按这个域名生成自签证书，客户端握手时 SNI 就是它（链接里 insecure=1，证书不校验真伪）。不需要真实域名，也不需要把域名解析到服务器，留空会自动推荐一个。'
    : p === 'naive'
    ? 'Naive 的域名必须是真实域名：CA 证书上的名字就是它，且要解析到这台服务器。建好节点后在节点菜单里上传证书。'
    : p === 'vless' && vlessMode !== 'reality'
    ? 'TLS 档：填了域名，链接地址就是该域名（须解析到本机）；留空则链接地址用服务器 IP，同样能通。面板按域名生成自签证书，客户端要允许不验证证书。'
    : '默认从精选清单里推荐，点“换一个”随机换。';
  fillSuggestPort(true);
  checkPort443Warning();
}
function checkPort443Warning(){
  const h = $('portHint');
  if (!h) return;
  const p = parseInt($('fPort').value, 10);
  if ((CUR_PROTO === 'hy2' || CUR_PROTO === 'tuic') && p === 443){
    h.textContent = 'UDP443端口可能会被运营商拦截、阻断';
    h.style.color = 'var(--red)';
    h.dataset.warn = '1';
  } else if (h.dataset.warn === '1'){
    h.textContent = '';
    h.style.color = '';
    delete h.dataset.warn;
  }
}
async function fillSuggestPort(quiet){
  try {
    let q = '/api/suggest-port?protocol=' + encodeURIComponent(CUR_PROTO);
    if (CUR_PROTO === 'vmess' && $('vMode') && $('vMode').value === 'cf') q += '&mode=cf';
    if (CUR_PROTO === 'trojan' && $('tMode') && $('tMode').value === 'cf') q += '&mode=cf';
    const r = await api(q);
    $('fPort').value = r.port;
    $('portHint').textContent = r.reason;
    $('portHint').style.color = '';
    delete $('portHint').dataset.warn;
    checkPort443Warning();
  } catch(e){ if (!quiet) toast(e.message, true); }
}
async function randomSni(){
  try {
    const cur = $('fSni').value.trim();
    const r = await api('/api/sni-random?exclude=' + encodeURIComponent(cur));
    $('fSni').value = r.domain;
    $('sniHint').textContent = r.domain + '（' + r.label + '）';
  } catch(e){ toast(e.message, true); }
}
async function randomHandshake(id){
  try {
    const r = await api('/api/sni-random?exclude=gateway.icloud.com&exclude=bing.com');
    if (r && r.domain) document.getElementById(id).value = r.domain;
  } catch(e){ toast(e.message, true); }
}
async function createInbound(){
  const btn = $('btnCreate');
  btn.disabled = true; btn.textContent = '创建中…';
  $('createMsg').textContent = '';
  const needCore = { vless: 'sing-box', vmess: 'sing-box', ss: 'sing-box', socks: 'sing-box', http: 'sing-box', trojan: 'sing-box', wireguard: 'sing-box', hy2: 'sing-box', tuic: 'sing-box', anytls: 'sing-box', naive: 'sing-box', snell: 'sing-box', shadowtls: 'sing-box' }[CUR_PROTO];
  const coreRow = CORE_LIST.find(c => c.name === needCore);
  if (coreRow && !coreRow.installed){
    $('createMsg').className = 'msg err';
    $('createMsg').textContent = needCore + ' 内核还没安装：先去“系统概览”页的内核卡片安装 ' + needCore + '，装好再创建节点';
    btn.disabled = false; btn.textContent = '创建节点';
    return;
  }
  const port = parseInt($('fPort').value, 10);
  const qMode = $('qMode') ? $('qMode').value : '';
  const qGB = $('qGB') ? parseFloat($('qGB').value) : NaN;
  const body = {
    protocol: CUR_PROTO,
    port: isNaN(port) ? 0 : port,
    name: $('fName').value.trim(),
    address: $('fAddr').value.trim(),
    sni: $('fSni').value.trim(),
    advanced: {},
    quota_mode: qMode,
    quota_bytes: qMode && !isNaN(qGB) && qGB > 0 ? Math.round(qGB * 1073741824) : 0,
  };
  if (CUR_PROTO === 'vless'){
    const adv = {};
    if ($('aUuid').value.trim()) adv.uuid = $('aUuid').value.trim();
    adv.mode = $('vlMode').value;
    if ($('vlPath').value.trim()) adv.path = $('vlPath').value.trim();
    adv.flow = $('aFlow').value;
    if ($('aDest').value.trim()) adv.dest = $('aDest').value.trim();
    if ($('aShortId').value.trim()) adv.short_id = $('aShortId').value.trim();
    adv.fingerprint = $('aFp').value;
    adv.spider_x = $('aSpiderX').value || '/';
    if ($('aListen').value.trim()) adv.listen = $('aListen').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'hy2'){
    const adv = {};
    if ($('hPass').value.trim()) adv.password = $('hPass').value.trim();
    if ($('hObfs').value) adv.obfs_type = $('hObfs').value;
    if ($('hObfsPass').value.trim()) adv.obfs_password = $('hObfsPass').value.trim();
    if ($('hUp').value.trim()) adv.up_mbps = $('hUp').value.trim();
    if ($('hDown').value.trim()) adv.down_mbps = $('hDown').value.trim();
    if ($('hHop') && $('hHop').checked && $('hHopPorts').value.trim()) adv.hop_ports = $('hHopPorts').value.trim();
    if ($('hListen').value.trim()) adv.listen = $('hListen').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'vmess'){
    const mode = $('vMode').value;
    body.sni = mode === 'tcp' ? '' : $('vDomain').value.trim();
    body.advanced = { mode: mode, path: (mode === 'tcp' || mode === 'quic') ? '' : $('vPath').value.trim() };
  } else if (CUR_PROTO === 'trojan'){
    const mode = $('tMode').value;
    body.sni = mode === 'reality' ? $('fSni').value.trim() : $('tDomain').value.trim();
    const adv = { mode: mode, path: mode === 'reality' ? '' : $('tPath').value.trim() };
    if ($('tPass').value.trim()) adv.password = $('tPass').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'wireguard'){
    body.advanced = {};
  } else if (CUR_PROTO === 'snell'){
    const adv = { version: parseInt($('snVersion').value, 10) };
    if ($('snPsk').value.trim()) adv.psk = $('snPsk').value.trim();
    if (adv.version === 5){
      adv.obfs_mode = $('snObfs').value;
      if ($('snObfsHost').value.trim()) adv.obfs_host = $('snObfsHost').value.trim();
    } else {
      adv.mode = $('snMode').value;
    }
    body.advanced = adv;
  } else if (CUR_PROTO === 'shadowtls'){
    const adv = {};
    if ($('stHandshake').value.trim()) adv.handshake = $('stHandshake').value.trim();
    if ($('stPass').value.trim()) adv.password = $('stPass').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'tuic' || CUR_PROTO === 'anytls' || CUR_PROTO === 'naive'){
    body.advanced = {};
  } else if (CUR_PROTO === 'ss'){
    const adv = { method: $('ssMethod').value };
    if ($('ssPass').value.trim()) adv.password = $('ssPass').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'socks'){
    const adv = {};
    if ($('skUser').value.trim()) adv.user = $('skUser').value.trim();
    if ($('skPass').value.trim()) adv.pass = $('skPass').value.trim();
    body.advanced = adv;
  } else if (CUR_PROTO === 'http'){
    const adv = {};
    if ($('htUser').value.trim()) adv.user = $('htUser').value.trim();
    if ($('htPass').value.trim()) adv.pass = $('htPass').value.trim();
    body.advanced = adv;
  }
  try {
    const r = await api('/api/inbounds', 'POST', body);
    closeModal();
    const linkField = (CUR_PROTO === 'wireguard' || CUR_PROTO === 'naive')
      ? `<label>${CUR_PROTO === 'naive' ? 'Naive 配置（参考客户端 JSON 配置，不是 URL，别贴进 URL 导入框）' : 'WireGuard 配置（贴进官方客户端，或扫下方二维码）'}</label><textarea id="lkMain" readonly rows="11" style="width:100%" class="mono">${escHtml(r.link)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain')">复制配置</button></div>`
      : `<label>节点链接</label><div class="input-row"><input id="lkMain" readonly value="${escAttr(r.link)}"><button class="btn ghost small" onclick="copyText('lkMain')">复制</button></div>`;
    const link6Field = !r.link6 ? '' : (CUR_PROTO === 'wireguard' || CUR_PROTO === 'naive'
      ? `<div style="margin-top:12px"><label>${CUR_PROTO === 'wireguard' ? 'WireGuard 配置 IPv6' : 'Naive 配置 IPv6'}</label><textarea id="lkMain6" readonly rows="11" style="width:100%" class="mono">${escHtml(r.link6)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkMain6')">复制配置</button></div></div>`
      : `<div style="margin-top:12px"><label>节点链接 IPv6</label><div class="input-row"><input id="lkMain6" readonly value="${escAttr(r.link6)}"><button class="btn ghost small" onclick="copyText('lkMain6')">复制</button></div></div>`);
    openModal(`<h4>节点已创建：${escHtml(r.inbound.name)}</h4>
      ${linkField}
      ${link6Field}
      ${r.tme_link ? `<div style="margin-top:12px"><label>t.me 链接</label><div class="input-row"><input id="lkTme" readonly value="${escAttr(r.tme_link)}"><button class="btn ghost small" onclick="copyText('lkTme')">复制</button></div></div>` : ''}
      ${CUR_PROTO === 'naive' ? `<div class="hint" style="margin-top:12px">Naive 节点还没证书、暂时启动不了：去节点列表点节点行的 ⋮ → “上传 CA 证书”，上传后立即启动。</div>` : ''}
      <div class="qr-box"><img src="${escAttr((window.PANEL_BASE||'') + '/api/inbounds/' + encodeURIComponent(r.inbound.id) + '/qr')}" alt="二维码"></div>
      <div class="foot"><button class="btn" onclick="closeModal()">完成</button></div>`);
    await refreshStatus(); await loadChains();
  } catch(e){ $('createMsg').className = 'msg err'; $('createMsg').textContent = '创建失败：' + e.message; }
  btn.disabled = false; btn.textContent = '创建节点';
}

// ---------- chains & bnodes (多协议入口 A + 多 B 节点分流) ----------
async function loadChains(){
  try { const c = await api('/api/chains'); CHAINS = Array.isArray(c) ? c : []; } catch(e){ CHAINS = []; }
  try { const b = await api('/api/bnodes'); BNODES = Array.isArray(b) ? b : []; } catch(e){ BNODES = []; }
  try { const list = await api('/api/inbounds'); NODES = Array.isArray(list) ? list : []; } catch(e){}
  renderBNodeRows();
  renderChainRows();
  renderLocalRows();
}
function renderBNodeRows(){
  const el = $('bnodeRows');
  if (!el) return;
  if (!BNODES.length){ el.innerHTML = '<div class="empty">还没有外部节点，点击右上角“＋ 导入外部节点”粘贴其他服务器的节点链接</div>'; return; }
  el.innerHTML = BNODES.map(b => {
    const bid = escAttr(b.id);
    return `
    <div class="row">
      <button class="menu-btn" title="操作" onclick="openBNodeMenu(this,'${bid}')">⋮</button>
      <div class="grow"><div class="t">${escHtml(b.name)} ${protoBadge(b.protocol)}</div>
        <div class="s mono">${escHtml(b.link.slice(0, 90))}${b.link.length > 90 ? '…' : ''}</div></div>
      <span class="ping" id="bping-${bid}" title="本机到该节点服务器的延迟">测活中…</span>
    </div>`;
  }).join('');
  refreshBNodePing();
}
function openBNodeMenu(btn, id){
  const b = BNODES.find(x => x.id === id);
  if (!b) return;
  const bid = escAttr(id);
  openDropdown(btn, `
    <button onclick="closeDropdown();copyBNodeLink('${bid}')">${MI.copy}复制原始链接</button>
    <button class="danger" onclick="closeDropdown();delBNode('${bid}')">${MI.trash}删除外部节点</button>`);
}
function copyBNodeLink(id){
  const b = BNODES.find(x => x.id === id);
  if (b) copyText(null, b.link);
}
async function refreshBNodePing(){
  if (!$('view-inbounds') || !$('view-inbounds').classList.contains('on')) return;
  if (!BNODES.length) return;
  try {
    const rows = await api('/api/bnodes-latency');
    rows.forEach(r => {
      const el = $('bping-' + r.id);
      if (!el) return;
      if (r.kind === 'udp') el.textContent = 'UDP 协议不适用';
      else if (r.ms >= 0) el.textContent = r.ms + ' ms';
      else el.textContent = '不通';
    });
  } catch(e){}
}
function delBNode(id){
  const b = BNODES.find(x => x.id === id);
  if (!b) return;
  const used = CHAINS.filter(c => c.bnode_id === id || (c.routes || []).some(r => r.bnode_id === id));
  const warn = used.length ? `它正被 ${used.length} 条链式/分流规则引用，删除后对应分流组或链式规则将自动清理。` : '';
  confirmModal('删除外部节点', `确定删除 <b>${escHtml(b.name)}</b> 吗？${warn}`, '确认删除', async ()=>{
    await api('/api/bnodes/' + encodeURIComponent(id), 'DELETE');
    toast('已删除'); loadChains();
  });
}
function openAddBNodeModal(){
  openModal(`<h4>导入外部落地节点 (B 节点)</h4>
    <label>粘贴节点分享链接（自动识别协议）</label>
    <input id="bLink" placeholder="vless://、vmess://、trojan://、ss://、socks://、http://、hysteria2://、snell://、shadowtls://">
    <div class="hint">B 节点支持 9 种协议：VLESS、VMess、Trojan、SS、SOCKS、HTTP、Hysteria2、Snell、ShadowTLS。</div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="bSaveBtn" onclick="saveBNodeFromModal()">解析并保存</button></div>
    <div class="msg" id="bMsg"></div>`);
}
async function saveBNodeFromModal(){
  const link = $('bLink').value.trim();
  if (!link){ $('bMsg').className = 'msg err'; $('bMsg').textContent = '请先粘贴节点链接'; return; }
  const scheme = link.split('://')[0].toLowerCase();
  const okSchemes = ['vless', 'vmess', 'trojan', 'ss', 'socks', 'socks5', 'http', 'https', 'hysteria2', 'hy2', 'snell', 'shadowtls'];
  if (!okSchemes.includes(scheme)){
    $('bMsg').className = 'msg err';
    $('bMsg').textContent = '不支持的协议：' + scheme + '（B 节点只支持 VLESS/VMess/Trojan/SS/SOCKS/HTTP/Hysteria2/Snell/ShadowTLS）';
    return;
  }
  const btn = $('bSaveBtn'); btn.disabled = true;
  try {
    const r = await api('/api/bnodes', 'POST', { link });
    toast('已保存：' + r.name + '（' + r.protocol + '）');
    closeModal(); await loadChains();
  } catch(e){
    $('bMsg').className = 'msg err'; $('bMsg').textContent = '保存失败：' + e.message;
    btn.disabled = false;
  }
}

// 入口 A 节点下拉选项：支持除 WireGuard / dokodemo 外全部本机节点，已绑定的自动置灰防冲突
function chainAOptions(selectedId, excludeChainId){
  if (!NODES.length) return '<option value="">（暂无本地节点，请先新建入站）</option>';
  return NODES.map(n => {
    let dis = '', note = '';
    if (n.protocol === 'wireguard' || n.protocol === 'dokodemo'){
      dis = ' disabled';
      note = '（' + n.protocol.toUpperCase() + ' 不支持做入口 A）';
    } else {
      const usedBy = CHAINS.find(c => c.inbound_id === n.id && c.id !== excludeChainId);
      if (usedBy){ dis = ' disabled'; note = '（已有链式）'; }
    }
    const sel = n.id === selectedId ? ' selected' : '';
    return `<option value="${escAttr(n.id)}"${sel}${dis}>[${escHtml(n.protocol.toUpperCase())}] ${escHtml(n.name)} :${n.port}${note}</option>`;
  }).join('');
}

function bnodeOptions(selectedId, includeDirect){
  let html = includeDirect ? `<option value=""${!selectedId ? ' selected' : ''}>本机直连（默认）</option>` : '';
  if (!BNODES.length && !includeDirect) return '<option value="">（暂无外部节点，请先导入外部节点）</option>';
  html += BNODES.map(b => `<option value="${escAttr(b.id)}"${b.id === selectedId ? ' selected' : ''}>${escHtml(b.name)}（${escHtml(b.protocol)}）</option>`).join('');
  return html;
}

function renderSplitGroupHTML(bnodeId, listText){
  return `<div class="split-group" style="border:1px solid var(--line-subtle);border-radius:var(--r-md);padding:12px;margin-bottom:10px;background:rgba(248,250,252,.72)">
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
      <span class="sg-idx badge" style="flex:none">分流</span>
      <select class="sg-bnode" onchange="syncSplitSelects()" style="flex:1">${bnodeOptions(bnodeId || '', false)}</select>
      <button type="button" class="btn ghost sm" onclick="removeSplitGroup(this)">删除此组</button>
    </div>
    <textarea class="sg-list mono" rows="3" style="min-height:72px" placeholder="一行一个域名或 IP/CIDR（命中则走上方所选 B 节点落地），例如：&#10;openai.com&#10;netflix.com&#10;1.1.1.0/24">${escHtml(listText || '')}</textarea>
  </div>`;
}

// 实时同步组号与下拉防重：同一条链式规则中，已被其他分流组或兜底选中的 B 节点自动置灰
function syncSplitSelects(){
  const groups = [...document.querySelectorAll('#chRoutesBox .split-group')];
  groups.forEach((g, idx) => {
    const badge = g.querySelector('.sg-idx');
    if (badge) badge.textContent = 'B' + (idx + 1);
  });
  const selects = groups.map(g => g.querySelector('.sg-bnode'));
  const fallback = $('chFallbackB');
  const chosen = selects.map(s => s.value).filter(Boolean);
  selects.forEach(sel => {
    [...sel.options].forEach(opt => {
      if (!opt.value) return;
      opt.disabled = (opt.value !== sel.value && chosen.includes(opt.value)) || (fallback && fallback.value && fallback.value === opt.value);
    });
  });
  if (fallback){
    [...fallback.options].forEach(opt => {
      if (!opt.value) return;
      opt.disabled = chosen.includes(opt.value);
    });
  }
}

function addSplitGroup(bnodeId, listText){
  const box = $('chRoutesBox');
  if (!box) return;
  if (!bnodeId && BNODES.length){
    const used = new Set([...box.querySelectorAll('.sg-bnode')].map(s => s.value));
    if ($('chFallbackB') && $('chFallbackB').value) used.add($('chFallbackB').value);
    const free = BNODES.find(b => !used.has(b.id));
    if (free) bnodeId = free.id;
  }
  box.insertAdjacentHTML('beforeend', renderSplitGroupHTML(bnodeId || '', listText || ''));
  syncSplitSelects();
}

function removeSplitGroup(btn){
  const box = $('chRoutesBox');
  if (!box || box.querySelectorAll('.split-group').length <= 1){
    toast('多节点分流至少保留 1 个分流组', true);
    return;
  }
  btn.closest('.split-group').remove();
  syncSplitSelects();
}

function chModeChange(){
  const direct = document.querySelector('input[name="chMode"]:checked')?.value === 'direct';
  if ($('chDirectWrap')) $('chDirectWrap').style.display = direct ? '' : 'none';
  if ($('chSplitWrap')) $('chSplitWrap').style.display = direct ? 'none' : '';
}

function chainFormHTML(chain){
  const c = chain || {};
  const direct = chain ? c.mode === 'direct' : true;
  let initRoutes = [];
  if (!direct && Array.isArray(c.routes) && c.routes.length){
    initRoutes = c.routes;
  } else if (!direct && c.bnode_id && c.list){
    initRoutes = [{ bnode_id: c.bnode_id, list: c.list }];
  } else {
    initRoutes = [{ bnode_id: BNODES[0] ? BNODES[0].id : '', list: '' }];
  }
  const fbBNode = (!direct && Array.isArray(c.routes) && c.routes.length) ? (c.bnode_id || '') : '';
  return `<div class="form-grid">
    <div class="full"><label>链式规则名称</label><input id="chName" value="${escAttr(c.name || '')}" placeholder="留空自动命名"></div>
    <div class="full">
      <label>入口 A 节点（本机）</label>
      <select id="chA">${chainAOptions(c.inbound_id || '', c.id || '')}</select>
      <div class="hint">支持本机 VLESS / Hysteria2 / Trojan / VMess / TUIC / AnyTLS / Snell / ShadowTLS / SS / Naive / SOCKS / HTTP（仅 WireGuard 不支持）</div>
    </div>
    <div class="full"><label>转发策略</label><div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:4px">
      <label style="display:flex;gap:6px;align-items:center;cursor:pointer;font-weight:500"><input type="radio" name="chMode" value="direct"${direct ? ' checked' : ''} onchange="chModeChange()">全局直通链式<span class="hint" style="margin:0">（全部流量 A 进 B 出）</span></label>
      <label style="display:flex;gap:6px;align-items:center;cursor:pointer;font-weight:500"><input type="radio" name="chMode" value="split"${direct ? '' : ' checked'} onchange="chModeChange()">多节点按清单分流<span class="hint" style="margin:0">（不同域名/IP 分别走 B1、B2、B3…）</span></label>
    </div></div>

    <div class="full" id="chDirectWrap" style="display:${direct ? '' : 'none'}">
      <label>落地 B 节点（外部）</label>
      <select id="chB">${bnodeOptions(direct ? (c.bnode_id || '') : '', false)}</select>
      <div class="hint">先在“外部落地节点”中导入</div>
    </div>

    <div class="full" id="chSplitWrap" style="display:${direct ? 'none' : ''}">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px">
        <label style="margin:0">分流落地组（自动拦截重复域名、父子包含域名与重叠 IP 网段）</label>
        <button type="button" class="btn ghost small" onclick="addSplitGroup()">＋ 添加 B 节点分流</button>
      </div>
      <div id="chRoutesBox">${initRoutes.map(r => renderSplitGroupHTML(r.bnode_id, r.list)).join('')}</div>
      <div style="margin-top:6px">
        <label>未命中以上清单的其余流量</label>
        <select id="chFallbackB" onchange="syncSplitSelects()">${bnodeOptions(fbBNode, true)}</select>
      </div>
    </div>
  </div>`;
}
function openChainModal(){
  openModal(`<h4>新建链式与分流规则</h4>${chainFormHTML(null)}
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="chSaveBtn" onclick="saveChain(null)">保存规则</button></div>
    <div class="msg" id="chMsg"></div>`, true);
  syncSplitSelects();
}
function openChainEditModal(id){
  const c = CHAINS.find(x => x.id === id);
  if (!c) return;
  openModal(`<h4>编辑链式：${escHtml(c.name)}</h4>${chainFormHTML(c)}
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" id="chSaveBtn" onclick="saveChain('${escAttr(id)}')">保存修改</button></div>
    <div class="msg" id="chMsg"></div>`, true);
  syncSplitSelects();
}
async function saveChain(id){
  const a = $('chA').value, name = $('chName').value.trim();
  const mode = document.querySelector('input[name="chMode"]:checked')?.value || 'split';
  if (id && !name){ $('chMsg').className = 'msg err'; $('chMsg').textContent = '链式名不能为空'; return; }
  if (!a){ $('chMsg').className = 'msg err'; $('chMsg').textContent = '请选择入口 A 节点'; return; }
  const aOpt = $('chA').selectedOptions[0];
  if (aOpt && aOpt.disabled){
    $('chMsg').className = 'msg err';
    $('chMsg').textContent = '这个 A 节点不可选：' + (aOpt.text.includes('已有链式') ? '它已经有一条链式规则了，请直接编辑那条规则添加分流组' : '该协议不支持作为入口 A');
    return;
  }

  const payload = { name, inbound_id: a, mode };
  if (mode === 'direct'){
    const b = $('chB').value;
    if (!b){ $('chMsg').className = 'msg err'; $('chMsg').textContent = '请选择落地 B 节点'; return; }
    payload.bnode_id = b;
    payload.routes = [];
  } else {
    const groups = [...document.querySelectorAll('#chRoutesBox .split-group')];
    if (!groups.length){ $('chMsg').className = 'msg err'; $('chMsg').textContent = '请至少添加 1 个分流组'; return; }
    const routes = [];
    for (let i = 0; i < groups.length; i++){
      const bid = groups[i].querySelector('.sg-bnode').value;
      const lst = groups[i].querySelector('.sg-list').value.trim();
      if (!bid){ $('chMsg').className = 'msg err'; $('chMsg').textContent = `第 ${i + 1} 组未选择落地 B 节点`; return; }
      if (!lst){ $('chMsg').className = 'msg err'; $('chMsg').textContent = `第 ${i + 1} 组的域名或 IP 清单不能为空`; return; }
      routes.push({ bnode_id: bid, list: lst });
    }
    payload.routes = routes;
    payload.bnode_id = $('chFallbackB') ? $('chFallbackB').value : '';
  }

  const btn = $('chSaveBtn'); btn.disabled = true;
  try {
    if (id){
      await api('/api/chains/' + encodeURIComponent(id), 'PUT', payload);
      toast('链式已保存');
    } else {
      await api('/api/chains', 'POST', payload);
      toast('链式规则已添加');
    }
    closeModal(); await loadChains();
  } catch(e){
    $('chMsg').className = 'msg err'; $('chMsg').textContent = e.message;
    btn.disabled = false;
  }
}
function renderChainRows(){
  const el = $('chainRows');
  if (!el) return;
  if (!CHAINS.length){ el.innerHTML = '<div class="empty">还没有链式代理规则</div>'; return; }
  el.innerHTML = CHAINS.map(c => {
    const a = NODES.find(n => n.id === c.inbound_id);
    const aDesc = a ? `${escHtml(a.name)} (${escHtml(a.protocol.toUpperCase())})` : escHtml(c.inbound_id);
    let targetDesc = '';
    if (c.mode === 'direct'){
      const b = BNODES.find(x => x.id === c.bnode_id);
      targetDesc = `落地 B：${b ? escHtml(b.name) : escHtml(c.bnode_id)} · 全局流量直通`;
    } else {
      const rts = (c.routes && c.routes.length) ? c.routes : (c.bnode_id ? [{ bnode_id: c.bnode_id, list: c.list || '' }] : []);
      const parts = rts.map((r, i) => {
        const b = BNODES.find(x => x.id === r.bnode_id);
        const cnt = (r.list || '').split('\n').filter(x => x.trim() && !x.trim().startsWith('#')).length;
        return `B${i + 1}:${b ? escHtml(b.name) : escHtml(r.bnode_id)}(${cnt}条)`;
      });
      const fb = (c.routes && c.routes.length && c.bnode_id) ? BNODES.find(x => x.id === c.bnode_id) : null;
      targetDesc = `分流：${parts.join(' / ')} · 其余：${fb ? escHtml(fb.name) : '本机直连'}`;
    }
    const cid = escAttr(c.id);
    return `<div class="row">
      <button class="menu-btn" title="操作" onclick="openChainMenu(this,'${cid}')">⋮</button>
      <input type="checkbox" class="switch" ${c.enabled ? 'checked' : ''} onchange="toggleChain('${cid}', this.checked)">
      <div class="grow"><div class="t">${escHtml(c.name)}</div>
        <div class="s">入口 A：${aDesc} → ${targetDesc} · ${c.enabled ? '生效中' : '已停用'}</div></div>
    </div>`;
  }).join('');
}
function openChainMenu(btn, id){
  const c = CHAINS.find(x => x.id === id);
  if (!c) return;
  const cid = escAttr(id);
  openDropdown(btn, `
    <button onclick="closeDropdown();showChainLink('${cid}')">${MI.link}链式连接链接</button>
    <button onclick="closeDropdown();openChainEditModal('${cid}')">${MI.edit}编辑规则</button>
    <button class="danger" onclick="closeDropdown();delChain('${cid}')">${MI.trash}删除规则</button>`);
}
async function showChainLink(id){
  const c = CHAINS.find(x => x.id === id);
  if (!c) return;
  const a = NODES.find(n => n.id === c.inbound_id);
  const isMultiline = a && (a.protocol === 'naive' || a.protocol === 'wireguard');
  try {
    const r = await api('/api/chains/' + encodeURIComponent(id) + '/link');
    const mainField = isMultiline
      ? `<label>链式客户端配置（客户端直连入口 A，服务端自动按规则分流）</label><textarea id="lkChain" readonly rows="10" style="width:100%" class="mono">${escHtml(r.link)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkChain')">复制配置</button></div>`
      : `<label>链式链接（客户端直连入口 A，链式转发在服务端自动完成）</label><div class="input-row"><input id="lkChain" readonly value="${escAttr(r.link)}"><button class="btn ghost small" onclick="copyText('lkChain')">复制</button></div>`;
    const link6Field = !r.link6 ? '' : (isMultiline
      ? `<div style="margin-top:12px"><label>链式客户端配置 IPv6</label><textarea id="lkChain6" readonly rows="10" style="width:100%" class="mono">${escHtml(r.link6)}</textarea><div style="margin-top:8px"><button class="btn ghost small" onclick="copyText('lkChain6')">复制配置</button></div></div>`
      : `<div style="margin-top:12px"><label>链式链接 IPv6</label><div class="input-row"><input id="lkChain6" readonly value="${escAttr(r.link6)}"><button class="btn ghost small" onclick="copyText('lkChain6')">复制</button></div></div>`);
    openModal(`<h4>${escHtml(c.name)} · 链式连接凭证</h4>
      ${mainField}
      ${link6Field}
      <div class="qr-box"><img src="${escAttr((window.PANEL_BASE||'') + '/api/chains/' + encodeURIComponent(id) + '/qr')}" alt="二维码"></div>
      <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button></div>`);
  } catch(e){ toast(e.message, true); }
}
async function toggleChain(id, enable){
  try { await api('/api/chains/' + encodeURIComponent(id), 'PUT', { enabled: enable }); loadChains(); }
  catch(e){ toast(e.message, true); loadChains(); }
}
function delChain(id){
  const c = CHAINS.find(x => x.id === id);
  if (!c) return;
  confirmModal('删除链式规则', `确定删除 <b>${escHtml(c.name)}</b> 吗？`, '确认删除', async ()=>{
    await api('/api/chains/' + encodeURIComponent(id), 'DELETE');
    toast('已删除'); loadChains();
  });
}

// ---------- settings ----------
let ACC_LOADED = {};
async function loadSettings(){
  try {
    await loadPanelCerts();
  } catch(e){}
  try {
    const me = await api('/api/me');
    if ($('curUser')) $('curUser').value = me.username || '';
  } catch(e){}
  try {
    const s = await api('/api/settings');
    ACC_LOADED = { port: s.panel_port || '', path: s.panel_path || '' };
    if ($('accPort')) $('accPort').value = ACC_LOADED.port;
    if ($('accPath')) $('accPath').value = ACC_LOADED.path;
  } catch(e){}
  try {
    const t = await api('/api/settings/2fa/status');
    if ($('tfaStatus')) $('tfaStatus').textContent = t.broken ? '密钥损坏（请用本机 SSH 菜单关闭二次验证后重新开通）' : (t.enabled ? ('已开启保护（剩余一次性恢复码 ' + t.recovery_left + ' 个）') : '尚未开通两步验证');
    if ($('tfaOpenBtn')) $('tfaOpenBtn').style.display = t.enabled ? 'none' : '';
    if ($('tfaCloseBtn')) $('tfaCloseBtn').style.display = t.enabled ? '' : 'none';
  } catch(e){}
  checkUpdate(true);
}
async function savePanelAccess(){
  const portRaw = parseInt($('accPort').value, 10), path = $('accPath').value.trim();
  const msg = $('accMsg'); msg.className = 'hint'; msg.textContent = '正在保存…';
  try {
    const port = isNaN(portRaw) ? ACC_LOADED.port : portRaw;
    const r = await api('/api/settings/panel-access', 'POST', { port, path });
    const host = location.hostname.includes(':') ? '[' + location.hostname + ']' : location.hostname;
    const base = r.path ? '/' + r.path : '';
    const curPort = location.port ? parseInt(location.port, 10) : (location.protocol === 'https:' ? 443 : 80);
    const portChanged = r.port !== curPort, pathChanged = base !== (window.PANEL_BASE || '');
    if (r.restart_required){
      if (pathChanged){
        msg.className = 'hint';
        msg.textContent = '路径已生效，端口已写入服务文件但不会自动重启（手动部署），手动重启后请用新地址：' + location.protocol + '//' + host + ':' + r.port + base + '/' + (r.note ? '（' + r.note + '）' : '');
        toast('路径已生效，端口待手动重启');
        location.href = location.protocol + '//' + host + (location.port ? ':' + location.port : '') + base + '/';
      } else {
        msg.className = 'hint';
        msg.textContent = '端口已写入服务文件，但面板不会自动重启（手动部署），请手动按新端口重启面板：' + host + ':' + r.port + (r.note ? '（' + r.note + '）' : '');
        toast('已保存，待手动重启');
      }
    } else if (portChanged || pathChanged){
      msg.className = 'hint'; msg.textContent = '正在重启面板，重启后自动跳转新地址…';
      toast('面板访问已改，正在重启');
      const url = location.protocol + '//' + host + ':' + r.port + base + '/';
      await waitForPanel(url);
      location.href = url;
    } else {
      msg.className = 'hint'; msg.textContent = '已保存，立即生效';
      toast('已保存');
    }
    ACC_LOADED = { port: r.port, path: r.path };
  } catch(e){ msg.className = 'hint'; msg.textContent = ''; toast(e.message, true); }
}
async function waitForPanel(url){
  for (let i = 0; i < 50; i++){
    try { await fetch(url, { mode: 'no-cors' }); return; } catch(e){}
    await new Promise(r => setTimeout(r, 400));
  }
}
async function open2faBegin(){
  try {
    const r = await api('/api/settings/2fa/begin', 'POST', {});
    open2faModal(r);
  } catch(e){ toast(e.message, true); }
}
function open2faModal(r){
  const safeQr = (r.qr && String(r.qr).startsWith('data:image/png;base64,')) ? escAttr(r.qr) : '';
  openModal(`<h4>开通两步验证（2FA）</h4>
    <div class="muted" style="padding:4px 0 12px">使用验证器 App 扫描二维码或手动输入密钥；随后输入 6 位动态码完成绑定。绑定成功后将生成 10 个一次性恢复码，请务必妥善保存。</div>
    <div style="text-align:center;margin:8px 0 14px"><img src="${safeQr}" style="width:184px;height:184px;border:1px solid var(--line-subtle);border-radius:16px;padding:6px;background:#fff;box-shadow:var(--shadow-sm)"></div>
    <label>手动密钥（可复制）</label><div class="input-row"><input id="tfaSecret" readonly value="${escAttr(r.secret)}"><button class="btn ghost small" onclick="copyText('tfaSecret')">复制</button><button class="btn ghost small" onclick="regen2faSecret()">换一个</button></div>
    <div class="hint">每次打开与刷新均重新随机生成密钥。</div>
    <div style="margin-top:12px"><label>验证器 6 位动态码</label><input id="tfaCode" inputmode="numeric" placeholder="请输入 6 位数字动态码"></div>
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn" onclick="enable2fa()">验证并开通</button></div>
    <div class="msg" id="tfaModalMsg"></div>`);
}
async function regen2faSecret(){
  try {
    const r = await api('/api/settings/2fa/regenerate', 'POST', {});
    open2faModal(r);
  } catch(e){ toast(e.message, true); }
}
async function enable2fa(){
  const code = $('tfaCode').value.trim();
  if (!code){ $('tfaModalMsg').className = 'msg err'; $('tfaModalMsg').textContent = '请先输入动态码'; return; }
  try {
    const r = await api('/api/settings/2fa/enable', 'POST', { code });
    const codes = (r.recovery || []).join('\n');
    openModal(`<h4>两步验证（2FA）已成功开通</h4>
      <div class="muted" style="padding:4px 0 12px">以下是您的 10 个一次性紧急恢复码，<b>仅显示这一次</b>。遗失手机验证器时凭恢复码登录，用一次少一个。请立即复制并妥善保存。</div>
      <textarea id="tfaRecovery" readonly rows="11" style="width:100%" class="mono">${escHtml(codes)}</textarea>
      <div class="foot"><button class="btn ghost" onclick="copyText('tfaRecovery')">复制全部恢复码</button><button class="btn" onclick="closeModal();loadSettings()">我已妥善保存</button></div>`);
    toast('2FA 已开通');
  } catch(e){ $('tfaModalMsg').className = 'msg err'; $('tfaModalMsg').textContent = e.message; }
}
function open2faDisable(){
  openModal(`<h4>关闭两步验证（2FA）</h4>
    <div class="muted" style="padding:4px 0 12px">关闭后登录不再要求动态码，现有恢复码同时作废。请输入当前 6 位动态码（或任意未使用的恢复码）以确认身份。</div>
    <label>动态码或恢复码</label><input id="tfaOffCode" placeholder="6 位动态码 或 XXXX-XXXX 恢复码">
    <div class="foot"><button class="btn ghost" onclick="closeModal()">取消</button><button class="btn red" onclick="disable2fa()">确认关闭 2FA</button></div>
    <div class="msg" id="tfaOffMsg"></div>`);
}
async function disable2fa(){
  const code = $('tfaOffCode').value.trim();
  if (!code){ $('tfaOffMsg').className = 'msg err'; $('tfaOffMsg').textContent = '请先输入动态码或恢复码'; return; }
  try {
    await api('/api/settings/2fa/disable', 'POST', { code });
    closeModal(); loadSettings(); toast('2FA 已关闭');
  } catch(e){ $('tfaOffMsg').className = 'msg err'; $('tfaOffMsg').textContent = e.message; }
}
async function saveLogin(){
  const u = $('newUser').value.trim(), p = $('pwNew').value, old = $('pwOld').value;
  if (!u && !p){ toast('账号和密码都留空，没有要改的内容', true); return; }
  if (p && p.length < 6){ toast('新密码至少 6 位', true); return; }
  if (p && !old){ toast('改密码请先输入旧密码', true); return; }
  try {
    const r = await api('/api/settings/login', 'POST', { username: u, password: p, old_password: old });
    toast('已保存，立即生效');
    if (r.username) $('curUser').value = r.username;
    $('newUser').value = ''; $('pwNew').value = ''; $('pwOld').value = '';
  } catch(e){ toast(e.message, true); }
}

// ---------- 在线更新 ----------
let UPD_LATEST = '';
async function checkUpdate(auto){
  const msg = $('updMsg'); if (!msg) return;
  const btn = $('updCheckBtn');
  if (btn) btn.disabled = true;
  if (!auto) msg.textContent = '正在检查…';
  try {
    const r = await api('/api/update/check', 'POST', { force: !auto }, 60000);
    if ($('updCur')) $('updCur').value = r.current || '';
    if ($('updLatest')) $('updLatest').value = r.latest || '未查到';
    if ($('updChecked')) $('updChecked').value = r.checked_at || '';
    UPD_LATEST = r.latest || '';
    const apply = $('updApplyBtn');
    if (apply) apply.disabled = !r.has_update;
    msg.textContent = r.has_update ? ('发现新版本 ' + r.latest + '，点击“更新到最新版”即可在线升级。') : (r.latest ? '当前已是最新版本。' : '暂未查到新版信息，请稍后再试。');
  } catch(e){
    UPD_LATEST = '';
    msg.textContent = '检查失败：' + e.message;
  }
  if (btn) btn.disabled = false;
}
async function applyUpdate(){
  if (!UPD_LATEST) { toast('先检查更新', true); return; }
  const btn = $('updApplyBtn'); const msg = $('updMsg');
  btn.disabled = true; btn.textContent = '下载中…';
  let progBusy = false;
  let timer = setInterval(async () => {
    if (progBusy) return;
    progBusy = true;
    try {
      const p = await api('/api/update/progress');
      if (p.phase === 'installing') btn.textContent = '安装中…';
      else if (p.phase === 'downloading') btn.textContent = '下载中…';
      else if (p.phase === 'restarting') btn.textContent = '重启中…';
    } catch(_){}
    finally { progBusy = false; }
  }, 800);
  try {
    const r = await api('/api/update/apply', 'POST', {}, 300000);
    clearInterval(timer);
    if (r.restart_required){
      msg.textContent = '已更新到 ' + r.version + '，但面板未自动重启（手动部署），请手动重启面板服务后再登录验证版本。';
      btn.disabled = false; btn.textContent = '更新到最新版';
      return;
    }
    msg.textContent = '已更新到 ' + r.version + '，面板正在重启…';
    btn.textContent = '重启中…';
    let tries = 0, lastVer = '';
    const normVer = v => (v || '').replace(/^v/, '');
    const target = normVer(r.version);
    const wait = setInterval(async () => {
      tries++;
      const ctl = new AbortController();
      const to = setTimeout(() => ctl.abort(), 5000);
      try {
        const resp = await fetch((window.PANEL_BASE || '') + '/api/setup-status', { signal: ctl.signal });
        if (!resp.ok) throw new Error('not up');
        const st = (await resp.json()).data || {};
        if (st.version) lastVer = st.version;
        if (st.version && normVer(st.version) === target) {
          clearInterval(wait);
          clearTimeout(to);
          const onSettings = $('view-settings') && $('view-settings').classList.contains('on');
          const modalOpen = $('overlay') && $('overlay').classList.contains('on');
          const ae = document.activeElement;
          const typing = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' || ae.isContentEditable);
          if (onSettings && !modalOpen && !typing){
            msg.textContent = '更新完成（' + r.version + '），正在刷新页面…';
            setTimeout(() => location.reload(), 1200);
          } else {
            msg.textContent = '更新完成（' + r.version + '），请手动刷新页面。';
            btn.disabled = false; btn.textContent = '更新到最新版';
          }
          return;
        }
        throw new Error('version not yet');
      } catch(_){}
      clearTimeout(to);
      if (tries > 45){ clearInterval(wait); msg.textContent = '面板重启后版本未变成 ' + r.version + (lastVer ? '（仍是 ' + lastVer + '）' : '（仍是旧版）') + '，更新未生效，请手动重启面板服务后再试。'; btn.disabled = false; btn.textContent = '更新到最新版'; }
    }, 2000);
  } catch(e){
    clearInterval(timer);
    msg.textContent = '更新失败：' + e.message;
    btn.disabled = false; btn.textContent = '更新到最新版';
  }
}
// ---------- 面板域名和证书（手动添加 / 在线申请 / 启用 HTTPS） ----------
let PANEL_CERTS = [];
let PANEL_CERT_ID = '';
function panelCertDomain(id){
  for (const x of PANEL_CERTS || []) if (x.id === id) return (x.domains || [])[0] || '';
  return '';
}
function panelHttpsUrl(certId){
  const host = panelCertDomain(certId || PANEL_CERT_ID) || location.hostname;
  const port = location.port ? ':' + location.port : '';
  const base = (window.PANEL_BASE || '');
  return 'https://' + host + port + base + (base ? '/' : '');
}
function setPanelHttpsBtn(enabled){
  const b = $('panelHttpsEnable'); if (!b) return;
  b.textContent = enabled ? '已启用' : '启用 HTTPS';
}
function panelCertNameById(list, id){
  for (const x of list || []) if (x.id === id) return x.name;
  return id || '';
}
async function loadPanelCerts(){
  try {
    const c = await api('/api/settings/certs');
    const list = c.certs || [];
    PANEL_CERTS = list; PANEL_CERT_ID = c.panel_cert || '';
    const box = $('panelCertList'); if (!box) return;
    if (!list.length){
      box.textContent = '还没有证书：先手动上传或 ACME 在线申请一张，再选它启用 HTTPS。';
    } else {
      box.innerHTML = list.map(x => {
        const exp = x.days_left === -9999 ? '到期未知'
          : (x.days_left < 0 ? '已过期 ' + (-x.days_left) + ' 天' : '剩余 ' + x.days_left + ' 天');
        return '<div style="padding:4px 0">' + escHtml(x.name) + '（' + escHtml((x.domains || []).join('、')) + ' · ' + exp
          + ' · ' + (x.auto_renew ? '自动续签' : '不自动续签')
          + (x.selected ? ' · <b style="color:var(--primary)">当前选用</b>' : '') + '）</div>';
      }).join('');
    }
    const sel = $('panelHttpsCert'); if (sel){
      sel.innerHTML = '<option value="">— 选择证书 —</option>' + list.map(x =>
        '<option value="' + escHtml(x.id) + '"' + (x.id === c.panel_cert ? ' selected' : '') + '>'
        + escHtml(x.name) + '（' + escHtml((x.domains || [])[0] || x.id) + '）</option>').join('');
    }
    const hint = $('panelHttpsHint'); if (hint){
      if (c.panel_https){
        const u = panelHttpsUrl(c.panel_cert);
        hint.innerHTML = 'HTTPS 已启用（证书：' + escHtml(panelCertNameById(list, c.panel_cert))
          + '）。请使用 <a href="' + escHtml(u) + '">' + escHtml(u) + '</a> 访问面板。';
      } else {
        hint.textContent = '当前走 HTTP。选一张证书并启用 HTTPS 后，面板支持加密访问。';
      }
      setPanelHttpsBtn(!!c.panel_https);
    }
  } catch(e){}
}
async function savePanelHttps(enable){
  if (enable){
    const cert = $('panelHttpsCert').value;
    if (!cert){ toast('请先选择一张证书', true); return; }
    const u = panelHttpsUrl(cert);
    const base = (window.PANEL_BASE || '');
    confirmModal('启用 HTTPS',
      '启用后，面板同时支持两种打开方式：<a href="' + escHtml(u) + '">' + escHtml(u) + '</a>（加密，日常用这个）；http://' + location.host + base + (base ? '/' : '') + ' 也能打开，但是明文，登录信息不加密，只当备用入口。证书丢了/过期，重启面板会自动回落 HTTP。',
      '确定启用', async ()=>{
      await api('/api/settings/panel-https', 'POST', { enabled: true, cert });
      const hint = $('panelHttpsHint'); if (hint){
        hint.innerHTML = 'HTTPS 已启用。请使用 <a href="' + escHtml(u) + '">' + escHtml(u) + '</a> 访问面板。';
      }
      setPanelHttpsBtn(true);
      toast('HTTPS 已启用，请用 https 地址访问面板');
    });
  } else {
    try {
      await api('/api/settings/panel-https', 'POST', { enabled: false });
      setPanelHttpsBtn(false);
      location.href = 'http://' + location.host + location.pathname;
    } catch(e){ toast(e.message, true); }
  }
}
function openManualCertDialog(){
  openModal('<h3>手动上传证书</h3><div class="form-grid">'
    + '<div class="full"><label>证书备注名（留空 = 自动取证书首域名）</label><input id="mCertName"></div>'
    + '<div class="full"><label>证书文件（.crt / .pem，须与私钥成对）</label><input id="mCertFile" type="file"></div>'
    + '<div class="full"><label>私钥文件（.key）</label><input id="mCertKey" type="file"></div>'
    + '<div class="full"><div class="hint" id="mCertResult"></div></div></div>'
    + '<div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button><button class="btn" onclick="uploadPanelCert()">上传并添加</button></div>');
}
async function uploadPanelCert(){
  const name = $('mCertName').value.trim();
  const cert = $('mCertFile').files[0], key = $('mCertKey').files[0];
  const res = $('mCertResult');
  if (!cert || !key){ res.textContent = '请同时选择证书与私钥文件'; return; }
  const fd = new FormData();
  fd.append('name', name); fd.append('cert', cert); fd.append('key', key);
  res.textContent = '上传中…';
  try {
    const r = await fetch((window.PANEL_BASE || '') + '/api/settings/cert-manual', { method: 'POST', body: fd });
    let j = {}; try { j = await r.json(); } catch(e){}
    if (r.status === 401){ showLogin(); throw new Error('未登录'); }
    if (!j.ok) throw new Error(j.error || ('请求失败 ' + r.status));
    res.textContent = '已添加证书：' + (j.data.cert ? j.data.cert.name : name);
    await loadPanelCerts();
  } catch(e){ res.textContent = '失败：' + e.message; }
}
async function openAcmeDialog(){
  let configured = false;
  try { const c = await api('/api/settings/certs'); configured = !!c.cf_token_configured; } catch(e){}
  openModal('<h3>ACME 在线申请证书</h3><div class="form-grid">'
    + '<div class="full"><label>域名列表（一行一个，首域名决定证书存放目录名）</label><textarea id="aCertDomains" rows="3" placeholder="example.com"></textarea></div>'
    + '<div class="full"><label>证书备注名（留空 = 用首域名）</label><input id="aCertName"></div>'
    + '<div class="full"><label>验证方式</label><select id="aCertMethod">'
    + '<option value="">自动（80 空闲走 HTTP-01，80 被占走 DNS-01）</option>'
    + '<option value="http-01">HTTP-01（需 80 端口空闲）</option>'
    + '<option value="dns-01">DNS-01（需 Cloudflare Token）</option></select></div>'
    + '<div class="full"><label>Cloudflare API Token（DNS-01 用，需对应域名的 DNS 编辑权限；仅存本机用于续期）</label>'
    + '<input id="aCertToken" type="password" placeholder="' + (configured ? '已保存 Token（留空表示沿用，填新值则覆盖）' : 'Cloudflare API Token') + '"></div>'
    + '<div class="full"><label style="display:inline-flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="aCertRenew" checked> 开启自动续签（到期前 30 天自动续期）</label></div>'
    + '<div class="full"><div class="hint">自动：80 空闲走 HTTP-01，80 被占走 DNS-01（需 Token）。通配符域名只能 DNS-01。</div></div>'
    + '<div class="full"><div class="hint" id="aCertResult" style="color:var(--primary);font-weight:500"></div></div></div>'
    + '<div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button><button class="btn" onclick="applyAcme()">开始申请</button></div>');
}
async function applyAcme(){
  const domains = $('aCertDomains').value.split('\n').map(s => s.trim()).filter(Boolean);
  const name = $('aCertName').value.trim();
  const method = $('aCertMethod').value;
  const cfToken = $('aCertToken').value;
  const autoRenew = $('aCertRenew').checked;
  const res = $('aCertResult');
  if (!domains.length){ res.textContent = '请填写域名（一行一个）'; return; }
  res.textContent = '申请中…';
  try {
    const r = await api('/api/settings/cert-acme', 'POST', { domains, method, cfToken, name, autoRenew }, 120000);
    res.textContent = '已提交（' + (r.method === 'http-01' ? 'HTTP-01' : 'DNS-01') + '），等待验证…';
    pollAcmeStatus();
  } catch(e){ res.textContent = '失败：' + e.message; }
}
async function pollAcmeStatus(){
  const el = $('aCertResult'); if (!el) return;
  try {
    const j = await api('/api/settings/cert-acme-status');
    if (j.running){
      el.textContent = '验证进行中…（' + (j.domains || []).join('、') + '，' + j.method + '）';
      setTimeout(pollAcmeStatus, 2000);
      return;
    }
    if (j.last_err){ el.textContent = '失败：' + j.last_err; }
    else if (j.last_ok){
      el.textContent = '申请成功（' + j.last_ok + '）。请在下方证书列表里确认，然后启用 HTTPS。';
      await loadPanelCerts();
    }
  } catch(e){ el.textContent = '状态查询失败：' + e.message; }
}
function subLinkValue(token){
  const host = panelCertDomain(PANEL_CERT_ID) || location.hostname;
  const scheme = location.protocol === 'https:' ? 'https' : 'http';
  const port = location.port ? ':' + location.port : '';
  return scheme + '://' + host + port + '/sub/' + token;
}
async function openSubModal(){
  openModal(`<h4>多端统一订阅配置</h4><div class="muted" style="padding:8px 0">正在读取订阅信息…</div>`);
  try {
    const s = await api('/api/settings');
    const link = subLinkValue(s.sub_token);
    const excluded = new Set(s.sub_excluded || []);
    const locals = (NODES || []).map(n => `<div class="row"><input type="checkbox" class="sub-check" data-key="in:${n.id}" ${excluded.has('in:' + n.id) ? '' : 'checked'}><div class="grow"><div class="t">${escHtml(n.name)} ${protoBadge(n.protocol)}</div><div class="s">本地节点 · ${n.enabled ? '启用中' : '已停用（停用的节点订阅里也不会出）'}</div></div></div>`).join('');
    const others = (BNODES || []).map(b => `<div class="row"><input type="checkbox" class="sub-check" data-key="bn:${b.id}" ${excluded.has('bn:' + b.id) ? '' : 'checked'}><div class="grow"><div class="t">${escHtml(b.name)} ${protoBadge(b.protocol)}</div><div class="s">外部节点</div></div></div>`).join('');
    openModal(`<h4>多端统一订阅配置</h4>
      <div style="margin-bottom:10px"><label>通用订阅链接（Base64 链接列表，适配 v2rayN / Shadowrocket / NekoBox）</label><div class="input-row"><input id="subLink" readonly value="${escHtml(link)}"><button class="btn ghost small" onclick="copyText('subLink')">复制</button><button class="btn ghost small" onclick="regenSubFromModal()">重置令牌</button></div></div>
      <div style="margin-bottom:10px"><label>Sing-box 专属订阅（JSON 完整配置，适配 Hiddify / Sing-box / Karing，支持全部 13 种协议）</label><div class="input-row"><input id="subLinkSingbox" readonly value="${escHtml(link + '?format=singbox')}"><button class="btn ghost small" onclick="copyText('subLinkSingbox')">复制</button></div></div>
      <div style="margin-bottom:10px"><label>Clash Mihomo 专属订阅（YAML 配置，适配 Clash Verge / FlClash / Stash）</label><div class="input-row"><input id="subLinkClash" readonly value="${escHtml(link + '?format=clash')}"><button class="btn ghost small" onclick="copyText('subLinkClash')">复制</button></div></div>
      <div class="hint">同一订阅链接支持按客户端 User-Agent 自动识别格式；也可直接复制上方带参数的专属链接。WireGuard 仅在 Sing-box JSON 与 Clash YAML 中下发。</div>
      <div style="margin-top:16px"><label>勾选包含在订阅中的节点（默认全选）</label><div style="max-height:220px;overflow-y:auto;border:1px solid var(--line-subtle);border-radius:var(--r-md);padding:4px 8px;background:rgba(248,250,252,.7)">${locals || '<div class="muted" style="padding:10px">暂无本地节点</div>'}${others}</div></div>
      <div class="foot"><button class="btn ghost" onclick="closeModal()">关闭</button><button class="btn" id="subSaveBtn" onclick="saveSubSelection()">保存节点勾选</button></div>
      <div class="msg" id="subMsg"></div>`, true);
  } catch(e){ toast(e.message, true); }
}
async function saveSubSelection(){
  const excluded = [];
  document.querySelectorAll('.sub-check').forEach(cb => { if (!cb.checked) excluded.push(cb.dataset.key); });
  const btn = $('subSaveBtn'); btn.disabled = true;
  try {
    await api('/api/settings/sub-excluded', 'POST', { excluded });
    $('subMsg').className = 'msg ok'; $('subMsg').textContent = '订阅已保存，客户端刷新订阅就生效';
    toast('订阅已保存');
  } catch(e){
    $('subMsg').className = 'msg err'; $('subMsg').textContent = e.message;
  }
  btn.disabled = false;
}
async function regenSubFromModal(){
  confirmModal('更换订阅链接', '换了之后，<b>旧订阅链接立即失效</b>，原来用旧链接的客户端要重新换新链接才能刷新。确定换吗？', '确定更换', async ()=>{
    try {
      const r = await api('/api/settings/sub-token', 'POST', {});
      $('subLink').value = subLinkValue(r.sub_token);
      if ($('subLinkSingbox')) $('subLinkSingbox').value = subLinkValue(r.sub_token) + '?format=singbox';
      if ($('subLinkClash')) $('subLinkClash').value = subLinkValue(r.sub_token) + '?format=clash';
      toast('订阅链接已更换，旧链接已失效');
    } catch(e){ toast(e.message, true); }
  });
}

// ---------- boot ----------
async function refreshAll(){
  await loadPanelCerts();
  await loadChains();
  await refreshStatus();
  await loadSettings();
}
(async function(){
  try {
    const st = await api('/api/setup-status');
    if (st.setup_required){ showSetup(); return; }
  } catch(e){}
  try {
    await api('/api/me');
    showApp();
  } catch(e){ showLogin(); }
})();