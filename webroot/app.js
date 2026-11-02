import { exec, loginURL, quote } from './bridge.js';
const $ = (id) => document.getElementById(id);
let busy = false;
let current = null;
let authURL = null;

function message(text, error = false) {
  $('feedback').textContent = text;
  $('feedback').classList.toggle('error', error);
}
function controls() {
  document.querySelectorAll('button, input, select').forEach(el => { el.disabled = busy; });
  if (!busy) {
    document.querySelectorAll('[data-setting]:not([data-module]), #save-exit, #exit-node, #save-hostname, #hostname').forEach(el => { el.disabled = !current?.running; });
    $('lan').disabled = !current?.running || !(current?.prefs?.ExitNodeIP || current?.prefs?.ExitNodeID);
  }
}
function render(data) {
  current = data;
  const ts = data.tailscale || {};
  const prefs = data.prefs || {};
  $('state').textContent = data.running ? (ts.BackendState || 'Starting') : (data.recovering ? 'Recovering service' : 'Service stopped');
  $('addresses').textContent = (ts.TailscaleIPs || []).join(' · ') || 'No tailnet address assigned';
  $('identity').textContent = ts.Self?.DNSName || ts.Self?.HostName || '';
  const dns = data.dns || {};
  const skipped = (dns.skipped || []).join('/');
  const dnsInfo = dns.active ? ` · Tailnet DNS active (${(dns.families || []).join('/') || 'quad-100'}${skipped ? `; ${skipped} unavailable` : ''})` : dns.enabled ? ' · Tailnet DNS bridge inactive' : '';
  $('service-info').textContent = `${data.running ? 'Running' : data.recovering ? 'Recovering' : 'Stopped'} · TUN ${data.tun ? 'present' : 'absent'}${data.paused ? ' · Boot start paused' : ''}${data.disconnected ? ' · Disconnected until Connect' : ''}${dnsInfo}`;
  $('version').textContent = `Module ${data.version || 'unknown'} · Tailscale ${data.coreVersion || 'unknown'}`;
  $('setup').hidden = !!data.initialized;
  const options = data.options || {};
  for (const [id, key] of Object.entries({'capture-dns':'captureDNS', 'hotspot-dns':'hotspotDNS', 'search-domains':'searchDomains', 'userspace-fallback':'userspaceFallback'})) $(id).checked = !!options[key];
  if (document.activeElement !== $('hotspot-interface')) $('hotspot-interface').value = options.hotspotInterface || '';
  $('ssh').checked = !!prefs.RunSSH;
  $('routes').checked = !!prefs.RouteAll;
  $('accept-dns').checked = !!prefs.CorpDNS;
  $('shields').checked = !!prefs.ShieldsUp;
  $('lan').checked = !!prefs.ExitNodeAllowLANAccess;
  if (document.activeElement !== $('hostname')) $('hostname').value = prefs.Hostname || '';
  if (document.activeElement !== $('exit-node')) {
    const select = $('exit-node');
    select.replaceChildren(new Option('None', ''));
    const choices = new Map();
    for (const peer of Object.values(ts.Peer || {})) {
      if (!peer.ExitNodeOption || !peer.TailscaleIPs?.length) continue;
      const ip = peer.TailscaleIPs[0];
      choices.set(ip, `${peer.HostName} · ${ip}${peer.Online ? '' : ' (offline)'}`);
    }
    let selected = prefs.ExitNodeIP || '';
    if (selected === '0.0.0.0' || selected === '::') selected = '';
    if (!selected && prefs.ExitNodeID) selected = Object.values(ts.Peer || {}).find(peer => peer.ID === prefs.ExitNodeID)?.TailscaleIPs?.[0] || '';
    if (selected && !choices.has(selected)) choices.set(selected, `Selected · ${selected}`);
    for (const [value, text] of choices) select.add(new Option(text, value));
    select.value = selected;
  }
  authURL = loginURL(ts.AuthURL);
  $('login').hidden = !authURL;
  $('login-url').textContent = authURL || '';
  if (data.error) message(data.error, true);
  else if (dns.error) message(`Tailnet DNS: ${dns.error}`, true);
  else if (ts.Health?.length) message(ts.Health.join('\n'));
  else if (data.disabled) message('Module is disabled or pending removal.');
  controls();
}
async function run(args, silent = false) {
  if (busy) return;
  busy = true; controls();
  if (!silent) message('Working…');
  try {
    const result = await exec(args);
    if (args[0] === 'logs' || args[0] === 'diagnostics') {
      $('output').textContent = result.text || JSON.stringify(result, null, 2);
      message('Report refreshed.');
    } else {
      message(''); render(result);
      if (args[0] === 'connect') setTimeout(() => run(['status'], true), 1500);
    }
  } catch (error) { message(error.message, true); }
  finally { busy = false; controls(); }
}

$('refresh').addEventListener('click', () => run(['status']));
document.querySelectorAll('[data-command]').forEach(button => button.addEventListener('click', () => {
  const action = button.dataset.command;
  if (action === 'logout' && !confirm('Sign out and expire this device’s Tailscale session?')) return;
  run([action]);
}));
document.querySelectorAll('[data-setting]').forEach(input => input.addEventListener('change', async () => {
  await run(['set', input.dataset.setting, String(input.checked)]);
  // Restore authoritative preferences if a change was rejected.
  await run(['status'], true);
}));
$('save-hostname').addEventListener('click', () => run(['set', 'hostname', $('hostname').value]));
$('save-exit').addEventListener('click', () => run(['set', 'exit-node', $('exit-node').value]));
$('save-interface').addEventListener('click', () => run(['set', 'hotspot-interface', $('hotspot-interface').value]));
for (const policy of ['conservative', 'preserve']) $(`initialize-${policy}`).addEventListener('click', () => {
  if (confirm(policy === 'conservative' ? 'New identity: DNS, routes, SSH and exit node off; incoming connections blocked. Apply once?' : 'Reuse the identity already at /data/adb/tailscale and keep its current network preferences? No files will be migrated.')) run(['initialize', policy]);
});
$('purge').addEventListener('click', () => {
  if (prompt('Erase ALL saved state, identity, preferences, logs and backups in /data/adb/tailscale? This cannot be undone. Type erase-identity:') === 'erase-identity') run(['purge', 'erase-identity']);
});
$('open-login').addEventListener('click', () => {
  if (!authURL) return;
  // Launch the browser outside this privileged WebView. The URL is allowlisted.
  const callback = `tsctl_browser_${Date.now()}`;
  window[callback] = (code, out, err) => {
    delete window[callback];
    if (Number(code) !== 0) message(err || out || 'Could not open browser. Copy the sign-in URL instead.', true);
  };
  try { window.ksu.exec(`/system/bin/am start -a android.intent.action.VIEW -d ${quote(authURL)}`, '{}', callback); }
  catch (error) { delete window[callback]; message(error.message, true); }
});
document.addEventListener('visibilitychange', () => { if (!document.hidden) run(['status'], true); });
setInterval(() => { if (!document.hidden && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'SELECT') run(['status'], true); }, 10000);
run(['status']);
