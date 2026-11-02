// Uses the KernelSU exec callback protocol; no remote scripts or HTTP server.
export const helper = '/data/adb/modules/magisk-tailscaled/bin/tsctl';
export function quote(value) { return "'" + String(value).replaceAll("'", "'\\''") + "'"; }
const operations = new Set(['status', 'start', 'stop', 'restart', 'connect', 'disconnect', 'logout', 'set', 'logs', 'diagnostics', 'initialize', 'purge']);
const settings = new Set(['accept-routes', 'shields-up', 'exit-node-allow-lan-access', 'accept-dns', 'hostname', 'exit-node', 'ssh', 'capture-dns', 'hotspot-dns', 'hotspot-interface', 'search-domains', 'userspace-fallback']);
export function commandFor(args) {
  if (!Array.isArray(args) || !operations.has(args[0])) throw new Error('Unsupported operation');
  const valid = args[0] === 'set' ? args.length === 3 && settings.has(args[1])
    : args[0] === 'initialize' ? args.length === 2 && ['conservative', 'preserve'].includes(args[1])
    : args[0] === 'purge' ? args.length === 2 && args[1] === 'erase-identity'
    : args.length === 1;
  if (!valid) throw new Error('Invalid arguments');
  return [helper, ...args].map(quote).join(' ');
}
export function loginURL(value) {
  try {
    const url = new URL(value);
    // Official hosted login only; never launch arbitrary intents from tailnet data.
    if (url.protocol !== 'https:' || url.username || url.password || url.port) return null;
    if (!['login.tailscale.com', 'controlplane.tailscale.com'].includes(url.hostname)) return null;
    return url.href;
  } catch { return null; }
}
let counter = 0;
export function exec(args, scope = window) {
  const command = commandFor(args);
  if (!scope.ksu || typeof scope.ksu.exec !== 'function') return Promise.reject(new Error('Open WebUI in KernelSU Manager or KsuWebUIStandalone.'));
  return new Promise((resolve, reject) => {
    const callback = `tsctl_callback_${Date.now()}_${++counter}`;
    const timer = setTimeout(() => {
      // Keep a harmless callback for a late Android bridge response.
      scope[callback] = () => { delete scope[callback]; };
      reject(new Error('Operation timed out. Refresh status before trying again.'));
    }, 90000);
    scope[callback] = (errno, stdout, stderr) => {
      clearTimeout(timer); delete scope[callback];
      if (Number(errno) !== 0) return reject(new Error(stderr || stdout || `Operation failed (${errno})`));
      try { resolve(JSON.parse(stdout)); } catch { reject(new Error('Invalid response from module control.')); }
    };
    try { scope.ksu.exec(command, '{}', callback); }
    catch (error) { clearTimeout(timer); delete scope[callback]; reject(error); }
  });
}
