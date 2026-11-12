import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

test('dashboard uses native DNS preference and preserves exit-node selection', () => {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', value: '', options: [], classList: { toggle() {} },
      addEventListener() {}, replaceChildren(...options) { this.options = options; },
      add(option) { this.options.push(option); },
    });
    return elements.get(id);
  };
  const context = vm.createContext({
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    Option: function (text, value) { this.text = text; this.value = value; },
    // Do not execute the manager/root bridge or schedule live refreshes.
    exec: () => new Promise(() => {}), loginURL: () => null, setInterval() {},
  });
  const source = readFileSync(new URL('../webroot/app.js', import.meta.url), 'utf8');
  vm.runInContext(source.replace(/^import .*;\n/, ''), context);
  const status = {
    running: true, tun: true, version: 'test',
    prefs: { CorpDNS: true, ExitNodeID: 'exit-id' },
    dns: { enabled: true, active: true, families: ['ipv4', 'ipv6'] },
    tailscale: { BackendState: 'Running', Peer: {
      key: { ID: 'exit-id', HostName: 'my-exit', TailscaleIPs: ['100.64.0.2'], ExitNodeOption: true, Online: true },
    } },
  };
  context.render(status);
  assert.equal(element('accept-dns').checked, true);
  assert.equal(element('exit-node').value, '100.64.0.2');
  assert.match(element('service-info').textContent, /Tailnet DNS active \(ipv4\/ipv6\)/);
  status.dns.active = false;
  status.dns.error = 'test bridge error';
  context.render(status);
  assert.equal(element('feedback').textContent, 'Tailnet DNS: test bridge error');
  assert.doesNotMatch(element('service-info').textContent, /waiting for route/);
  assert.equal(element('exit-node').value, '100.64.0.2');
  status.prefs.CorpDNS = false;
  status.dns = { enabled: false, active: false };
  context.render(status);
  assert.equal(element('accept-dns').checked, false);
  status.prefs = { CorpDNS: true, RouteAll: true };
  status.options = { captureDNS: true };
  status.dns = { enabled: true, active: true, families: ['ipv4'] };
  context.render(status);
  assert.equal(element('capture-dns').checked, true);
  assert.equal(element('exit-node').value, '');
  assert.match(element('service-info').textContent, /Tailnet DNS active/);
});

test('setup, names and identity erasure require exact user choices', async () => {
  const elements = new Map(), calls = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      value: '', options: [], classList: { toggle() {} }, handlers: {},
      addEventListener(name, fn) { this.handlers[name] = fn; },
      replaceChildren(...options) { this.options = options; }, add(option) { this.options.push(option); },
    });
    return elements.get(id);
  };
  let confirmation = false, typed = '';
  const context = vm.createContext({
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    Option: function(text, value) { this.text = text; this.value = value; },
    exec: async args => { calls.push(Array.from(args)); return { running: false, initialized: false }; },
    loginURL: () => null, setInterval() {}, confirm: () => confirmation, prompt: () => typed,
  });
  vm.runInContext(readFileSync(new URL('../webroot/app.js', import.meta.url), 'utf8').replace(/^import .*;\n/, ''), context);
  const click = async id => { element(id).handlers.click(); await new Promise(resolve => setImmediate(resolve)); };
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, [['status']]);
  await click('initialize-conservative');
  assert.equal(calls.length, 1);
  confirmation = true;
  await click('initialize-preserve');
  assert.deepEqual(calls.at(-1), ['initialize', 'preserve']);
  element('hostname').value = ' phone ';
  await click('save-hostname');
  assert.deepEqual(calls.at(-1), ['set', 'hostname', ' phone ']);
  const before = calls.length;
  typed = 'yes'; await click('purge');
  assert.equal(calls.length, before);
  typed = 'erase-identity'; await click('purge');
  assert.deepEqual(calls.at(-1), ['purge', 'erase-identity']);
});

test('diagnostics export preserves chosen filename and query and survives refresh', async () => {
  const elements = new Map(), calls = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      value: '', options: [], classList: { toggle() {} }, handlers: {}, dataset: {},
      addEventListener(name, fn) { this.handlers[name] = fn; },
      replaceChildren(...options) { this.options = options; }, add(option) { this.options.push(option); },
    });
    return elements.get(id);
  };
  const buttons = ['diagnostics', 'export-diagnostics'].map(id => {
    const button = element(id); button.dataset.command = id; return button;
  });
  const context = vm.createContext({
    document: { getElementById: element, querySelectorAll: selector => selector === '[data-command]' ? buttons : [], addEventListener() {} },
    Option: function(text, value) { this.text = text; this.value = value; },
    exec: async args => {
      calls.push(Array.from(args));
      if (args[0] === 'export-diagnostics') return { path: args[1] };
      if (args[0] === 'diagnostics') return { redacted: true };
      return { running: true, prefs: { CorpDNS: true }, options: { captureDNS: true } };
    },
    loginURL: () => null, setInterval() {},
  });
  vm.runInContext(readFileSync(new URL('../webroot/app.js', import.meta.url), 'utf8').replace(/^import .*;\n/, ''), context);
  const tick = () => new Promise(resolve => setImmediate(resolve));
  await tick();
  element('diagnostic-path').value = '/sdcard/Download/诊断 report.json';
  element('diagnostic-name').value = 'Service.Private.Example.';
  element('export-diagnostics').handlers.click(); await tick();
  assert.deepEqual(calls.at(-1), ['export-diagnostics', '/sdcard/Download/诊断 report.json', 'Service.Private.Example.']);
  assert.equal(element('feedback').textContent, 'Diagnostics saved to /sdcard/Download/诊断 report.json');
  await context.run(['status'], true);
  assert.equal(element('feedback').textContent, 'Diagnostics saved to /sdcard/Download/诊断 report.json');
  element('diagnostic-name').value = '';
  element('diagnostics').handlers.click(); await tick();
  assert.deepEqual(calls.at(-1), ['diagnostics']);
  assert.equal(JSON.parse(element('output').textContent).redacted, true);
  context.exec = async () => { throw new Error('existing files are not replaced'); };
  element('export-diagnostics').handlers.click(); await tick();
  assert.equal(element('feedback').textContent, 'existing files are not replaced');
  assert.equal(element('diagnostic-path').value, '/sdcard/Download/诊断 report.json');
});
