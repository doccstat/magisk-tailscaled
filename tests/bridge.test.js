import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { exec, quote, commandFor, loginURL } from '../webroot/bridge.js';

test('shell quoting preserves hostile input as one literal argument', () => {
  const value = "name'; $(printf INJECTED) `printf INJECTED`\n--reset";
  const result = execFileSync('/bin/sh', ['-c', `printf '%s' ${quote(value)}`], { encoding: 'utf8' });
  assert.equal(result, value);
  assert.throws(() => commandFor(['eval', 'id']));
  assert.equal(commandFor(['set', 'accept-dns', 'true']), `${commandFor(['set', 'shields-up', 'true']).replace('shields-up', 'accept-dns')}`);
  assert.throws(() => commandFor(['status', 'extra']));
  assert.throws(() => commandFor(['purge']));
  assert.throws(() => commandFor(['purge', 'yes']));
  assert.throws(() => commandFor(['initialize', 'guess']));
  assert.match(commandFor(['initialize', 'preserve']), /'initialize' 'preserve'$/);
  assert.match(commandFor(['purge', 'erase-identity']), /'purge' 'erase-identity'$/);
});
test('sign-in only opens official HTTPS browser URLs', () => {
  assert.equal(loginURL('https://login.tailscale.com/a/abc'), 'https://login.tailscale.com/a/abc');
  for (const bad of ['javascript:alert(1)', 'intent://evil', 'http://login.tailscale.com/a', 'https://login.tailscale.com.evil/a', 'https://user:pw@login.tailscale.com/', 'https://login.tailscale.com:8443/']) assert.equal(loginURL(bad), null);
});
test('bridge uses JSON options, parses response and removes callbacks', async () => {
  const scope = {};
  scope.ksu = { exec(command, options, callback) {
    assert.equal(command, commandFor(['status']));
    assert.equal(options, '{}');
    scope[callback](0, '{"running":true}', '');
  } };
  assert.deepEqual(await exec(['status'], scope), { running: true });
  assert.deepEqual(Object.keys(scope), ['ksu']);
  scope.ksu.exec = (_, __, callback) => scope[callback](1, '', 'TUN missing');
  await assert.rejects(exec(['start'], scope), /TUN missing/);
  scope.ksu.exec = (_, __, callback) => scope[callback](0, 'bad json', '');
  await assert.rejects(exec(['status'], scope), /Invalid response/);
  await assert.rejects(exec(['status'], {}), /Open WebUI/);
});
