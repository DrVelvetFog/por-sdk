// PorClient option handling. A silently-ignored option means gating on the wrong
// chain, so these must either resolve unambiguously or throw. No network access:
// constructing a client doesn't touch the chain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PorClient, TESTNET, MAINNET } from '../dist/index.js';

test('defaults to testnet', () => {
  assert.equal(new PorClient().deployment, TESTNET);
});

test("network: 'mainnet' selects the mainnet deployment", () => {
  const c = new PorClient({ network: 'mainnet' });
  assert.equal(c.deployment, MAINNET);
  assert.equal(c.credentialType, `${MAINNET.packageId}::credential::RealHumanCredential`);
});

test("network: 'testnet' selects the testnet deployment", () => {
  assert.equal(new PorClient({ network: 'testnet' }).deployment, TESTNET);
});

test('deployment still works on its own', () => {
  assert.equal(new PorClient({ deployment: MAINNET }).deployment, MAINNET);
});

test('matching network + deployment is allowed', () => {
  assert.equal(new PorClient({ network: 'mainnet', deployment: MAINNET }).deployment, MAINNET);
});

test('conflicting network + deployment throws', () => {
  assert.throws(() => new PorClient({ network: 'mainnet', deployment: TESTNET }), /conflicts/);
});

test('unknown network throws', () => {
  assert.throws(() => new PorClient({ network: 'mainet' }), /unknown network/);
});

test('unknown option throws instead of being ignored', () => {
  assert.throws(() => new PorClient({ chain: 'mainnet' }), /unknown option "chain"/);
});
