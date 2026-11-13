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

test('buildRevokeOwnTx targets the latest package with registry + credential', async () => {
  const { Transaction } = await import('@mysten/sui/transactions');
  const tx = new Transaction();
  new PorClient().buildRevokeOwnTx(tx, '0x' + '11'.repeat(32));
  const call = tx.getData().commands[0].MoveCall;
  assert.equal(`${call.package}::${call.module}::${call.function}`, `${TESTNET.latestPackageId}::registry::revoke_own`);
  assert.equal(call.arguments.length, 2);
});

test('buildRevokeOwnTx refuses a deployment without latestPackageId (mainnet today)', async () => {
  const { Transaction } = await import('@mysten/sui/transactions');
  assert.throws(() => new PorClient({ network: 'mainnet' }).buildRevokeOwnTx(new Transaction(), '0x' + '11'.repeat(32)), /latestPackageId/);
});
