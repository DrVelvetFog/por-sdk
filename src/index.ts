import type { SuiClientTypes } from '@mysten/sui/client';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction } from '@mysten/sui/transactions';
import type { TransactionObjectArgument } from '@mysten/sui/transactions';
import { bcs } from '@mysten/sui/bcs';
import { TESTNET, MAINNET, CLOCK_ID, type Deployment } from './deployment.js';

/** BN254 scalar-field modulus (used to reduce an address to the bound signal). */
const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Any valid address works as a read-only-simulation sender for view calls. */
const READ_SENDER = '0x0000000000000000000000000000000000000000000000000000000000000000';

/**
 * The field-reduced "signal" a prover must commit to (`signalHash`) to bind a
 * uniqueness proof to `address`. Matches `por::uniqueness::signal_for` on-chain.
 * Pass this as the circuit's `signalHash` input when generating the proof.
 */
export function signalFor(address: string): bigint {
  return BigInt(address) % FR_MODULUS;
}

/** Canonical real-world-action vouch layout. Field ORDER is the signing contract
 *  and MUST match the PoR attestor's verifier (`attestor/src/action-vouch.mjs`
 *  `RealActionVouch`). Numbers are rounded so signer and verifier agree.
 *
 *  `device_nullifier` is the device-rooted personhood binding: a
 *  context-scoped one-way hash of the source device's App Attest / Play Integrity
 *  key id (`H(key_id, por_context)`), so PoR can dedup one credential per physical
 *  device on-chain. Empty (`[]`) when the source has no device attestation yet —
 *  legacy / harness / rollout. See docs/DEVICE_ROOTED_PERSONHOOD.md. */
const RealActionVouchBcs = bcs.struct('RealActionVouch', {
  user: bcs.Address,
  steps: bcs.u64(),
  elapsed_ms: bcs.u64(),
  gps_distance_m: bcs.u64(),
  issued_at_ms: bcs.u64(),
  expiry_ms: bcs.u64(),
  device_nullifier: bcs.vector(bcs.u8()),
});

/** Serialize the exact bytes a trusted source signs / the attestor verifies.
 *  `deviceNullifier` defaults to empty — the no-device path. */
export function realActionVouchBytes(p: {
  address: string;
  session: RealActionSession;
  issuedAtMs: number;
  expiryMs: number;
  deviceNullifier?: number[] | Uint8Array;
}): Uint8Array {
  return RealActionVouchBcs.serialize({
    user: p.address,
    steps: BigInt(Math.round(p.session.steps)),
    elapsed_ms: BigInt(Math.round(p.session.elapsedMs ?? 0)),
    gps_distance_m: BigInt(Math.round(p.session.gpsDistanceM ?? 0)),
    issued_at_ms: BigInt(p.issuedAtMs),
    expiry_ms: BigInt(p.expiryMs),
    device_nullifier: Array.from(p.deviceNullifier ?? []),
  }).toBytes();
}

/**
 * Sign a real-world-action vouch with a trusted source's ed25519 key. A source
 * (e.g. a fitness attestor) calls this AFTER its own validation of the walk, then
 * passes the vouch to {@link PorClient.requestRealActionUpgrade}. PoR verifies the
 * signature against the source's registered public key and grants L2 on that
 * basis — so L2 rests on the source's witness, not self-reported numbers.
 *
 * `keypair` is any signer with a raw-ed25519 `sign` (e.g. `@mysten/sui`'s
 * `Ed25519Keypair`). Default validity window is 5 minutes.
 */
export async function signRealActionVouch(
  keypair: { sign(data: Uint8Array): Promise<Uint8Array> },
  params: {
    address: string;
    session: RealActionSession;
    ttlMs?: number;
    /** Device-rooted personhood binding. 32 bytes when the source has
     *  device attestation, else omit/empty for the no-device path. The exact
     *  bytes are carried back on the returned vouch so the attestor can
     *  reconstruct + verify, and the chain can dedup. */
    deviceNullifier?: number[] | Uint8Array;
  },
): Promise<RealActionVouch> {
  const issuedAtMs = Date.now();
  const expiryMs = issuedAtMs + (params.ttlMs ?? 5 * 60_000);
  const deviceNullifier = Array.from(params.deviceNullifier ?? []);
  const bytes = realActionVouchBytes({
    address: params.address,
    session: params.session,
    issuedAtMs,
    expiryMs,
    deviceNullifier,
  });
  const signature = await keypair.sign(bytes);
  return { issuedAtMs, expiryMs, signature: Array.from(signature), deviceNullifier };
}

/**
 * Canonical L2-assertion clientData (H1 — device-signed sensor session). When the
 * walker's device produces an Apple App Attest assertion for an L2 upgrade, it MUST
 * sign `SHA256(utf8(this string))`, so a genuine device can't sign arbitrary bytes
 * while reporting different walk numbers. Binds a domain tag ‖ holder address ‖
 * credential id ‖ the session numbers ‖ a device timestamp (freshness/replay).
 *
 * CONTRACT — byte-identical across all three implementations:
 *   · this function (JS clients/tests)
 *   · the PoR attestor verifier (`attestor/src/app-attest.mjs` `l2AssertionClientData`)
 *   · the device signer (Yomp `ios/Yomp/Attest/AppAttest.swift` `l2ClientData`)
 * address + credId are full 0x-hex, lowercased; numbers use the same `Math.round` as
 * the vouch; fields are '\n'-joined.
 */
export function l2AssertionClientData(p: {
  address: string;
  credId: string;
  session: RealActionSession;
  issuedAtMs: number;
}): string {
  const n = (x: number | undefined) => String(Math.round(Number(x) || 0));
  return [
    'por-l2-walk-v1',
    p.address.toLowerCase(),
    p.credId.toLowerCase(),
    n(p.session.steps),
    n(p.session.elapsedMs),
    n(p.session.gpsDistanceM),
    n(p.issuedAtMs),
  ].join('\n');
}

// === SD-JWT-VC offline verification (portable, off-chain proof of a PoR cred) ===

/** The result of verifying a PoR SD-JWT-VC. */
export interface PorVcResult {
  valid: true;
  issuer: string;
  subject: string;
  /** The holder's Sui address, recovered from the did:pkh subject. */
  address: string;
  credId: string;
  network: string;
  /** Selectively-disclosed claims (e.g. `effort`, `unique`). */
  claims: Record<string, unknown>;
  /** Expiry in ms, if present. */
  expiresAtMs?: number;
}

function b64urlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const b64urlToString = (s: string) => new TextDecoder().decode(b64urlToBytes(s));
function bytesToB64url(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function sha256B64url(input: string): Promise<string> {
  const hash = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(input) as BufferSource);
  return bytesToB64url(new Uint8Array(hash));
}

/** did:web:host(:path) -> https://host(/path)/.well-known/jwks.json */
function didWebToJwksUrl(iss: string): string {
  const parts = iss.replace(/^did:web:/, '').split(':').map(decodeURIComponent);
  const host = parts[0];
  const path = parts.slice(1).join('/');
  return `https://${host}${path ? '/' + path : ''}/.well-known/jwks.json`;
}

/**
 * Verify a PoR SD-JWT-VC fully offline: checks the EdDSA signature against the
 * issuer's published JWKS, the expiry, and that every presented disclosure is
 * committed in `_sd`. Returns the issuer, the holder's Sui address, and the
 * disclosed claims. Revocation is intentionally separate (check on-chain via
 * `PorClient`, or the issuer's `/api/vc/status/:credId`).
 */
export async function verifyPorVc(
  sdjwt: string,
  opts: { jwksUrl?: string; now?: number } = {},
): Promise<PorVcResult> {
  const [jwt, ...disclosures] = sdjwt.split('~');
  const discs = disclosures.filter(Boolean);
  const [h, p, sig] = jwt.split('.');
  const header = JSON.parse(b64urlToString(h));
  const payload = JSON.parse(b64urlToString(p));

  const jwksUrl = opts.jwksUrl ?? didWebToJwksUrl(payload.iss);
  const { keys } = await (await fetch(jwksUrl)).json();
  const jwk = keys.find((k: { kid?: string }) => k.kid === header.kid) ?? keys[0];
  const key = await globalThis.crypto.subtle.importKey(
    'jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, { name: 'Ed25519' }, false, ['verify'],
  );
  const ok = await globalThis.crypto.subtle.verify(
    'Ed25519', key, b64urlToBytes(sig) as BufferSource, new TextEncoder().encode(`${h}.${p}`) as BufferSource,
  );
  if (!ok) throw new Error('PoR VC signature invalid');

  const now = opts.now ?? Date.now();
  if (payload.exp && now / 1000 >= payload.exp) throw new Error('PoR VC expired');

  const sd: string[] = payload._sd ?? [];
  const claims: Record<string, unknown> = {};
  for (const disc of discs) {
    if (!sd.includes(await sha256B64url(disc))) throw new Error('disclosure not committed in _sd');
    const [, name, value] = JSON.parse(b64urlToString(disc));
    claims[name] = value;
  }

  return {
    valid: true,
    issuer: payload.iss,
    subject: payload.sub,
    address: String(payload.sub).split(':').pop() as string,
    credId: payload.por?.credId,
    network: payload.por?.network,
    claims,
    expiresAtMs: payload.exp ? payload.exp * 1000 : undefined,
  };
}

export { TESTNET, MAINNET, CLOCK_ID, type Deployment } from './deployment.js';

/** PoR assurance levels. Higher = harder to fake. */
export enum Level {
  /** L0 — genuine device + live human. */
  DeviceHuman = 0,
  /** L1 — + phone/SIM uniqueness. */
  Phone = 1,
  /** L2 — + real-world-action history & continuous re-attestation. */
  RealAction = 2,
  /** L3 — + unique verified person (KYC/biometric partner). */
  UniquePerson = 3,
}

/** A parsed RealHumanCredential. */
export interface Credential {
  id: string;
  level: Level;
  /** Unix ms; 0 means never expires. */
  expiresAtMs: number;
  issuedAtMs: number;
  /** Hex commitment to the holder's device key (not the raw key). */
  deviceCommitment: string;
  attestor: string;
}

/** A reported real-world-action session. The attestor validates it (anti-cheat
 *  + step bar) before signing an upgrade. */
export interface RealActionSession {
  /** Steps in this session. */
  steps: number;
  /** Wall-clock duration in ms (enables a cadence check). */
  elapsedMs?: number;
  /** GPS distance in metres (enables a stride check). */
  gpsDistanceM?: number;
}

/** A trusted real-world-action source's signature attesting that IT witnessed
 *  this exact session for this user. Produce one with {@link signRealActionVouch}
 *  and pass it to {@link PorClient.requestRealActionUpgrade}; the attestor grants
 *  L2 on the strength of the source's signature rather than self-reported numbers
 *  (when it runs with the vouch requirement on). */
export interface RealActionVouch {
  issuedAtMs: number;
  expiryMs: number;
  signature: number[];
  /** Device-rooted personhood nullifier the signature binds (32 bytes, or `[]`
   *  for the no-device path). Forwarded to the attestor so it reconstructs the
   *  exact signed bytes and the chain dedups it (genuine-device + real-action per
   *  credential — not a per-physical-device cap; see DEVICE_ROOTED_PERSONHOOD.md). */
  deviceNullifier: number[];
}

/** A PoR attestor's signed authorization to raise a credential to L2.
 *  Everything needed to build the on-chain `attest_real_action_v2` call. */
/** A K-of-N quorum authorization (item 7): K signatures over the same canonical
 *  attestation bytes, by `signerIndices[i]` → the on-chain `AttestorQuorum.pubkeys`.
 *  Present instead of a single `signature` when the attestor runs a quorum. */
export interface QuorumAuth {
  quorumId: string;
  signatures: number[][];
  signerIndices: number[];
}

export interface RealActionAuthorization {
  packageId: string;
  actionRegistryId: string;
  /** Shared DeviceRegistry — the device-nullifier dedup set. */
  deviceRegistryId: string;
  /** Main Registry — needed only for the recovery (rebind) path. */
  registryId?: string;
  clockId: string;
  credId: string;
  newLevel: number;
  newExpiresAtMs: number;
  nonce: number;
  sigExpiryMs: number;
  /** Device nullifier the attestor's signature binds (32 bytes, or `[]` for the
   *  legacy no-device path while on-chain `require_nullifier` is off). */
  deviceNullifier: number[];
  /** Single-key authorization. Absent when a `quorum` authorization is used instead. */
  signature?: number[];
  /** K-of-N quorum authorization (item 7) — present instead of `signature` when the
   *  attestor runs a quorum. Routes to `attest_real_action_v3_quorum`. */
  quorum?: QuorumAuth;
  /** True when the attestor accepted a trusted-source vouch for this upgrade. */
  vouched?: boolean;
  /** True when the device nullifier is already bound to a *different* (stranded)
   *  credential — submit with `buildRecoverRealActionTx` to rebind + revoke. */
  recover?: boolean;
  /** On-chain attestation version the attestor signed: 2 (default) or 3. v3 (H2+A3)
   *  binds `registryId` for domain separation and the on-chain path enforces
   *  revocation, so the tx passes the main Registry. The builders route automatically. */
  attestationVersion?: number;
}

/** An attestor's signed authorization to bind an externally-verified nullifier. */
export interface UniquenessAuthorization {
  packageId: string;
  uniquenessRegistryId: string;
  offchainAttestorId: string;
  registryId: string;
  clockId: string;
  credId: string;
  nullifier: number[];
  nonce: number;
  sigExpiryMs: number;
  /** Single-key authorization. Absent when a `quorum` authorization is used instead. */
  signature?: number[];
  /** K-of-N quorum authorization (item 7) — present instead of `signature` on a first
   *  bind when the attestor runs a quorum. Routes to `attest_unique_quorum`. */
  quorum?: QuorumAuth;
  /** True if the nullifier is already bound — use buildAttestRecoverUniqueTx. */
  recover: boolean;
}

/** A recovery authorization (D1): like {@link UniquenessAuthorization} but always a
 *  rebind (`recover: true`), and it names the stranded credential the rebind revokes. */
export interface RecoveryAuthorization extends UniquenessAuthorization {
  /** The credential currently holding the signal — this recovery revokes it. */
  strandedCredId: string;
}

/**
 * The transport surface PorClient reads through — the two v2 core methods it
 * uses. Satisfied by `SuiGrpcClient` (the default), the v2 JSON-RPC client, or
 * any custom wrapper (failover, private endpoints, …).
 */
export type PorSuiTransport = Pick<
  SuiClientTypes.TransportMethods,
  'listOwnedObjects' | 'simulateTransaction'
>;

export interface PorClientOptions {
  /**
   * Provide your own Sui client (e.g. a `SuiGrpcClient` pointed at a private
   * endpoint), or omit to use gRPC against the deployment network's public
   * fullnode. Mysten retired public JSON-RPC on fullnode.*.sui.io (2026-07),
   * so the default transport is gRPC on the same hosts.
   */
  suiClient?: PorSuiTransport;
  /** Override on-chain addresses. Defaults to PoR testnet. */
  deployment?: Deployment;
  /**
   * Shorthand for PoR's own deployments: `'mainnet'` = `MAINNET`, `'testnet'` =
   * `TESTNET`. If you also pass `deployment`, its `network` must match.
   */
  network?: 'testnet' | 'mainnet';
}

const KNOWN_OPTIONS = new Set(['suiClient', 'deployment', 'network']);
const BY_NETWORK: Record<string, Deployment> = { testnet: TESTNET, mainnet: MAINNET };

/** Resolve the deployment, refusing anything ambiguous. A silently-ignored option
 *  here means gating on the wrong chain (testnet credentials are free to mint), so
 *  unknown keys, unknown networks and conflicting settings all throw. */
function resolveDeployment(opts: PorClientOptions): Deployment {
  for (const k of Object.keys(opts)) {
    if (!KNOWN_OPTIONS.has(k)) {
      throw new Error(`PorClient: unknown option "${k}" — expected suiClient, deployment or network`);
    }
  }
  if (opts.network === undefined) return opts.deployment ?? TESTNET;
  const byNet = BY_NETWORK[opts.network];
  if (!byNet) throw new Error(`PorClient: unknown network "${String(opts.network)}" — use 'testnet' or 'mainnet'`);
  if (opts.deployment && opts.deployment.network !== opts.network) {
    throw new Error(`PorClient: network "${opts.network}" conflicts with deployment.network "${opts.deployment.network}"`);
  }
  return opts.deployment ?? byNet;
}

const CRED_SUFFIX = '::credential::RealHumanCredential';

function bytesToHex(bytes: number[]): string {
  return '0x' + bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Normalize a `vector<u8>` commitment field to 0x-hex. gRPC JSON renders it as
 *  base64; a JSON-RPC-shaped client yields a number array; already-hex passes through. */
function commitmentToHex(v: unknown): string {
  if (Array.isArray(v)) return bytesToHex(v as number[]);
  if (typeof v === 'string' && !v.startsWith('0x') && v !== '') {
    try { return bytesToHex(Array.from(b64urlToBytes(v))); } catch { /* fall through */ }
  }
  return String(v ?? '');
}

/** One attestor URL, or an ordered list (primary first) for redundancy/failover. */
export type AttestorUrls = string | string[];

/**
 * POST JSON to the first reachable attestor (D3 redundancy/failover).
 *
 * A PoR attestor is a STATELESS signer over shared on-chain state — every replica
 * gives the same answer for the same request — so trying another on failure is safe
 * and idempotent (the user, not the attestor, submits the resulting tx). Behaviour:
 *   · transport failure (DNS/connection/abort/timeout) → try the next URL;
 *   · 5xx or 429 (instance unhealthy / throttling / cold) → try the next URL;
 *   · any other 4xx (bad input, anti-cheat, ownership, revoked) is a DETERMINISTIC
 *     rejection — surfaced immediately, since every replica would reject it too.
 * Throws an aggregated error only when no replica was reachable.
 *
 * `timeoutMs` (optional) bounds each attempt so one hung replica can't block the
 * whole list; omit it to rely on the platform default (e.g. tolerate a cold start).
 */
async function postToAttestor<T>(
  attestorUrl: AttestorUrls,
  path: string,
  body: unknown,
  opts: { timeoutMs?: number } = {},
): Promise<T> {
  const urls = (Array.isArray(attestorUrl) ? attestorUrl : [attestorUrl])
    .map((u) => (u || '').replace(/\/$/, ''))
    .filter(Boolean);
  if (urls.length === 0) throw new Error('no attestor URL provided');

  const failures: string[] = [];
  for (const base of urls) {
    const url = base + path;
    let res: Response;
    try {
      const ctrl = opts.timeoutMs != null ? new AbortController() : undefined;
      const timer = ctrl ? setTimeout(() => ctrl.abort(), opts.timeoutMs) : undefined;
      try {
        res = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
          signal: ctrl?.signal,
        });
      } finally {
        if (timer) clearTimeout(timer);
      }
    } catch (e) {
      failures.push(`${url}: ${(e as Error)?.message ?? 'fetch failed'}`);
      continue; // transport failure → next replica
    }

    let parsed: (T & { error?: string }) | undefined;
    try { parsed = (await res.json()) as T & { error?: string }; } catch { parsed = undefined; }
    if (res.ok) return parsed as T;
    if (res.status >= 500 || res.status === 429) {
      failures.push(`${url}: ${parsed?.error ?? `HTTP ${res.status}`}`);
      continue; // instance unhealthy/throttling → next replica
    }
    // Deterministic rejection — another replica would answer identically.
    throw new Error(parsed?.error ?? `attestor returned ${res.status}`);
  }
  throw new Error(`all attestors unreachable: ${failures.join('; ')}`);
}

/**
 * Read + gate on PoR credentials.
 *
 * The "3 lines to gate your airdrop":
 *   const por = new PorClient();
 *   if (!(await por.isVerified(address, Level.DeviceHuman)))
 *     throw new Error('Not a verified human');
 */
export class PorClient {
  readonly client: PorSuiTransport;
  readonly deployment: Deployment;

  constructor(opts: PorClientOptions = {}) {
    this.deployment = resolveDeployment(opts ?? {});
    const network = this.deployment.network;
    this.client =
      opts.suiClient ??
      new SuiGrpcClient({
        network,
        baseUrl:
          network === 'localnet'
            ? 'http://127.0.0.1:9000'
            : `https://fullnode.${network}.sui.io:443`,
      });
  }

  /**
   * Read-only view call: simulate `tx` (no gas, no signer — `checksEnabled:
   * false` mirrors the old devInspect semantics) and return the first
   * command's first BCS return value, or `undefined` when the view aborts.
   */
  private async simulateView(tx: Transaction): Promise<{ ok: boolean; error?: string; bytes?: Uint8Array }> {
    tx.setSender(READ_SENDER);
    const r = await this.client.simulateTransaction({
      transaction: tx,
      checksEnabled: false,
      include: { commandResults: true },
    });
    const t = r.Transaction ?? r.FailedTransaction;
    if (t?.status?.success !== true) {
      return { ok: false, error: t?.status?.error?.message ?? 'simulation failed' };
    }
    return { ok: true, bytes: r.commandResults?.[0]?.returnValues?.[0]?.bcs };
  }

  /** The fully-qualified credential type for this deployment. */
  get credentialType(): string {
    return `${this.deployment.packageId}${CRED_SUFFIX}`;
  }

  /** Fetch the holder's credential, or `null` if they have none. */
  async getCredential(owner: string): Promise<Credential | null> {
    // A holder can own more than one credential (e.g. an L0 plus a separately
    // minted/upgraded one). Fetch a page and return the BEST — highest level
    // among unexpired, else highest expired — so an L2 gate isn't given a false
    // negative just because an L0 happened to be read first.
    const res = await this.client.listOwnedObjects({
      owner,
      type: this.credentialType,
      limit: 50,
      include: { json: true },
    });
    const now = Date.now();
    let best: Credential | null = null;
    let bestScore = -1;
    for (const obj of res.objects) {
      const f = obj.json as Record<string, unknown> | null;
      if (!f) continue;
      const cred: Credential = {
        id: obj.objectId,
        level: Number(f.level) as Level,
        expiresAtMs: Number(f.expires_at_ms),
        issuedAtMs: Number(f.issued_at_ms),
        deviceCommitment: commitmentToHex(f.device_commitment),
        attestor: String(f.attestor),
      };
      // Rank: any unexpired cred beats any expired one; within that, higher level wins.
      const unexpired = cred.expiresAtMs === 0 || now < cred.expiresAtMs;
      const score = (unexpired ? 1000 : 0) + cred.level;
      if (score > bestScore) { best = cred; bestScore = score; }
    }
    return best;
  }

  /** True if `cred` is unexpired and at least `minLevel`. */
  static meets(cred: Credential | null, minLevel: Level = Level.DeviceHuman, now = Date.now()): boolean {
    if (!cred) return false;
    const unexpired = cred.expiresAtMs === 0 || now < cred.expiresAtMs;
    return cred.level >= minLevel && unexpired;
  }

  /**
   * Off-chain: has `credId` been revoked in the main Registry? Read-only
   * simulation of `registry::is_revoked` (no gas, no signer). Folded into
   * {@link isVerified} by default; call directly if you track revocation on
   * your own cadence.
   */
  async isRevoked(credId: string): Promise<boolean> {
    const tx = new Transaction();
    tx.moveCall({
      target: `${this.deployment.packageId}::registry::is_revoked`,
      arguments: [tx.object(this.deployment.registryId), tx.object(credId)],
    });
    const r = await this.simulateView(tx);
    if (!r.ok) throw new Error(`revocation check failed: ${r.error}`);
    return r.bytes?.[0] === 1;
  }

  /**
   * Off-chain gate: does `owner` hold a VALID credential at >= `minLevel`?
   * "Valid" = present, unexpired, level high enough, AND not revoked — all three by
   * default. Revocation costs one extra read-only devInspect; pass
   * `{ checkRevocation: false }` to skip it where revocation can't apply or latency
   * is critical. Fails closed: if the best credential is revoked, the gate returns
   * false (a false negative is the safe direction for a gate).
   *
   * Any off-chain read has a check→act gap (the holder could be revoked, or swap
   * credentials, between this read and your action). For high-value gates, enforce
   * atomically in the same transaction with {@link requireVerified}.
   */
  async isVerified(
    owner: string,
    minLevel: Level = Level.DeviceHuman,
    opts: { checkRevocation?: boolean } = {},
  ): Promise<boolean> {
    const cred = await this.getCredential(owner);
    if (!PorClient.meets(cred, minLevel)) return false;
    if (opts.checkRevocation === false) return true;
    return !(await this.isRevoked(cred!.id));
  }

  /**
   * On-chain gate (recommended for high-value flows): add a `require_verified` call
   * to a PTB so the credential is presented and checked IN THE SAME transaction as
   * your gated action — closing the check→act gap the off-chain {@link isVerified}
   * can't. The transaction aborts unless the credential meets the level, is unexpired,
   * AND (by default) is not revoked.
   *
   * By default targets the revocation-aware `registry::require_verified` (level +
   * expiry + not-revoked), adding the shared Registry as a read-only input. Pass
   * `{ checkRevocation: false }` for the lighter `credential::require_verified` (level
   * + expiry only, no Registry input) when revocation can't apply to your flow.
   */
  requireVerified(
    tx: Transaction,
    args: { credential: string | TransactionObjectArgument; minLevel?: Level; checkRevocation?: boolean },
  ): void {
    const cred = typeof args.credential === 'string' ? tx.object(args.credential) : args.credential;
    const minLevel = tx.pure.u8(args.minLevel ?? Level.DeviceHuman);
    if (args.checkRevocation === false) {
      tx.moveCall({
        target: `${this.deployment.packageId}::credential::require_verified`,
        arguments: [cred, minLevel, tx.object(CLOCK_ID)],
      });
      return;
    }
    tx.moveCall({
      target: `${this.deployment.packageId}::registry::require_verified`,
      arguments: [tx.object(this.deployment.registryId), cred, minLevel, tx.object(CLOCK_ID)],
    });
  }

  /**
   * Ask a PoR attestor to validate a real-world action and sign an L2 upgrade.
   * The attestor checks anti-cheat + that `credId` is owned by `address`, then
   * returns a signed authorization. Submit it with `buildRealActionUpgradeTx`.
   *
   * The L2 upgrade in two lines:
   *   const auth = await por.requestRealActionUpgrade(ATTESTOR_URL, { address, credId, session });
   *   por.buildRealActionUpgradeTx(tx, auth);   // holder signs + submits (sponsor the gas)
   *
   * A real-world-action *source* (e.g. a fitness attestor) additionally passes a
   * `vouch` from {@link signRealActionVouch} plus its registered `source` id, so
   * the attestor grants L2 on the source's signature rather than self-reported
   * numbers. `vouch`/`source` are simply forwarded in the request body.
   *
   * `attestorUrl` may be an ordered list for redundancy — the first reachable
   * replica wins, deterministic rejections surface immediately (see {@link postToAttestor}).
   */
  async requestRealActionUpgrade(
    attestorUrl: AttestorUrls,
    params: {
      address: string;
      credId: string;
      session: RealActionSession;
      vouch?: RealActionVouch;
      source?: string;
      /** App Attest payload for device-rooted personhood. The attestor
       *  verifies genuineness off-chain and derives the device nullifier the chain
       *  dedups. `simulatedKeyId` is a testnet-only path (no real attestation). */
      appAttest?: {
        keyId?: string;
        attestationB64?: string;
        /** Per-walk assertion (continuous re-attestation) + the request bytes it
         *  was signed over. Attestation is re-sent alongside it for the key. */
        assertionB64?: string;
        clientDataB64?: string;
        challengeB64?: string;
        simulatedKeyId?: string;
      };
    },
    opts: { timeoutMs?: number } = {},
  ): Promise<RealActionAuthorization> {
    return postToAttestor<RealActionAuthorization>(attestorUrl, '/api/attest/real-action', params, opts);
  }

  /**
   * Add the on-chain `action_attestor::attest_real_action_v2` call to a PTB,
   * using a signed authorization from `requestRealActionUpgrade`. The holder
   * signs + submits (sponsor the gas for a seedless flow). Raises the credential
   * to L2 and dedups the device nullifier on-chain (device-rooted personhood).
   *
   * If `auth.recover` is set, routes to `buildRecoverRealActionTx` instead — the
   * device nullifier is already bound to a stranded credential, so this rebinds.
   */
  /**
   * Holder self-revocation: adds `registry::revoke_own` to `tx`. The holder signs (only
   * the owner can pass their credential). Permanent; the device slot is not freed.
   * Needs a deployment with `latestPackageId` (testnet v9+; not yet on mainnet).
   */
  buildRevokeOwnTx(tx: Transaction, credId: string): void {
    const pkg = this.deployment.latestPackageId;
    if (!pkg) throw new Error('this deployment has no latestPackageId — self-revocation needs PoR package v9+');
    tx.moveCall({
      target: `${pkg}::registry::revoke_own`,
      arguments: [tx.object(this.deployment.registryId), tx.object(credId)],
    });
  }

  buildRealActionUpgradeTx(tx: Transaction, auth: RealActionAuthorization): void {
    if (auth.recover) {
      this.buildRecoverRealActionTx(tx, auth);
      return;
    }
    if (auth.quorum) {
      // K-of-N quorum upgrade (item 7): same v3 message, verified against the AttestorQuorum.
      if (!auth.registryId) throw new Error('quorum upgrade requires auth.registryId (main Registry)');
      tx.moveCall({
        target: `${auth.packageId}::action_attestor::attest_real_action_v3_quorum`,
        arguments: [
          tx.object(auth.actionRegistryId),
          tx.object(auth.quorum.quorumId),
          tx.object(auth.deviceRegistryId),
          tx.object(auth.registryId),
          tx.object(auth.credId),
          tx.pure.u8(auth.newLevel),
          tx.pure.u64(BigInt(auth.newExpiresAtMs)),
          tx.pure.u64(BigInt(auth.nonce)),
          tx.pure.u64(BigInt(auth.sigExpiryMs)),
          tx.pure.vector('u8', auth.deviceNullifier),
          tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(auth.quorum.signatures).toBytes()),
          tx.pure.vector('u8', auth.quorum.signerIndices),
          tx.object(auth.clockId),
        ],
      });
      return;
    }
    if (!auth.signature) throw new Error('authorization has neither a signature nor a quorum');
    if (auth.attestationVersion === 3) {
      // v3 (H2+A3): inserts the main Registry (revocation check + domain separation).
      if (!auth.registryId) throw new Error('v3 upgrade requires auth.registryId (main Registry)');
      tx.moveCall({
        target: `${auth.packageId}::action_attestor::attest_real_action_v3`,
        arguments: [
          tx.object(auth.actionRegistryId),
          tx.object(auth.deviceRegistryId),
          tx.object(auth.registryId),
          tx.object(auth.credId),
          tx.pure.u8(auth.newLevel),
          tx.pure.u64(BigInt(auth.newExpiresAtMs)),
          tx.pure.u64(BigInt(auth.nonce)),
          tx.pure.u64(BigInt(auth.sigExpiryMs)),
          tx.pure.vector('u8', auth.deviceNullifier),
          tx.pure.vector('u8', auth.signature),
          tx.object(auth.clockId),
        ],
      });
      return;
    }
    tx.moveCall({
      target: `${auth.packageId}::action_attestor::attest_real_action_v2`,
      arguments: [
        tx.object(auth.actionRegistryId),
        tx.object(auth.deviceRegistryId),
        tx.object(auth.credId),
        tx.pure.u8(auth.newLevel),
        tx.pure.u64(BigInt(auth.newExpiresAtMs)),
        tx.pure.u64(BigInt(auth.nonce)),
        tx.pure.u64(BigInt(auth.sigExpiryMs)),
        tx.pure.vector('u8', auth.deviceNullifier),
        tx.pure.vector('u8', auth.signature),
        tx.object(auth.clockId),
      ],
    });
  }

  /**
   * Add the on-chain `action_attestor::attest_recover_real_action[_v3]` call to a PTB.
   * Used when the human lost their device: the new device's nullifier rebinds the
   * credential from the stranded one (which is revoked). Requires `auth.registryId`
   * (the main Registry, for the revoke). The new-device holder signs + submits. Routes
   * to the v3 function when `auth.attestationVersion === 3` (same arg shape).
   */
  buildRecoverRealActionTx(tx: Transaction, auth: RealActionAuthorization): void {
    if (!auth.registryId) throw new Error('recovery requires auth.registryId (main Registry)');
    if (!auth.signature) throw new Error('recovery requires a single signature (quorum recovery is not supported)');
    const fn = auth.attestationVersion === 3 ? 'attest_recover_real_action_v3' : 'attest_recover_real_action';
    tx.moveCall({
      target: `${auth.packageId}::action_attestor::${fn}`,
      arguments: [
        tx.object(auth.actionRegistryId),
        tx.object(auth.deviceRegistryId),
        tx.object(auth.registryId),
        tx.object(auth.credId),
        tx.pure.u8(auth.newLevel),
        tx.pure.u64(BigInt(auth.newExpiresAtMs)),
        tx.pure.u64(BigInt(auth.nonce)),
        tx.pure.u64(BigInt(auth.sigExpiryMs)),
        tx.pure.vector('u8', auth.deviceNullifier),
        tx.pure.vector('u8', auth.signature),
        tx.object(auth.clockId),
      ],
    });
  }

  // === Uniqueness (Axis 2) + recovery ===

  /**
   * Off-chain: is `credId` backed by a one-human-one-credential proof?
   * Reads `uniqueness::is_unique_id` via read-only simulation (no owned object
   * needed).
   */
  async isUniqueCredId(credId: string): Promise<boolean> {
    const { uniquenessPackageId, uniquenessRegistryId } = this.deployment;
    if (!uniquenessPackageId || !uniquenessRegistryId) return false;
    const tx = new Transaction();
    tx.moveCall({
      target: `${uniquenessPackageId}::uniqueness::is_unique_id`,
      arguments: [tx.object(uniquenessRegistryId), tx.pure.id(credId)],
    });
    const r = await this.simulateView(tx);
    return r.ok && r.bytes?.[0] === 1;
  }

  /** Off-chain: does `owner` hold a credential backed by a uniqueness proof? */
  async isUnique(owner: string): Promise<boolean> {
    const cred = await this.getCredential(owner);
    return cred ? this.isUniqueCredId(cred.id) : false;
  }

  /** Off-chain: a valid (unexpired, ≥`minLevel`, not-revoked) credential AND proven
   *  unique. Revocation is checked by default; `{ checkRevocation: false }` skips it. */
  async isVerifiedUniqueHuman(
    owner: string,
    minLevel: Level = Level.DeviceHuman,
    opts: { checkRevocation?: boolean } = {},
  ): Promise<boolean> {
    const cred = await this.getCredential(owner);
    if (!PorClient.meets(cred, minLevel)) return false;
    if (opts.checkRevocation !== false && (await this.isRevoked(cred!.id))) return false;
    return this.isUniqueCredId(cred!.id);
  }

  /**
   * On-chain gate: abort unless the credential is valid (level + unexpired + not
   * revoked) AND backed by a uniqueness proof. Compose before your protocol's gated
   * call. Like {@link requireVerified}, the level/expiry/revocation leg defaults to
   * the revocation-aware `registry::require_verified`; `{ checkRevocation: false }`
   * uses the lighter `credential::require_verified`.
   */
  requireUniqueHuman(
    tx: Transaction,
    args: { credential: string | TransactionObjectArgument; minLevel?: Level; checkRevocation?: boolean },
  ): void {
    const { uniquenessPackageId, uniquenessRegistryId, packageId, registryId } = this.deployment;
    if (!uniquenessPackageId || !uniquenessRegistryId) {
      throw new Error('deployment has no uniqueness registry configured');
    }
    const cred = typeof args.credential === 'string' ? tx.object(args.credential) : args.credential;
    const minLevel = tx.pure.u8(args.minLevel ?? Level.DeviceHuman);
    tx.moveCall({
      target: `${uniquenessPackageId}::uniqueness::assert_unique`,
      arguments: [tx.object(uniquenessRegistryId), cred],
    });
    if (args.checkRevocation === false) {
      tx.moveCall({
        target: `${packageId}::credential::require_verified`,
        arguments: [cred, minLevel, tx.object(CLOCK_ID)],
      });
      return;
    }
    tx.moveCall({
      target: `${packageId}::registry::require_verified`,
      arguments: [tx.object(registryId), cred, minLevel, tx.object(CLOCK_ID)],
    });
  }

  /**
   * Add `uniqueness::prove_unique` to a PTB. The holder presents their credential
   * and a Groth16 nullifier proof (generate it client-side with `signalFor(addr)`
   * as the circuit's `signalHash`). Binds one human to one credential.
   */
  buildProveUniqueTx(
    tx: Transaction,
    args: {
      credential: string | TransactionObjectArgument;
      publicInputs: Uint8Array | number[];
      proofPoints: Uint8Array | number[];
    },
  ): void {
    const { uniquenessPackageId, uniquenessRegistryId } = this.deployment;
    if (!uniquenessPackageId || !uniquenessRegistryId) {
      throw new Error('deployment has no uniqueness registry configured');
    }
    const cred = typeof args.credential === 'string' ? tx.object(args.credential) : args.credential;
    tx.moveCall({
      target: `${uniquenessPackageId}::uniqueness::prove_unique`,
      arguments: [
        tx.object(uniquenessRegistryId),
        cred,
        tx.pure.vector('u8', Array.from(args.publicInputs)),
        tx.pure.vector('u8', Array.from(args.proofPoints)),
      ],
    });
  }

  /**
   * Add `uniqueness::recover_unique` to a PTB. The original human re-proves the
   * same nullifier from a NEW address holding a fresh credential — the proof
   * authorizes revoking the stranded credential and rebinding to the new one.
   */
  buildRecoverUniqueTx(
    tx: Transaction,
    args: {
      newCredential: string | TransactionObjectArgument;
      publicInputs: Uint8Array | number[];
      proofPoints: Uint8Array | number[];
    },
  ): void {
    const { uniquenessPackageId, uniquenessRegistryId, registryId } = this.deployment;
    if (!uniquenessPackageId || !uniquenessRegistryId) {
      throw new Error('deployment has no uniqueness registry configured');
    }
    const cred = typeof args.newCredential === 'string' ? tx.object(args.newCredential) : args.newCredential;
    tx.moveCall({
      target: `${uniquenessPackageId}::uniqueness::recover_unique`,
      arguments: [
        tx.object(uniquenessRegistryId),
        tx.object(registryId),
        cred,
        tx.pure.vector('u8', Array.from(args.publicInputs)),
        tx.pure.vector('u8', Array.from(args.proofPoints)),
      ],
    });
  }

  // === Off-chain-verified uniqueness (World ID / passport via the attestor) ===

  /**
   * Ask a PoR attestor to verify an external uniqueness proof (World ID,
   * zkpassport, …) off-chain and sign a binding. Submit with
   * `buildAttestUniqueTx` (or `buildAttestRecoverUniqueTx` if `recover` is true).
   */
  async requestUniqueAttestation(
    attestorUrl: AttestorUrls,
    params: { address: string; credId: string; provider: string; proof: unknown },
    opts: { timeoutMs?: number } = {},
  ): Promise<UniquenessAuthorization> {
    return postToAttestor<UniquenessAuthorization>(attestorUrl, '/api/attest/unique', params, opts);
  }

  /** Add `uniqueness::attest_unique` to a PTB from a signed authorization. Routes to
   *  `attest_unique_quorum` when the authorization carries a K-of-N `quorum` (item 7). */
  buildAttestUniqueTx(
    tx: Transaction,
    auth: UniquenessAuthorization,
    credential: string | TransactionObjectArgument,
  ): void {
    const cred = typeof credential === 'string' ? tx.object(credential) : credential;
    if (auth.quorum) {
      tx.moveCall({
        target: `${auth.packageId}::uniqueness::attest_unique_quorum`,
        arguments: [
          tx.object(auth.uniquenessRegistryId),
          tx.object(auth.quorum.quorumId),
          tx.object(auth.offchainAttestorId),
          cred,
          tx.pure.vector('u8', auth.nullifier),
          tx.pure.u64(BigInt(auth.nonce)),
          tx.pure.u64(BigInt(auth.sigExpiryMs)),
          tx.pure(bcs.vector(bcs.vector(bcs.u8())).serialize(auth.quorum.signatures).toBytes()),
          tx.pure.vector('u8', auth.quorum.signerIndices),
          tx.object(auth.clockId),
        ],
      });
      return;
    }
    if (!auth.signature) throw new Error('authorization has neither a signature nor a quorum');
    tx.moveCall({
      target: `${auth.packageId}::uniqueness::attest_unique`,
      arguments: [
        tx.object(auth.uniquenessRegistryId),
        tx.object(auth.offchainAttestorId),
        cred,
        tx.pure.vector('u8', auth.nullifier),
        tx.pure.u64(BigInt(auth.nonce)),
        tx.pure.u64(BigInt(auth.sigExpiryMs)),
        tx.pure.vector('u8', auth.signature),
        tx.object(auth.clockId),
      ],
    });
  }

  /** Add `uniqueness::attest_recover_unique` to a PTB (recovery from a new address). */
  buildAttestRecoverUniqueTx(
    tx: Transaction,
    auth: UniquenessAuthorization,
    newCredential: string | TransactionObjectArgument,
  ): void {
    const cred = typeof newCredential === 'string' ? tx.object(newCredential) : newCredential;
    if (!auth.signature) throw new Error('recovery requires a single signature (quorum recovery is not supported)');
    tx.moveCall({
      target: `${auth.packageId}::uniqueness::attest_recover_unique`,
      arguments: [
        tx.object(auth.uniquenessRegistryId),
        tx.object(auth.registryId),
        tx.object(auth.offchainAttestorId),
        cred,
        tx.pure.vector('u8', auth.nullifier),
        tx.pure.u64(BigInt(auth.nonce)),
        tx.pure.u64(BigInt(auth.sigExpiryMs)),
        tx.pure.vector('u8', auth.signature),
        tx.object(auth.clockId),
      ],
    });
  }

  // === Passkey-loss / device-loss recovery (D1) ===

  /**
   * Recover personhood to a FRESH credential after losing the passkey/device that
   * held it. Personhood is anchored by the Axis-2 uniqueness signal, not the passkey:
   * re-proving the SAME signal from a new credential revokes the stranded one and
   * rebinds the nullifier (sybil-resistant — one signal, one live credential).
   *
   * The full flow:
   *   1. Re-establish an address you control + mint a fresh L0 there — zkLogin re-login
   *      ({@link deriveZkLoginAddress}; same Google ⇒ same address if the salt survives,
   *      so the credential may not even be stranded) or a NEW passkey via /begin+/finish.
   *   2. `const auth = await por.requestRecovery(URL, { address, credId, provider, proof });`
   *      (`auth.strandedCredId` is the credential this revokes — show it to the user.)
   *   3. `por.buildRecoverTx(tx, auth, credId);` — the new holder signs + submits.
   *
   * Errors if the signal isn't bound to anything yet (nothing to recover — that's a
   * first bind via {@link requestUniqueAttestation}). `attestorUrl` may be a list (failover).
   */
  async requestRecovery(
    attestorUrl: AttestorUrls,
    params: { address: string; credId: string; provider: string; proof: unknown },
    opts: { timeoutMs?: number } = {},
  ): Promise<RecoveryAuthorization> {
    return postToAttestor<RecoveryAuthorization>(attestorUrl, '/api/attest/recover', params, opts);
  }

  /** Add the recovery rebind to a PTB (alias of {@link buildAttestRecoverUniqueTx},
   *  named for the recovery flow). Revokes the stranded credential + rebinds the signal. */
  buildRecoverTx(
    tx: Transaction,
    auth: RecoveryAuthorization,
    newCredential: string | TransactionObjectArgument,
  ): void {
    this.buildAttestRecoverUniqueTx(tx, auth, newCredential);
  }

  /**
   * Re-derive a zkLogin Sui address from a fresh Google sign-in (address recovery): the
   * same Google account ⇒ the same address as long as the attestor's salt is unchanged.
   * If your credential is held by that address, you're back in — no rebind needed; the
   * passkey was only the device gesture. Returns `{ address, ... }`.
   */
  async deriveZkLoginAddress(
    attestorUrl: AttestorUrls,
    jwt: string,
    opts: { timeoutMs?: number } = {},
  ): Promise<{ address: string } & Record<string, unknown>> {
    return postToAttestor(attestorUrl, '/api/zklogin/address', { jwt }, opts);
  }
}
