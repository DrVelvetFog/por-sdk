# por-sdk

Gate any Sui app on **verified-human** credentials — in a few lines.

```bash
npm install por-sdk @mysten/sui
```

## Try it

```bash
npm install && npm run build
npm run demo                 # reads a real testnet credential
```

## Off-chain gate (show/hide a claim, gate an action)

Three lines:

```ts
import { PorClient, Level } from 'por-sdk';

const por = new PorClient();                               // 1 · testnet by default
if (!(await por.isVerified(address, Level.DeviceHuman)))   // 2 · real human?
  throw new Error('Not a verified human');                 // 3
```

`isVerified` returns true only if the address holds a PoR credential that is
**unexpired**, at **least** the level you require, and **not revoked**. All three are
checked by default; revocation costs one extra read-only call — pass
`{ checkRevocation: false }` to skip it. (Need just the revocation bit? `por.isRevoked(credId)`.)

> **Note:** `DeviceHuman` (L0) attests a genuine device + live human, **not uniqueness** —
> one operator with many devices passes L0 many times. Require `RealAction`/`UniquePerson`,
> or use `isVerifiedUniqueHuman`, where sybil-resistance matters.

> **High-value gates: prefer the on-chain gate below.** Any off-chain `isVerified`
> read has a check→act gap — the holder could be revoked, or swap credentials, between
> the read and your action. The on-chain `requireVerified` PTB enforces it atomically.

## On-chain gate (inside a Programmable Transaction)

Compose `require_verified` before your protocol's gated call — the whole
transaction aborts if the caller isn't a verified human. By default this is the
**revocation-aware** gate (level + expiry + not-revoked):

```ts
import { Transaction } from '@mysten/sui/transactions';
import { PorClient, Level } from 'por-sdk';

const por = new PorClient();
const tx = new Transaction();

// aborts unless `credentialId` is valid at >= L2 AND not revoked
por.requireVerified(tx, { credential: credentialId, minLevel: Level.RealAction });

// ...your gated move call, e.g. the airdrop claim...
tx.moveCall({ target: `${AIRDROP_PKG}::airdrop::claim`, arguments: [/* ... */] });
```

In your own Move module the gate is one line. Use `registry::require_verified` (passes
the shared `Registry`) for the revocation-aware check; `credential::require_verified`
is the lighter level+expiry-only variant:

```move
use por::registry;
registry::require_verified(&registry, cred, 2, clock); // >= L2, unexpired, not revoked
```

## Read a credential

```ts
const cred = await por.getCredential(address);
// { id, level, expiresAtMs, issuedAtMs, deviceCommitment, attestor } | null
```

## Levels

| `Level` | Meaning |
|---|---|
| `DeviceHuman` (0) | genuine device + live human |
| `Phone` (1) | + phone/SIM uniqueness |
| `RealAction` (2) | + real-world-action history & continuous re-attestation |
| `UniquePerson` (3) | + unique verified person |

## Config

`new PorClient()` defaults to PoR's testnet deployment. Override with your own
client or addresses:

```ts
new PorClient({ suiClient, deployment: { network, packageId, registryId } });
```
