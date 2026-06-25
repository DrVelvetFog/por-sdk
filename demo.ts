// Proves the SDK reads real PoR credentials from testnet.
// The default address received an L0 credential during attestor testing.
import { PorClient, Level } from './src/index.js';

const owner =
  process.argv[2] ||
  '0x43a5782881f7ae4584fb7a3d9d9b3cd3440ed634a67301de5e45f734505e8e7d';

const por = new PorClient(); // defaults to PoR testnet

const cred = await por.getCredential(owner);
console.log('owner:', owner);
console.log('credential:', cred);

for (const lvl of [Level.DeviceHuman, Level.Phone, Level.RealAction]) {
  console.log(`isVerified(>= L${lvl}):`, await por.isVerified(owner, lvl));
}
