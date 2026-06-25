/** On-chain deployment addresses for PoR. */
export interface Deployment {
  network: 'testnet' | 'mainnet' | 'devnet' | 'localnet';
  packageId: string;
  registryId: string;
  /** Upgraded package id that includes the `action_attestor` module (L2 real-action path). */
  actionPackageId?: string;
  /** Shared ActionRegistry holding the real-action attestor pubkey. */
  actionRegistryId?: string;
  /** Shared DeviceRegistry: the device-nullifier dedup set. Forces a genuine
   *  attested device + a real walk per L2 credential (raises per-credential cost);
   *  NOT a per-physical-device cap — see docs/DEVICE_ROOTED_PERSONHOOD.md. */
  deviceRegistryId?: string;
  /** Latest upgraded package id that includes the `uniqueness` module (Axis 2). */
  uniquenessPackageId?: string;
  /** Shared UniquenessRegistry (vk + nullifier set) for one-human-one-credential. */
  uniquenessRegistryId?: string;
  /** Canonical PoR personhood context (externalNullifier) as a decimal string. */
  porContext?: string;
  /** Shared AttestorQuorum (item 7) — N attestor pubkeys + threshold K for the K-of-N
   *  L2 / uniqueness paths. The quorum id is also returned on the attestor authorization. */
  actionQuorumId?: string;
  uniquenessQuorumId?: string;
}

export const TESTNET: Deployment = {
  network: 'testnet',
  packageId: '0xe7e692cd273ff1ed0c860e26de5f99629da73fbb41107ab26e43c5c1dbc755c7',
  registryId: '0x446ddd3bbda15b6760a54b092e84d475351480ca2a7d4a3f99265cfd7d9ae23e',
  actionPackageId: '0xe73b7c3b5b2cf533529358a0f232a0b4decbfa16456dfeb472c0e66ed79cd402',
  actionRegistryId: '0x723bb35f7ca3daabec7d6108f6c81b9d59b35cd59e5e4e217cdeb8c29351a7d2',
  deviceRegistryId: '0x57a46dc8e6f4b2b19cf05e81ff20c7d2c7f0e0f0e92911281824345ac62a0922',
  uniquenessPackageId: '0xe73b7c3b5b2cf533529358a0f232a0b4decbfa16456dfeb472c0e66ed79cd402',
  uniquenessRegistryId: '0x4ed70d45c6e5c551d1fbcfd28e416ecf623e360870a1abc1362a5b3f3193766c',
  porContext: '5892269913328866253268307249312928604523378311602329750868675706200992307667',
  actionQuorumId: '0x7291bf44d6abe68fad18ba75fecf94360aa822b6da1663493d03472f232d7221',
  uniquenessQuorumId: '0x7291bf44d6abe68fad18ba75fecf94360aa822b6da1663493d03472f232d7221',
};

export const MAINNET: Deployment = {
  network: 'mainnet',
  packageId: '0x5cd7f8c6c9adb370aa2fdfb9cc3ba93310f70b69f3e8b3596d893e8a51ac3282',
  registryId: '0x26873b0ab53768d64fb3b45ef23acfc4e1d49391d73d37331e777191137ed7c1',
};

/** Sui system clock — required by the on-chain expiry checks. */
export const CLOCK_ID = '0x6';
