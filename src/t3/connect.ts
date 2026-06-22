/**
 * Establish an authenticated session with a live Terminal 3 node.
 * Shared by the live executor and the contract-deploy tooling.
 */
import {
  T3nClient,
  loadWasmComponent,
  createDefaultHandlers,
  createEthAuthInput,
  eth_get_address,
  metamask_sign,
  NODE_URLS,
} from "@terminal3/t3n-sdk";
import type { AegisConfig } from "../config.js";

export interface T3nConnection {
  client: T3nClient;
  /** The opaque, node-assigned DID for this account. */
  did: string;
  baseUrl: string;
  address: string;
}

export async function connectT3n(cfg: AegisConfig): Promise<T3nConnection> {
  const baseUrl = cfg.nodeUrl ?? NODE_URLS[cfg.environment];
  const address = eth_get_address(cfg.apiKey);
  const wasmComponent = await loadWasmComponent();
  const client = new T3nClient({
    baseUrl,
    wasmComponent,
    handlers: {
      ...createDefaultHandlers(baseUrl),
      EthSign: metamask_sign(address, undefined, cfg.apiKey),
    },
  });
  await client.handshake();
  const did = await client.authenticate(createEthAuthInput(address));
  return { client, did: did.value, baseUrl, address };
}
