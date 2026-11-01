// The DigestMultibase of a JSON document, as DTG credentials bind to one another: base58btc multibase ("z") of a sha2-256
// multihash (0x12, 0x20, then the 32 bytes) over the RFC 8785 (JCS) form of the document with its `proof` removed. This is
// dtg-credentials' `digest_multibase_json`, which the VTC uses to check a member's acknowledgement against the grant it issued
// (vtc-service members/inbound_vmc.rs at the pinned VTC). Equality is over the decoded bytes, never the encoded string.
import { sha256 } from "@noble/hashes/sha2.js";
import { base58 } from "@scure/base";
import { canonicalBytes } from "@openvtc/trust-tasks-proof";

/** `z` + base58btc(0x12 0x20 || sha256(JCS(doc without `proof`))). */
export function digestMultibase(doc: Record<string, unknown>): string {
  const { proof: _proof, ...unproofed } = doc;
  return "z" + base58.encode(Uint8Array.from([0x12, 0x20, ...sha256(canonicalBytes(unproofed))]));
}

/** Whether two DigestMultibase values name the same sha2-256 digest (both must be base58btc multihashes). */
export function digestsMatch(a: string, b: string): boolean {
  const bytes = (s: string) => {
    if (!s.startsWith("z")) throw new Error("digest is not base58btc multibase");
    const d = base58.decode(s.slice(1));
    if (d.length !== 34 || d[0] !== 0x12 || d[1] !== 0x20) throw new Error("digest is not a sha2-256 multihash");
    return d;
  };
  const x = bytes(a), y = bytes(b);
  return x.every((v, i) => v === y[i]);
}
