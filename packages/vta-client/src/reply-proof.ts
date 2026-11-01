// Is a reply really from the agent it came back from? Over REST the reply arrives on the connection the client opened,
// so on plain http:// anything on the path could write one. This checks the reply's own proof, as wallets do for VTA
// replies: present, signed by a key of the agent's DID (by DID, purpose relationship and controller), and valid.
// It REPORTS and never refuses (v1): the result goes on the onCall event and into the trace.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { canonicalBytes, fromMultibase } from "@openvtc/trust-tasks-proof";
import { keyForPurpose } from "./did-keys.js";

/**
 * `verified`: the proof checks out against the agent's DID document. `unsigned`: no proof. `wrongSigner`: signed by
 * someone else. `invalid`: bad signature, unsupported suite, or a key not listed for the proof's purpose.
 * `unchecked`: the agent's DID document could not be read.
 */
export type ReplyProof = "verified" | "unsigned" | "wrongSigner" | "invalid" | "unchecked";

/** Check one reply document's proof against `did` and its DID document (from `didDocument`, called at most once per check). */
export async function checkReplyProof(doc: any, did: string, didDocument: () => Promise<any>): Promise<ReplyProof> {
  const proof = doc?.proof;
  if (!proof || typeof proof !== "object") return "unsigned";
  const vm = typeof proof.verificationMethod === "string" ? proof.verificationMethod : "";
  if (vm.split("#")[0] !== did || (doc.issuer !== undefined && doc.issuer !== did)) return "wrongSigner";
  if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-jcs-2022" || typeof proof.proofValue !== "string") return "invalid";
  let ddoc: any;
  try { ddoc = await didDocument(); } catch { return "unchecked"; }
  const key = keyForPurpose(ddoc, vm, did, String(proof.proofPurpose));
  if (!key) return "invalid";
  const { proof: _p, ...body } = doc;
  const { proofValue, ...config } = proof;
  try {
    const hashData = new Uint8Array([...sha256(canonicalBytes(config)), ...sha256(canonicalBytes(body))]);
    return ed25519.verify(fromMultibase(proofValue), hashData, key) ? "verified" : "invalid";
  } catch {
    return "invalid";
  }
}

/** The agent's current DID document from `{baseUrl}/.well-known/did.jsonl` (last entry; the same trust as `fetchVtaDid`). */
export async function fetchDidDocument(baseUrl: string, fetchImpl: typeof fetch): Promise<any> {
  const res = await fetchImpl(`${baseUrl}/.well-known/did.jsonl`);
  if (!res.ok) throw new Error(`GET /.well-known/did.jsonl -> HTTP ${res.status}`);
  const lines = (await res.text()).trim().split("\n");
  return JSON.parse(lines[lines.length - 1]).state;
}
