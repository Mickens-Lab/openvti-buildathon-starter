// Reply proofs are checked and reported, never used to fail a call.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { signTrustTask, type Signer } from "@openvtc/trust-tasks-proof";
import { VtaClient, checkReplyProof, newIdentity, type CallEvent } from "../src/index.js";

const VTA = "did:webvh:Qmfake:localhost%3A8100";
const seed = ed25519.utils.randomSecretKey();
const signer: Signer = { curve: "ed25519", did: VTA, verificationMethod: `${VTA}#key-0`, sign: (h) => ed25519.sign(h, seed) };
const pub = "z" + base58.encode(Uint8Array.from([0xed, 0x01, ...ed25519.getPublicKey(seed)]));
const ddoc = { id: VTA, verificationMethod: [{ id: `${VTA}#key-0`, type: "Multikey", controller: VTA, publicKeyMultibase: pub }], authentication: [`${VTA}#key-0`], assertionMethod: [`${VTA}#key-0`] };
const reply = (over: Record<string, unknown> = {}) =>
  signTrustTask({ id: "r1", type: "https://trusttasks.org/spec/auth/whoami/0.1#response", issuer: VTA, threadId: "q1", issuedAt: "2026-10-31T12:00:00Z", payload: {}, ...over } as any, signer, { proofPurpose: "authentication" }) as any;
const doc = async () => ddoc;

test("checkReplyProof: verified, unsigned, wrong signer, tampered, key not listed for the purpose, document unreadable", async () => {
  assert.equal(await checkReplyProof(reply(), VTA, doc), "verified");
  const { proof: _p, ...bare } = reply();
  assert.equal(await checkReplyProof(bare, VTA, doc), "unsigned");
  assert.equal(await checkReplyProof(reply(), "did:example:other", doc), "wrongSigner");
  const tampered = reply();
  tampered.payload = { roles: ["admin"] };
  assert.equal(await checkReplyProof(tampered, VTA, doc), "invalid");
  assert.equal(await checkReplyProof(reply(), VTA, async () => ({ ...ddoc, authentication: [] })), "invalid");
  assert.equal(await checkReplyProof(reply(), VTA, async () => { throw new Error("offline"); }), "unchecked");
});

test("VtaClient reports replyProof on the onCall event and still returns the payload of a reply that fails it", async () => {
  const events: CallEvent[] = [];
  let forge = false;
  const c = new VtaClient("http://vta.test", VTA, newIdentity(), (async (u: any, init: any) => {
    if (String(u).endsWith("/.well-known/did.jsonl")) return new Response(JSON.stringify({ state: ddoc }));
    const d = JSON.parse(init.body);
    const r = reply({ type: `${d.type}#response`, threadId: d.id, payload: { ok: 1 } });
    if (forge) r.payload = { ok: 2 };
    return new Response(JSON.stringify(r));
  }) as typeof fetch);
  c.onCall = (e) => events.push(e);
  assert.deepEqual(await c.whoami(), { ok: 1 });
  forge = true;
  assert.deepEqual(await c.whoami(), { ok: 2 });
  assert.deepEqual(events.map((e) => e.replyProof), ["verified", "invalid"]);
});
