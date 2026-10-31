import assert from "node:assert/strict";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58 } from "@scure/base";
import { signTrustTask, type Signer } from "@openvtc/trust-tasks-proof";
import {
  CONSENT_DECISION, CONSENT_REQUEST, TrustTaskError, buildDecision, consentRequiredOf, extractRequests, identityFromSeed,
  keyFromDidDocument, matchCode, newIdentity, verifyConsentRequest, withConsent,
} from "../src/index.ts";

const digestOf = (bytes: Uint8Array) => "z" + base58.encode(Uint8Array.from([0x12, 0x20, ...bytes]));
const DIGEST = digestOf(sha256(new TextEncoder().encode("example payload")));

// A fake VTA: an Ed25519 key published in a DID document, signing requests under `authentication` as the real one does.
const vtaSeed = ed25519.utils.randomSecretKey();
const VTA = "did:webvh:Qmexample:localhost%3A8100";
const vtaSigner: Signer = { curve: "ed25519", did: VTA, verificationMethod: `${VTA}#key-0`, sign: (h) => ed25519.sign(h, vtaSeed) };
const vtaPub = "z" + base58.encode(Uint8Array.from([0xed, 0x01, ...ed25519.getPublicKey(vtaSeed)]));
const vtaDoc = { id: VTA, verificationMethod: [{ id: `${VTA}#key-0`, type: "Multikey", controller: VTA, publicKeyMultibase: vtaPub }], authentication: [`${VTA}#key-0`] };
const approver = newIdentity();

function request(over: { recipient?: string; expiresAt?: string; effects?: unknown[]; purpose?: string; issuer?: string } = {}) {
  return signTrustTask(
    {
      id: "urn:uuid:1", type: CONSENT_REQUEST, issuer: VTA, recipient: over.recipient ?? approver.did, issuedAt: "2026-01-01T00:00:00Z",
      payload: { challenge: "ab".repeat(16), taskType: "https://example/task/1.0", payloadDigest: DIGEST, sideEffects: "mutating", requester: "did:key:z6MkReq",
        approverSet: "s", minApprovals: 1, excludeRequester: true, effects: over.effects ?? [], expiresAt: over.expiresAt ?? "2099-01-01T00:00:00Z" },
    } as any,
    vtaSigner,
    { proofPurpose: over.purpose ?? "authentication" },
  );
}
const opts = { vtaDid: VTA, approverDid: approver.did, vtaDocument: vtaDoc };

test("matchCode is the first six hex characters of the digest bytes, not of the encoded string", () => {
  const bytes = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
  assert.equal(matchCode(digestOf(bytes)), "a0a1a2");
  assert.notEqual(matchCode(digestOf(bytes)), digestOf(bytes).slice(0, 6));
  assert.throws(() => matchCode("zQm"), /multihash/);
  assert.throws(() => matchCode("fabc"), /base58btc/);
});

test("a genuine request verifies and shows its effects", () => {
  const v = verifyConsentRequest(request({ effects: [{ kind: "rename", summary: "Renames context my-app" }] }), opts);
  assert.equal(v.matchCode, matchCode(DIGEST));
  assert.deepEqual(v.effects, ["Renames context my-app"]);
});

test("verification refuses tampering, a wrong issuer, recipient, purpose, key or an expired request", () => {
  const good: any = request();
  const tampered = { ...good, payload: { ...good.payload, taskType: "https://example/destructive/1.0" } };
  assert.throws(() => verifyConsentRequest(tampered, opts), /signature does not verify/);
  assert.throws(() => verifyConsentRequest(request({ recipient: "did:key:z6MkOther" }), opts), /different approver/);
  assert.throws(() => verifyConsentRequest(request({ purpose: "assertionMethod" }), opts), /not authentication/);
  assert.throws(() => verifyConsentRequest(request({ expiresAt: "2020-01-01T00:00:00Z" }), opts), /expired/);
  assert.throws(() => verifyConsentRequest(good, { ...opts, vtaDid: "did:webvh:Qmother:localhost" }), /not issued by this VTA/);
  const otherKey = { id: VTA, authentication: [`${VTA}#key-0`], verificationMethod: [{ id: `${VTA}#key-0`, controller: VTA, publicKeyMultibase: "z" + base58.encode(Uint8Array.from([0xed, 0x01, ...ed25519.getPublicKey(ed25519.utils.randomSecretKey())])) }] };
  assert.throws(() => verifyConsentRequest(good, { ...opts, vtaDocument: otherKey }), /signature does not verify/);
  assert.throws(() => verifyConsentRequest({ ...good, proof: undefined }, opts), /no eddsa-jcs-2022 proof/);
  assert.equal(keyFromDidDocument({ verificationMethod: [] }, "x#k"), undefined);
});

test("a decision needs the matching code, echoes challenge and digest, and is signed by the approver", () => {
  const v = verifyConsentRequest(request(), opts);
  assert.throws(() => buildDecision(v, approver, VTA, { approve: true, typedCode: "000000" }), /does not match/);
  const d = buildDecision(v, approver, VTA, { approve: true, typedCode: ` ${v.matchCode.toUpperCase()} ` });
  assert.equal(d.type, CONSENT_DECISION);
  assert.equal(d.issuer, approver.did);
  assert.equal(d.recipient, VTA);
  assert.deepEqual(d.payload, { challenge: "ab".repeat(16), payloadDigest: DIGEST, decision: "approve" });
  assert.equal(d.proof.cryptosuite, "eddsa-jcs-2022");
  const deny = buildDecision(v, approver, VTA, { approve: false, reason: "not expected" });
  assert.deepEqual([deny.payload.decision, deny.payload.reason], ["deny", "not expected"]);
});

const refusal = (reason: string, challenge = "c1") => ({ payload: { code: "taskFailed", details: { reason, challenge, payloadDigest: DIGEST, approverSet: "s", minApprovals: 1, consentRequests: [request()] } } });

test("consentRequiredOf reads the refusal and ignores other errors", () => {
  const c = consentRequiredOf(refusal("auth:consent_required"));
  assert.equal(c?.matchCode, matchCode(DIGEST));
  assert.equal(c?.requests.length, 1);
  assert.equal(consentRequiredOf(refusal("auth:step_up_required")), undefined);
  assert.equal(consentRequiredOf({ payload: { code: "permissionDenied" } }), undefined);
  assert.equal(extractRequests({ details: { consentRequests: [request(), { type: "other" }] } }).length, 1);
  assert.equal(extractRequests(refusal("x").payload.details.consentRequests[0]).length, 1);
  assert.equal(extractRequests("nonsense").length, 0);
});

const gated = (challenge: string) => new TrustTaskError(422, refusal("auth:consent_required", challenge));

test("withConsent shows the code once, keeps asking on the same challenge, and returns the result when it executes", async () => {
  let calls = 0;
  const seen: string[] = [];
  const out = await withConsent(async () => { if (++calls < 4) throw gated("c1"); return "done"; }, { onChallenge: (c) => { seen.push(c.matchCode); }, sleep: async () => {}, intervalMs: 1 });
  assert.equal(out, "done");
  assert.equal(calls, 4);
  assert.equal(seen.length, 1);
});

test("withConsent stops, without asking again, when the challenge changes or time runs out, and passes other errors through", async () => {
  let n = 0;
  await assert.rejects(withConsent(async () => { throw gated(n++ === 0 ? "c1" : "c2"); }, { onChallenge() {}, sleep: async () => {} }), /denied or lapsed/);
  await assert.rejects(withConsent(async () => { throw gated("c1"); }, { onChallenge() {}, sleep: async () => {}, timeoutMs: -1 }), /timed out/);
  await assert.rejects(withConsent(async () => { throw new Error("boom"); }, { onChallenge() {} }), /boom/);
  assert.ok(identityFromSeed(ed25519.utils.randomSecretKey()).did.startsWith("did:key:"));
});

test("the request's key must be listed under authentication and controlled by the VTA (SPEC 4.7.3 items 2-3)", () => {
  const vm = vtaDoc.verificationMethod[0];
  const opts = (doc: unknown) => ({ vtaDid: VTA, approverDid: approver.did, vtaDocument: doc, now: new Date("2026-01-01T00:01:00Z") });
  assert.ok(verifyConsentRequest(request(), opts(vtaDoc)));
  assert.throws(() => verifyConsentRequest(request(), opts({ ...vtaDoc, authentication: [], assertionMethod: [vm.id] })), /authentication/);
  assert.throws(() => verifyConsentRequest(request(), opts({ ...vtaDoc, verificationMethod: [{ ...vm, controller: "did:example:someone-else" }] })), /controller/);
  // A relative reference and an embedded method are both accepted.
  assert.ok(verifyConsentRequest(request(), opts({ ...vtaDoc, authentication: ["#key-0"] })));
  assert.ok(verifyConsentRequest(request(), opts({ id: VTA, authentication: [vm] })));
  assert.throws(() => verifyConsentRequest(request(), opts({ ...vtaDoc, id: "did:example:other" })), /not the VTA's/);
});

test("verifiedDidWebvh resolves a did:webvh log only when it verifies; a tampered log is refused", async () => {
  const { createDID, multibaseEncode, MultibaseEncoding, prepareDataForSigning } = await import("didwebvh-ts");
  const { verifiedDidWebvh } = await import("../src/index.js");
  const seed = ed25519.utils.randomSecretKey();
  const pub = "z" + base58.encode(Uint8Array.from([0xed, 0x01, ...ed25519.getPublicKey(seed)]));
  const vmId = `did:key:${pub}#${pub}`;
  const signer = {
    getVerificationMethodId: () => vmId,
    sign: async (input: any) => ({ proofValue: multibaseEncode(ed25519.sign(await prepareDataForSigning(input.document, input.proof), seed), MultibaseEncoding.BASE58_BTC) }),
  };
  const verifier = { verify: async (sig: Uint8Array, msg: Uint8Array, key: Uint8Array) => ed25519.verify(sig, msg, key) };
  const made = await createDID({ address: "localhost:8100", signer: signer as any, verifier, updateKeys: [pub], verificationMethods: [{ type: "Multikey", publicKeyMultibase: pub, purpose: "authentication" } as any] });
  const text = made.log.map((e: unknown) => JSON.stringify(e)).join("\n");
  const r = await verifiedDidWebvh(text, made.did);
  assert.equal(r.did, made.did);
  await assert.rejects(verifiedDidWebvh(text, "did:example:other"), /resolves to/);
  const forged = JSON.parse(text);
  forged.state.verificationMethod = [{ id: `${made.did}#key-0`, type: "Multikey", controller: made.did, publicKeyMultibase: vtaPub }];
  await assert.rejects(verifiedDidWebvh(JSON.stringify(forged)));
});
