// Reply dispositions (SPEC 4.4.1) and the HTTPS binding's empty 202/204, as the VTA and VTC clients see them.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  TrustTaskError, TrustTaskPending, VtaClient, classifyReply, isAlreadyExists, isRequestOf, newIdentity, servedVersions,
  type CallEvent,
} from "../src/index.js";

const T = "https://trusttasks.org/spec/auth/whoami/0.1";
const req = { id: "11111111-2222-4333-8444-555555555555", type: T };
const json = (o: unknown) => JSON.stringify(o);

test("classifyReply decides by the reply's type alone", () => {
  assert.equal(classifyReply(req, 200, json({ type: `${T}#response`, payload: { a: 1 } })).kind, "response");
  assert.equal(classifyReply({ ...req, type: `${T}#request` }, 200, json({ type: `${T}#response`, payload: {} })).kind, "response");
  const err = classifyReply(req, 403, json({ type: "https://trusttasks.org/spec/trust-task-error/0.5", payload: { code: "permissionDenied" } }));
  assert.equal(err.kind, "error");
  assert.equal(err.code, "permissionDenied");
  // An error document under 200 is still a failure; a #response under 4xx is still the success the type says.
  assert.equal(classifyReply(req, 200, json({ type: "https://trusttasks.org/spec/trust-task-error/0.6", payload: { code: "taskFailed" } })).kind, "error");
  assert.equal(classifyReply(req, 200, json({ type: "https://trusttasks.org/spec/trust-task-next-step/0.1", payload: { step: "x" } })).kind, "next-step");
  // Another task's response, a bare request type, an untyped body: none is this task's answer.
  assert.equal(classifyReply(req, 200, json({ type: "https://trusttasks.org/spec/auth/challenge/0.1#response", payload: {} })).kind, "unexpected");
  assert.equal(classifyReply(req, 200, json({ type: T, payload: {} })).kind, "unexpected");
  assert.equal(classifyReply(req, 401, json({ error: "unauthorized" })).kind, "unexpected");
  assert.equal(classifyReply(req, 200, "<html>").kind, "unexpected");
});

test("classifyReply: an empty 202 is in flight, an empty 204 is done with no response, any other empty body is unexpected", () => {
  assert.equal(classifyReply(req, 202, "").kind, "in-flight");
  assert.equal(classifyReply(req, 204, "").kind, "no-response");
  assert.equal(classifyReply(req, 200, "").kind, "unexpected");
});

test("classifyReply flags a threadId that names another exchange, without refusing the reply", () => {
  const ok = classifyReply(req, 200, json({ type: `${T}#response`, threadId: req.id, payload: {} }));
  assert.equal(ok.threadMismatch, undefined);
  const bad = classifyReply(req, 200, json({ type: `${T}#response`, threadId: "other", payload: {} }));
  assert.equal(bad.kind, "response");
  assert.equal(bad.threadMismatch, true);
  assert.equal(classifyReply({ ...req, threadId: "t1" }, 200, json({ type: `${T}#response`, threadId: "t1", payload: {} })).threadMismatch, undefined);
});

test("isRequestOf accepts the bare URI and #request, never #response or another version", () => {
  assert.ok(isRequestOf(T, T));
  assert.ok(isRequestOf(`${T}#request`, T));
  assert.ok(isRequestOf(T, `${T}#request`));
  assert.ok(!isRequestOf(`${T}#response`, T));
  assert.ok(!isRequestOf("https://trusttasks.org/spec/auth/whoami/0.2", T));
  assert.ok(!isRequestOf(undefined, T));
});

test("isAlreadyExists and servedVersions read codes and details, not messages", () => {
  assert.ok(isAlreadyExists({ payload: { code: "taskFailed", details: { reason: "conflict" } } }));
  assert.ok(isAlreadyExists({ payload: { code: "acl/grant:alreadyExists" } }));
  assert.ok(!isAlreadyExists({ payload: { code: "idConflict" } }));
  assert.ok(!isAlreadyExists({ payload: { code: "taskFailed", message: "already exists" } }));
  assert.deepEqual(servedVersions({ payload: { code: "unsupportedVersion", details: { servedVersions: ["https://trusttasks.org/spec/x/0.3", "0.2"] } } }), ["0.3", "0.2"]);
  assert.equal(servedVersions({ payload: { code: "unsupportedVersion" } }), undefined);
});

function client(reply: (doc: any) => Response, events: CallEvent[] = []) {
  const c = new VtaClient("http://vta.test", "did:example:vta", newIdentity(), (async (_u: any, init: any) => reply(JSON.parse(init.body))) as typeof fetch);
  c.onCall = (e) => events.push(e);
  return c;
}

test("call: a next-step continuation and a 202 throw TrustTaskPending (not a payload, not a TrustTaskError); a 204 returns {}", async () => {
  const events: CallEvent[] = [];
  const next = client(() => new Response(json({ type: "https://trusttasks.org/spec/trust-task-next-step/0.1", payload: { next: "approve" } })), events);
  const e = await next.whoami().catch((x) => x);
  assert.ok(e instanceof TrustTaskPending && !(e instanceof TrustTaskError));
  assert.equal(e.reply.kind, "next-step");
  assert.equal(events[0].ok, false);
  assert.equal(events[0].kind, "next-step");
  await assert.rejects(client(() => new Response(null, { status: 202 })).whoami(), TrustTaskPending);
  assert.deepEqual(await client(() => new Response(null, { status: 204 })).whoami(), {});
});

test("call: a reply of another type, or not JSON, is a TrustTaskError, not a success", async () => {
  await assert.rejects(client((d) => new Response(json({ type: `${d.type}#request`, payload: {} }))).whoami(), TrustTaskError);
  const e = await client(() => new Response("bad gateway", { status: 502 })).whoami().catch((x) => x);
  assert.ok(e instanceof TrustTaskError);
  assert.equal(e.body, "bad gateway");
});

test("build + send resends the same signed bytes (a SPEC 8.4 retry); call mints a new document each time", async () => {
  const bodies: string[] = [];
  const c = new VtaClient("http://vta.test", "did:example:vta", newIdentity(), (async (_u: any, init: any) => {
    bodies.push(init.body);
    const d = JSON.parse(init.body);
    return new Response(json({ type: `${d.type}#response`, threadId: d.id, payload: {} }));
  }) as typeof fetch);
  const doc = c.build(T, {});
  assert.equal((await c.send(doc)).kind, "response");
  assert.equal((await c.send(doc)).kind, "response");
  assert.equal(bodies[0], bodies[1]);
  await c.whoami();
  assert.notEqual(JSON.parse(bodies[2]).id, JSON.parse(bodies[0]).id);
});
