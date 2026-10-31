// "Send my membership credential back": the explanation of credentialsDelivered, the confirm step, the call, the re-read
// that shows the flag turn true, the receipt, and a refusal in plain words.
import { beforeEach, describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { callLog } from "../../src/client.ts";
import { membershipGrant } from "../../src/grant.ts";
import { fake, freshDb, refusal } from "./fake.ts";
import { mountApp, resetWorld, settle } from "./harness.tsx";

const delivery = () => screen.getByTestId("delivery").textContent ?? "";
const toastText = () => document.querySelector(".toasts")?.textContent ?? "";
const SEND = "Send my membership credential back";

describe("send my membership credential back", () => {
  beforeEach(() => { const db = freshDb(); db.request = { id: "r1", status: "approved" }; db.member = true; resetWorld(db); membershipGrant.set(undefined); });

  it("explains the flag in a visible note, not only a tooltip", async () => {
    await mountApp();
    const note = screen.getByTestId("delivery-explained").textContent ?? "";
    expect(note).toMatch(/credentialsDelivered/);
    expect(note).toMatch(/turns true only when the community holds\s+your own membership credential sent back/);
    expect(note).toMatch(/vtc\/members\/vmc\/0\.1/);
    expect(note).toMatch(/do not change it/);
    expect(screen.getByText("Credential delivery").getAttribute("title")).toMatch(/pushed frames do not change it/);
  });

  it("asks first, then sends once, re-reads the status, and shows the flag true and the receipt", async () => {
    await mountApp();
    expect(delivery()).toMatch(/not applicable here/); // local mode, flag false
    await userEvent.click(screen.getByRole("button", { name: SEND }));
    expect(fake.sendMembershipCredential).not.toHaveBeenCalled();
    const confirm = screen.getByRole("group", { name: `Confirm: ${SEND}` }).textContent ?? "";
    expect(confirm).toMatch(/naming this community as its subject/);
    expect(confirm).toMatch(/the community stores it unbound/);
    expect(confirm).toMatch(/unbound/);
    expect(confirm).toMatch(/incomplete/);
    const before = fake.calls.length;
    await userEvent.click(screen.getByRole("button", { name: /Yes, send my membership credential back/i }));
    await settle();
    expect(fake.sendMembershipCredential).toHaveBeenCalledTimes(1);
    expect(fake.sendMembershipCredential.mock.calls[0]).toEqual([{}]); // no grant here, and no requestId: the page does not reliably know the approved one
    const after = fake.calls.slice(before);
    expect(after[0]).toBe("sendMembershipCredential");
    expect(after).toContain("joinStatus"); // re-read, never set locally
    expect(callLog.get().some((c) => c.type === "https://trusttasks.org/spec/vtc/members/vmc/0.1" && c.ok)).toBe(true);
    expect(toastText()).toContain('The community answered "stored" for your unbound membership credential.');
    expect(delivery()).toMatch(/reciprocal credential held/);
    expect(delivery()).toMatch(/unbound/);
    const receipt = screen.getByTestId("vmc-receipt").textContent ?? "";
    expect(receipt).toMatch(/"status": "stored"/);
    expect(receipt).toMatch(/urn:uuid:00000000-0000-4000-8000-000000000001/);
    expect(receipt).not.toMatch(/did:example:app/);
  });

  it("says why it is unbound when no grant arrived (local mode: no messaging)", async () => {
    await mountApp();
    const state = screen.getByTestId("grant-state").textContent ?? "";
    expect(state).toMatch(/no messaging/);
    expect(state).toMatch(/unbound/);
  });

  it("binds to the grant the frames brought, and then says bound and complete, never unbound", async () => {
    const grant = { type: ["VerifiableCredential", "DTGCredential", "MembershipCredential"], issuer: "did:example:vtc", issuerScope: "public", credentialSubject: { id: "did:example:app" } };
    membershipGrant.set(grant);
    await mountApp();
    expect(screen.getByTestId("grant-state").textContent).toMatch(/arrived in a credential frame/);
    await userEvent.click(screen.getByRole("button", { name: SEND }));
    const confirm = screen.getByRole("group", { name: `Confirm: ${SEND}` }).textContent ?? "";
    expect(confirm).toMatch(/digest of the membership credential the community issued to you/);
    expect(confirm).toMatch(/stores it bound, completing your membership pair/);
    expect(confirm).not.toMatch(/unbound|incomplete/);
    await userEvent.click(screen.getByRole("button", { name: /Yes, send my membership credential back/i }));
    await settle();
    expect(fake.sendMembershipCredential.mock.calls[0]).toEqual([{ grant }]);
    expect(toastText()).toContain('The community answered "stored" for your bound membership credential.');
    expect(delivery()).toMatch(/bound credential held/);
    expect(delivery()).toMatch(/pair is complete/);
    expect(delivery()).not.toMatch(/unbound|incomplete/);
  });

  it("cancel sends nothing", async () => {
    await mountApp();
    await userEvent.click(screen.getByRole("button", { name: SEND }));
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(fake.sendMembershipCredential).not.toHaveBeenCalled();
  });

  it("a refusal is shown plainly with its code, and no receipt", async () => {
    fake.db.failing.sendMembershipCredential = refusal(422, "vtc/members/vmc:subjectMismatch", "member vmc subject is not this community");
    await mountApp();
    await userEvent.click(screen.getByRole("button", { name: SEND }));
    await userEvent.click(screen.getByRole("button", { name: /Yes, send my membership credential back/i }));
    await settle();
    expect(toastText()).toMatch(/different community as its subject/);
    expect(toastText()).toMatch(/subjectMismatch/);
    expect(screen.queryByTestId("vmc-receipt")).toBeNull();
    expect(delivery()).not.toMatch(/reciprocal credential held/);
  });
});
