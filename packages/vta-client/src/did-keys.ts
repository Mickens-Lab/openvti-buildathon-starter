// Keys from a DID document, by verification relationship (SPEC 4.7.3 items 2-3). Browser-safe.
import { base58 } from "@scure/base";

/** The Ed25519 key of a verification method in a DID document (`publicKeyMultibase`), or undefined. */
export function keyFromDidDocument(doc: any, vmId: string): Uint8Array | undefined {
  const vm = (doc?.verificationMethod ?? []).find((m: any) => m.id === vmId || (vmId.startsWith("#") && m.id?.endsWith(vmId)));
  const mb: unknown = vm?.publicKeyMultibase;
  if (typeof mb !== "string" || !mb.startsWith("z")) return undefined;
  const raw = base58.decode(mb.slice(1));
  return raw[0] === 0xed && raw[1] === 0x01 && raw.length === 34 ? raw.slice(2) : undefined;
}

/**
 * The Ed25519 key of `vmId` only if the DID document lists it under `purpose` (by reference, relative `#id`, or embedded)
 * and the method's `controller` is `controller`. Undefined otherwise. `keyAgreement` is never a signing purpose.
 */
export function keyForPurpose(doc: any, vmId: string, controller: string, purpose: string): Uint8Array | undefined {
  if (!["authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"].includes(purpose)) return undefined;
  const did = doc?.id;
  const abs = (id: unknown) => (typeof id === "string" && id.startsWith("#") && typeof did === "string" ? did + id : id);
  const want = abs(vmId);
  const listed = (doc?.[purpose] ?? []).map((a: any) => (typeof a === "string" ? { id: abs(a) } : { ...a, id: abs(a?.id) }));
  const ref = listed.find((a: any) => a.id === want);
  if (!ref) return undefined;
  const vm = ref.type || ref.publicKeyMultibase ? ref : (doc?.verificationMethod ?? []).map((m: any) => ({ ...m, id: abs(m.id) })).find((m: any) => m.id === want);
  if (!vm || vm.controller !== controller) return undefined;
  return keyFromDidDocument({ verificationMethod: [vm] }, vm.id);
}

/** {@link keyForPurpose} for `authentication`. */
export function authenticationKey(doc: any, vmId: string, controller: string): Uint8Array | undefined {
  return keyForPurpose(doc, vmId, controller, "authentication");
}
