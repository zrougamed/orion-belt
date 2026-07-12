export function shortId(id?: string): string {
  if (!id) return "—";
  return id.length > 8 ? id.slice(0, 8) : id;
}

export function fmtTime(t?: string | null): string {
  if (!t) return "—";
  try {
    return new Date(t).toLocaleString();
  } catch {
    return String(t);
  }
}

export function badgeClass(status?: string): string {
  const s = (status || "").toLowerCase();
  if (["active", "online", "approved", "completed", "ok", "enabled"].includes(s)) return "ok";
  if (["pending", "warn", "warning"].includes(s)) return "warn";
  if (["denied", "rejected", "failed", "terminated", "danger", "offline"].includes(s)) return "danger";
  return "neutral";
}

export function b64urlToBuf(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const buf = new ArrayBuffer(raw.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < raw.length; i++) view[i] = raw.charCodeAt(i);
  return buf;
}

export function bufToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function preparePublicKeyCreation(publicKey: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const pk = { ...publicKey } as Record<string, unknown>;
  if (typeof pk.challenge === "string") pk.challenge = b64urlToBuf(pk.challenge);
  if (pk.user && typeof (pk.user as { id?: unknown }).id === "string") {
    const u = { ...(pk.user as Record<string, unknown>) };
    u.id = b64urlToBuf(String(u.id));
    pk.user = u;
  }
  if (Array.isArray(pk.excludeCredentials)) {
    pk.excludeCredentials = (pk.excludeCredentials as Array<Record<string, unknown>>).map((c) => ({
      ...c,
      id: typeof c.id === "string" ? b64urlToBuf(c.id) : c.id,
    }));
  }
  return pk as unknown as PublicKeyCredentialCreationOptions;
}

export function publicKeyCredentialToJSON(cred: PublicKeyCredential) {
  const r = cred.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const out: Record<string, unknown> = {
    id: cred.id,
    type: cred.type,
    rawId: bufToB64url(cred.rawId),
    response: {} as Record<string, string>,
  };
  const response = out.response as Record<string, string>;
  if (r.clientDataJSON) response.clientDataJSON = bufToB64url(r.clientDataJSON);
  if ("attestationObject" in r && r.attestationObject) response.attestationObject = bufToB64url(r.attestationObject);
  if ("authenticatorData" in r && r.authenticatorData) response.authenticatorData = bufToB64url(r.authenticatorData);
  if ("signature" in r && r.signature) response.signature = bufToB64url(r.signature);
  if ("userHandle" in r && r.userHandle) response.userHandle = bufToB64url(r.userHandle);
  if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
  if (cred.getClientExtensionResults) out.clientExtensionResults = cred.getClientExtensionResults();
  return out;
}
