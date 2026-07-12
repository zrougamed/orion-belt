import { useState } from "react";
import type { FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { useAuth, useHomePath } from "../auth/AuthContext";
import { api } from "../lib/api";
import { b64urlToBuf, bufToB64url } from "../lib/format";
import type { User } from "../lib/types";
import { useToast } from "../components/Toast";

type LoginResp = {
  session_token: string;
  access_token?: string;
  user: User;
};

function preparePublicKeyOptions(publicKey: Record<string, unknown>) {
  const pk = { ...publicKey } as Record<string, unknown>;
  if (typeof pk.challenge === "string") pk.challenge = b64urlToBuf(pk.challenge);
  if (pk.user && typeof (pk.user as { id?: unknown }).id === "string") {
    const u = pk.user as Record<string, unknown>;
    pk.user = { ...u, id: b64urlToBuf(String(u.id)) };
  }
  if (Array.isArray(pk.allowCredentials)) {
    pk.allowCredentials = (pk.allowCredentials as Array<Record<string, unknown>>).map((c) => ({
      ...c,
      id: typeof c.id === "string" ? b64urlToBuf(c.id) : c.id,
    }));
  }
  return pk as unknown as PublicKeyCredentialRequestOptions;
}

export function LoginPage() {
  const { user, version, login, ready } = useAuth();
  const home = useHomePath();
  const { toast } = useToast();
  const [username, setUsername] = useState("admin");
  const [publicKey, setPublicKey] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (ready && user) return <Navigate to={home} replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const data = await api<LoginResp>("/public/login", {
        method: "POST",
        body: JSON.stringify({
          username: username.trim(),
          public_key: publicKey.trim(),
          totp_code: totp.trim() || undefined,
        }),
      });
      login(data.session_token, data.user, data.access_token || "");
      toast("Signed in");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onWebAuthn() {
    setError("");
    setBusy(true);
    try {
      const begin = await api<{ publicKey: Record<string, unknown> }>("/public/webauthn/login/begin", {
        method: "POST",
        body: JSON.stringify({ username: username.trim() }),
      });
      const cred = (await navigator.credentials.get({
        publicKey: preparePublicKeyOptions(begin.publicKey),
      })) as PublicKeyCredential | null;
      if (!cred) throw new Error("WebAuthn cancelled");
      const r = cred.response as AuthenticatorAssertionResponse;
      const payload = {
        username: username.trim(),
        response: {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: bufToB64url(r.clientDataJSON),
            authenticatorData: bufToB64url(r.authenticatorData),
            signature: bufToB64url(r.signature),
            userHandle: r.userHandle ? bufToB64url(r.userHandle) : undefined,
          },
        },
      };
      const data = await api<LoginResp>("/public/webauthn/login/finish", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      login(data.session_token, data.user, data.access_token || "");
      toast("Signed in with WebAuthn");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const ver = version?.display || version?.version || "…";

  return (
    <div className="login-stage">
      <form className="card login-panel" onSubmit={onSubmit}>
        <h1 className="login-brand">
          Orion <em>Belt</em>
        </h1>
        <p className="login-tag">Privileged access gateway</p>
        <div className="muted mono" style={{ marginBottom: "1rem", fontSize: "0.75rem" }}>
          {ver}
        </div>
        <label className="field">Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        <label className="field" style={{ marginTop: "0.75rem" }}>
          SSH public key
        </label>
        <textarea
          rows={4}
          value={publicKey}
          onChange={(e) => setPublicKey(e.target.value)}
          placeholder="ssh-ed25519 AAAA… comment"
          required
        />
        <label className="field" style={{ marginTop: "0.75rem" }}>
          TOTP / backup code (if MFA enabled)
        </label>
        <input value={totp} onChange={(e) => setTotp(e.target.value)} autoComplete="one-time-code" />
        {error ? <div className="err">{error}</div> : null}
        <div className="row" style={{ marginTop: "1rem" }}>
          <button className="btn block" type="submit" disabled={busy}>
            Sign in
          </button>
        </div>
        <button className="btn secondary block" type="button" style={{ marginTop: "0.55rem" }} disabled={busy} onClick={() => void onWebAuthn()}>
          Sign in with security key
        </button>
      </form>
    </div>
  );
}
