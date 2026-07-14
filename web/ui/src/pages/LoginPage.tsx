import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { useAuth, useHomePath } from "../auth/AuthContext";
import { api } from "../lib/api";
import { b64urlToBuf, bufToB64url } from "../lib/format";
import type { User } from "../lib/types";
import { useToast } from "../components/Toast";
import { ThemeToggle, useTheme } from "../components/ThemeToggle";

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
  const { theme, toggle } = useTheme();
  const [searchParams] = useSearchParams();
  const [username, setUsername] = useState("admin");
  const [code, setCode] = useState(searchParams.get("code") || "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // A CLI-issued sign-in code arrives via ?code= when the user follows the
  // link `osh login` prints. Redeem it immediately rather than making them
  // click twice.
  useEffect(() => {
    const fromURL = searchParams.get("code");
    if (fromURL) void redeemCode(fromURL);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (ready && user) return <Navigate to={home} replace />;

  async function redeemCode(value: string) {
    if (!value.trim()) return;
    setError("");
    setBusy(true);
    try {
      const data = await api<LoginResp>("/public/auth/browser-bootstrap/redeem", {
        method: "POST",
        body: JSON.stringify({ code: value.trim() }),
      });
      login(data.session_token, data.user, data.access_token || "");
      toast("Signed in");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onSubmitCode(e: FormEvent) {
    e.preventDefault();
    await redeemCode(code);
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
      <div className="login-theme-toggle">
        <ThemeToggle theme={theme} onToggle={toggle} />
      </div>
      <form className="card login-panel" onSubmit={onSubmitCode}>
        <h1 className="login-brand">
          Orion <em>Belt</em>
        </h1>
        <p className="login-tag">Sign in to your gateway</p>
        <div className="muted mono" style={{ marginBottom: "1rem", fontSize: "0.75rem" }}>
          {ver}
        </div>

        <label className="field">Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />

        <button className="btn block" type="button" style={{ marginTop: "0.75rem" }} disabled={busy} onClick={() => void onWebAuthn()}>
          Sign in with security key
        </button>

        <div className="muted" style={{ margin: "1rem 0 0.5rem", fontSize: "0.8rem" }}>
          Or run <code>osh login</code> on your laptop and paste the code:
        </div>
        <label className="field">Sign-in code</label>
        <input
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="e.g. 7K4M9PQRXZ"
          autoComplete="off"
          className="mono"
        />
        {error ? <div className="err">{error}</div> : null}
        <div className="row" style={{ marginTop: "1rem" }}>
          <button className="btn secondary block" type="submit" disabled={busy || !code.trim()}>
            Redeem code
          </button>
        </div>
      </form>
    </div>
  );
}
