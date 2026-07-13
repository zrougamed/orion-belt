import { useState } from "react";
import type { FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useToast } from "../components/Toast";
import { useAuth } from "../auth/AuthContext";
import { canApprove } from "../lib/nav";
import { fmtTime, preparePublicKeyCreation, publicKeyCredentialToJSON } from "../lib/format";

type SSHKey = { id: string; name: string; key_type?: string; public_key?: string; created_at?: string };
type WACred = { id: string; name: string; cred_id?: string; created_at?: string };
type APIKeyItem = {
  id: string;
  name: string;
  key_prefix?: string;
  last_used_at?: string;
  expires_at?: string;
  created_at?: string;
  revoked_at?: string;
};

export function SecurityPage() {
  const { toast } = useToast();
  const { refreshMe, user } = useAuth();
  const manageHint = canApprove(user);
  const qc = useQueryClient();
  const [tab, setTab] = useState<"mfa" | "webauthn" | "keys" | "api-keys">("mfa");
  const [otpauth, setOtpauth] = useState("");
  const [secret, setSecret] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [keyName, setKeyName] = useState("");
  const [keyPub, setKeyPub] = useState("");
  const [waErr, setWaErr] = useState("");
  const [apiKeyName, setApiKeyName] = useState("");
  const [apiKeyExpiresDays, setApiKeyExpiresDays] = useState(0);
  const [newAPIKey, setNewAPIKey] = useState("");

  const mfaStatus = useQuery({
    queryKey: ["mfa", "status"],
    queryFn: () => api<{ mfa_enabled?: boolean; mfa_required?: boolean }>("/mfa/status"),
    enabled: tab === "mfa",
  });
  const keys = useQuery({
    queryKey: ["ssh-keys"],
    queryFn: () => api<SSHKey[]>("/ssh-keys"),
    enabled: tab === "keys",
  });
  const waCreds = useQuery({
    queryKey: ["webauthn", "credentials"],
    queryFn: () => api<WACred[]>("/webauthn/credentials"),
    enabled: tab === "webauthn",
    retry: false,
  });
  const apiKeys = useQuery({
    queryKey: ["api-keys"],
    queryFn: () => api<{ api_keys?: APIKeyItem[] }>("/api-keys"),
    enabled: tab === "api-keys",
  });

  async function enrollMfa() {
    try {
      const data = await api<{ otpauth_url?: string; secret?: string; backup_codes?: string[] }>("/mfa/enroll", {
        method: "POST",
        body: "{}",
      });
      setOtpauth(data.otpauth_url || "");
      setSecret(data.secret || "");
      setBackupCodes(data.backup_codes || []);
      toast("MFA enrollment started — scan the QR code");
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    }
  }

  async function confirmMfa(e: FormEvent) {
    e.preventDefault();
    try {
      await api("/mfa/confirm", { method: "POST", body: JSON.stringify({ code }) });
      toast("MFA enabled");
      setCode("");
      setOtpauth("");
      setSecret("");
      setBackupCodes([]);
      await refreshMe();
      void qc.invalidateQueries({ queryKey: ["mfa"] });
    } catch (ex) {
      toast(ex instanceof Error ? ex.message : String(ex), "err");
    }
  }

  async function disableMfa() {
    const c = prompt("Enter TOTP or backup code to disable MFA");
    if (!c) return;
    try {
      await api("/mfa/disable", { method: "POST", body: JSON.stringify({ code: c }) });
      toast("MFA disabled");
      await refreshMe();
      void qc.invalidateQueries({ queryKey: ["mfa"] });
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    }
  }

  async function registerWebAuthn() {
    setWaErr("");
    try {
      const begin = await api<{ publicKey?: Record<string, unknown> } | Record<string, unknown>>(
        "/webauthn/register/begin",
        { method: "POST", body: "{}" },
      );
      const publicKey = preparePublicKeyCreation(
        (("publicKey" in begin && begin.publicKey) || begin) as Record<string, unknown>,
      );
      const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
      if (!cred) throw new Error("registration cancelled");
      await api("/webauthn/register/finish", {
        method: "POST",
        body: JSON.stringify(publicKeyCredentialToJSON(cred)),
      });
      toast("Security key registered");
      await refreshMe();
      void qc.invalidateQueries({ queryKey: ["webauthn"] });
    } catch (e) {
      setWaErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function deleteWA(id: string) {
    if (!confirm("Remove this authenticator?")) return;
    try {
      await api(`/webauthn/credentials/${encodeURIComponent(id)}`, { method: "DELETE" });
      toast("Credential removed");
      void qc.invalidateQueries({ queryKey: ["webauthn"] });
      await refreshMe();
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    }
  }

  async function addKey(e: FormEvent) {
    e.preventDefault();
    try {
      await api("/ssh-keys", {
        method: "POST",
        body: JSON.stringify({ name: keyName.trim(), public_key: keyPub.trim() }),
      });
      toast("SSH key added");
      setKeyName("");
      setKeyPub("");
      void qc.invalidateQueries({ queryKey: ["ssh-keys"] });
    } catch (ex) {
      toast(ex instanceof Error ? ex.message : String(ex), "err");
    }
  }

  async function deleteKey(id: string) {
    if (!confirm("Delete this SSH key?")) return;
    try {
      await api(`/ssh-keys/${encodeURIComponent(id)}`, { method: "DELETE" });
      toast("Key deleted");
      void qc.invalidateQueries({ queryKey: ["ssh-keys"] });
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    }
  }

  async function createAPIKey(e: FormEvent) {
    e.preventDefault();
    try {
      const body: Record<string, unknown> = { name: apiKeyName.trim() };
      if (apiKeyExpiresDays > 0) body.expires_in = apiKeyExpiresDays;
      const res = await api<{ api_key: string }>("/api-keys", { method: "POST", body: JSON.stringify(body) });
      setNewAPIKey(res.api_key);
      setApiKeyName("");
      setApiKeyExpiresDays(0);
      void qc.invalidateQueries({ queryKey: ["api-keys"] });
    } catch (ex) {
      toast(ex instanceof Error ? ex.message : String(ex), "err");
    }
  }

  async function revokeAPIKey(id: string, name: string) {
    if (!confirm(`Revoke API key "${name}"? It will stop working immediately but stays in the audit trail.`)) return;
    try {
      await api(`/api-keys/${encodeURIComponent(id)}/revoke`, { method: "POST", body: "{}" });
      toast("API key revoked");
      void qc.invalidateQueries({ queryKey: ["api-keys"] });
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    }
  }

  async function deleteAPIKey(id: string, name: string) {
    if (!confirm(`Permanently delete API key "${name}"? This cannot be undone.`)) return;
    try {
      await api(`/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" });
      toast("API key deleted");
      void qc.invalidateQueries({ queryKey: ["api-keys"] });
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    }
  }

  const keyList = keys.data || [];
  const qrSrc = otpauth
    ? `https://api.qrserver.com/v1/create-qr-code/?size=220x220&ecc=M&data=${encodeURIComponent(otpauth)}`
    : "";

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Security</h1>
          <p>MFA, WebAuthn, and SSH keys for {user?.username}.</p>
        </div>
      </div>
      <div className="row" style={{ marginBottom: "1rem" }}>
        {(["mfa", "webauthn", "keys", "api-keys"] as const).map((t) => (
          <button key={t} type="button" className={`btn sm${tab === t ? "" : " secondary"}`} onClick={() => setTab(t)}>
            {t === "mfa" ? "MFA" : t === "webauthn" ? "WebAuthn" : t === "keys" ? "SSH keys" : "API keys"}
          </button>
        ))}
      </div>

      {tab === "mfa" ? (
        <div className="card">
          <h3>Time-based one-time passwords</h3>
          <p className="muted">
            Status: {mfaStatus.data?.mfa_enabled || user?.mfa_enabled ? "enabled" : "disabled"}
            {mfaStatus.data?.mfa_required ? " · organization requires MFA" : ""}
          </p>
          <div className="row">
            <button type="button" className="btn sm" onClick={() => void enrollMfa()} disabled={!!(mfaStatus.data?.mfa_enabled || user?.mfa_enabled)}>
              Start enrollment
            </button>
            <button type="button" className="btn danger sm" onClick={() => void disableMfa()} disabled={!(mfaStatus.data?.mfa_enabled || user?.mfa_enabled)}>
              Disable MFA
            </button>
          </div>
          {secret ? (
            <div className="mfa-enroll" style={{ marginTop: "1rem" }}>
              <p className="okmsg">Scan this QR code with your authenticator, then confirm with a code.</p>
              <div className="mfa-qr-row">
                {qrSrc ? (
                  <img className="mfa-qr" src={qrSrc} alt="TOTP QR code" width={220} height={220} />
                ) : null}
                <div>
                  <label className="field">Secret (manual entry)</label>
                  <input className="mono" readOnly value={secret} />
                  <label className="field">otpauth URL</label>
                  <textarea className="mono" rows={2} readOnly value={otpauth} />
                </div>
              </div>
              {backupCodes.length ? (
                <>
                  <label className="field">Backup codes — save these now</label>
                  <pre className="session">{backupCodes.join("\n")}</pre>
                </>
              ) : null}
              <form onSubmit={confirmMfa}>
                <label className="field">Confirm code</label>
                <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" />
                <button className="btn sm" type="submit" style={{ marginTop: "0.55rem" }}>
                  Confirm enrollment
                </button>
              </form>
            </div>
          ) : null}
        </div>
      ) : null}

      {tab === "webauthn" ? (
        <>
          <div className="card">
            <h3>Registered authenticators</h3>
            <p className="muted">Status: {user?.webauthn_enabled ? "enabled" : "not configured"}</p>
            <div className="row" style={{ marginBottom: "0.85rem" }}>
              <button type="button" className="btn sm" onClick={() => void registerWebAuthn()}>
                Register YubiKey / FIDO2
              </button>
            </div>
            {waErr ? <div className="err">{waErr}</div> : null}
            {waCreds.isError ? (
              <div className="err">
                {(waCreds.error as Error).message}
                <p className="muted">WebAuthn may be disabled or misconfigured on this server.</p>
              </div>
            ) : null}
            {(waCreds.data || []).length ? (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Credential</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {(waCreds.data || []).map((c) => (
                    <tr key={c.id}>
                      <td>{c.name || "key"}</td>
                      <td className="mono">{(c.cred_id || c.id).slice(0, 16)}…</td>
                      <td className="mono">{fmtTime(c.created_at)}</td>
                      <td>
                        <button type="button" className="btn danger sm" onClick={() => void deleteWA(c.id)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : !waCreds.isError ? (
              <div className="empty">No WebAuthn credentials yet. Register a key above (not from the login page).</div>
            ) : null}
          </div>
          {manageHint ? (
            <div className="card" style={{ marginTop: "1rem" }}>
              <h3>Admin: enable WebAuthn</h3>
              <p className="muted">
                Registration happens here while signed in. Login only uses keys that are already registered.
                Configure <span className="mono">auth.webauthn</span> in <span className="mono">server.yaml</span>, then restart the gateway.
              </p>
              <pre className="code">{`auth:
  webauthn:
    enabled: true
    rp_display_name: "Orion Belt"
    rp_id: "localhost"   # hostname only (no port)
    origins:
      - "http://localhost:8080"
      - "http://localhost:5173"   # Vite UI during development
      - "https://your-gateway.example.com"`}</pre>
              <ul className="muted help-list">
                <li>
                  <strong>rp_id</strong> must match the browser hostname (e.g. <span className="mono">localhost</span>).
                </li>
                <li>
                  Every UI origin you use (API port, Vite <span className="mono">:5173</span>, production HTTPS) must be listed under{" "}
                  <span className="mono">origins</span>.
                </li>
                <li>
                  After config, open Security → WebAuthn → <em>Register YubiKey / FIDO2</em>, then use “Sign in with YubiKey” on the login page.
                </li>
              </ul>
            </div>
          ) : null}
        </>
      ) : null}

      {tab === "keys" ? (
        <>
          <div className="card">
            <h3>Add SSH public key</h3>
            <p className="muted">
              Keys listed here are used for gateway SSH / API login. Your account’s legacy single{" "}
              <span className="mono">public_key</span> field is separate — add keys explicitly below (classic or FIDO{" "}
              <span className="mono">sk-*</span>).
            </p>
            <form onSubmit={addKey}>
              <label className="field">Name</label>
              <input value={keyName} onChange={(e) => setKeyName(e.target.value)} placeholder="laptop, yubikey-work…" required />
              <label className="field">Public key</label>
              <textarea
                rows={3}
                value={keyPub}
                onChange={(e) => setKeyPub(e.target.value)}
                placeholder="ssh-ed25519 AAAA… or sk-ssh-ed25519@openssh.com AAAA…"
                required
              />
              <button className="btn sm" type="submit" style={{ marginTop: "0.55rem" }}>
                Add key
              </button>
            </form>
          </div>
          <div className="card" style={{ marginTop: "1rem" }}>
            <h3>Your keys</h3>
            {keyList.length === 0 ? (
              <div className="empty">No keys in the SSH key store yet. Add one above to sign in with pubkey auth.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {keyList.map((k) => (
                    <tr key={k.id}>
                      <td>{k.name}</td>
                      <td className="mono">{k.key_type || "—"}</td>
                      <td className="mono">{fmtTime(k.created_at)}</td>
                      <td>
                        <button type="button" className="btn danger sm" onClick={() => void deleteKey(k.id)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      ) : null}

      {tab === "api-keys" ? (
        <>
          <div className="card">
            <h3>Create API key</h3>
            <p className="muted">
              API keys authenticate CLI tools (<span className="mono">osh</span>) and scripts against the REST API. The
              raw key is shown once at creation — copy it now, it can't be retrieved again.
            </p>
            <form onSubmit={createAPIKey}>
              <label className="field">Name</label>
              <input value={apiKeyName} onChange={(e) => setApiKeyName(e.target.value)} placeholder="ci-pipeline, laptop-cli…" required />
              <label className="field">Expires in days (0 = never)</label>
              <input
                type="number"
                min={0}
                value={apiKeyExpiresDays}
                onChange={(e) => setApiKeyExpiresDays(Number(e.target.value) || 0)}
              />
              <button className="btn sm" type="submit" style={{ marginTop: "0.55rem" }}>
                Create key
              </button>
            </form>
            {newAPIKey ? (
              <div className="mfa-enroll" style={{ marginTop: "1rem" }}>
                <p className="okmsg">Copy this key now — it won't be shown again.</p>
                <div className="row">
                  <input className="mono" readOnly value={newAPIKey} style={{ flex: 1 }} />
                  <button
                    type="button"
                    className="btn secondary sm"
                    onClick={async () => {
                      await navigator.clipboard.writeText(newAPIKey);
                      toast("API key copied");
                    }}
                  >
                    Copy
                  </button>
                  <button type="button" className="btn secondary sm" onClick={() => setNewAPIKey("")}>
                    Dismiss
                  </button>
                </div>
              </div>
            ) : null}
          </div>
          <div className="card" style={{ marginTop: "1rem" }}>
            <h3>Your API keys</h3>
            {(apiKeys.data?.api_keys || []).length === 0 ? (
              <div className="empty">No API keys yet. Create one above to authenticate {"osh"} or scripts.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Prefix</th>
                    <th>Created</th>
                    <th>Last used</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {(apiKeys.data?.api_keys || []).map((k) => (
                    <tr key={k.id}>
                      <td>{k.name}</td>
                      <td className="mono">{k.key_prefix ? `${k.key_prefix}…` : "—"}</td>
                      <td className="mono">{fmtTime(k.created_at)}</td>
                      <td className="mono">{k.last_used_at ? fmtTime(k.last_used_at) : "never"}</td>
                      <td className="mono">{k.expires_at ? fmtTime(k.expires_at) : "never"}</td>
                      <td>{k.revoked_at ? <span className="muted">revoked</span> : <span className="okmsg">active</span>}</td>
                      <td>
                        <div className="row">
                          <button
                            type="button"
                            className="btn secondary sm"
                            disabled={!!k.revoked_at}
                            onClick={() => void revokeAPIKey(k.id, k.name)}
                          >
                            Revoke
                          </button>
                          <button type="button" className="btn danger sm" onClick={() => void deleteAPIKey(k.id, k.name)}>
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      ) : null}
    </>
  );
}
