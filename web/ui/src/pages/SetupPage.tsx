import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useAuth, useRole } from "../auth/AuthContext";
import { Badge } from "../components/Badge";

type SetupStatus = {
  complete?: boolean;
  steps?: {
    admin_exists?: boolean;
    has_machines?: boolean;
    has_connected_agents?: boolean;
    has_users?: boolean;
    has_permissions?: boolean;
  };
  counts?: {
    admins?: number;
    users?: number;
    machines?: number;
    connected_agents?: number;
    permissions?: number;
  };
  next?: string;
};

export function SetupPage() {
  const role = useRole();
  const { user } = useAuth();
  const setup = useQuery({
    queryKey: ["setup"],
    queryFn: () => api<SetupStatus>("/setup/status"),
  });

  const d = setup.data;
  const statusSteps = d?.steps;
  const counts = d?.counts;
  const hardenedAuth = !!(user?.mfa_enabled || user?.webauthn_enabled);
  const steps = [
    {
      title: "1. Gateway config",
      body: (
        <>
          Edit <span className="mono">server.yaml</span>: listen addresses, PostgreSQL, recording path, and optional{" "}
          <span className="mono">auth.webauthn</span> / <span className="mono">auth.mfa_required</span>. Start{" "}
          <span className="mono">orion-belt-server</span>.
        </>
      ),
      done: true,
    },
    {
      title: "2. Admin account",
      body: (
        <>
          Bootstrap an admin (lab script or first-run). Confirm you can sign in: run <span className="mono">osh login</span> and redeem
          the printed code at <span className="mono">/ui/login</span>, or enroll a security key for WebAuthn sign-in.
        </>
      ),
      done: !!statusSteps?.admin_exists,
    },
    {
      title: "3. Enroll agents",
      body: (
        <>
          Open <Link to="/add-agent">Add agent</Link>, pick the host OS, generate the install script, and run it as root on each target.
          Watch <Link to="/agents">Agents</Link> until the tunnel shows <em>online</em>.
        </>
      ),
      done: !!statusSteps?.has_connected_agents,
    },
    {
      title: "4. Grant access",
      body: (
        <>
          Create users under <Link to="/users">Users</Link>, then grant machine access on <Link to="/permissions">Permissions</Link>{" "}
          (or approve <Link to="/requests">Access requests</Link>). Set allowed remote users (e.g. <span className="mono">root</span>).
        </>
      ),
      done: !!statusSteps?.has_permissions,
    },
    {
      title: "5. Harden auth",
      body: (
        <>
          On <Link to="/security">Security</Link>: enroll TOTP (QR), register WebAuthn keys, and add SSH keys to the key store. Admins:
          add Vite/production origins under <span className="mono">auth.webauthn.origins</span>.
        </>
      ),
      // No org-wide "hardened auth" signal exists in /setup/status yet, so this uses
      // the signed-in user's own MFA/WebAuthn enrollment as the best available proxy.
      done: hardenedAuth,
    },
    {
      title: "6. Verify sessions",
      body: (
        <>
          Open <Link to="/terminal">Terminal</Link> or SSH via the gateway, then confirm recording playback on{" "}
          <Link to="/sessions">Sessions</Link>.
        </>
      ),
      done: !!d?.complete,
    },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Setup guide</h1>
          <p>First-run path from gateway config → agents → access → hardened auth.</p>
        </div>
        <button type="button" className="btn secondary sm" onClick={() => void setup.refetch()}>
          Refresh status
        </button>
      </div>

      <div className="card" style={{ marginBottom: "1rem" }}>
        <h3>Machines vs agents</h3>
        <p className="muted">
          A <strong>machine</strong> is the inventory record (name, hostname, tags) used for permissions and sessions. An{" "}
          <strong>agent</strong> is the process on that host that opens a reverse SSH tunnel to the gateway.{" "}
          <Link to="/add-agent">Add agent</Link> creates both (registers the machine + install credentials).{" "}
          <Link to="/agents">Agents</Link> manages tunnel lifecycle; <Link to="/machines">Machines</Link> is the quieter inventory view for
          operators granting access.
        </p>
      </div>

      <div className="card" style={{ marginBottom: "1rem" }}>
        {setup.isLoading ? <p className="muted">Loading…</p> : null}
        {setup.error ? <div className="err">{(setup.error as Error).message}</div> : null}
        {d ? (
          <div className="grid">
            <div>
              <div className="stat-label">Admin</div>
              <div>{statusSteps?.admin_exists ? "ready" : "missing"}</div>
            </div>
            <div>
              <div className="stat-label">Machines</div>
              <div>{counts?.machines ?? 0}</div>
            </div>
            <div>
              <div className="stat-label">Agents connected</div>
              <div>{counts?.connected_agents ?? 0}</div>
            </div>
            <div>
              <div className="stat-label">Ready</div>
              <div>{d.complete ? "yes" : "not yet"}</div>
            </div>
          </div>
        ) : null}
      </div>

      <div className="setup-steps">
        {steps.map((s) => (
          <div key={s.title} className={`card setup-step${s.done ? " done" : ""}`}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <h3 style={{ margin: 0 }}>{s.title}</h3>
              <Badge status={s.done ? "completed" : "pending"}>{s.done ? "done" : "todo"}</Badge>
            </div>
            <p className="muted" style={{ marginBottom: 0 }}>
              {s.body}
            </p>
          </div>
        ))}
      </div>

      {(role === "admin" || role === "operator") && (
        <div className="card" style={{ marginTop: "1rem" }}>
          <h3>Quick links</h3>
          <div className="row">
            <Link className="btn secondary sm" to="/add-agent">
              Add agent
            </Link>
            <Link className="btn secondary sm" to="/agents">
              Agents
            </Link>
            <Link className="btn secondary sm" to="/permissions">
              Permissions
            </Link>
            <Link className="btn secondary sm" to="/security">
              Security
            </Link>
          </div>
        </div>
      )}
    </>
  );
}
