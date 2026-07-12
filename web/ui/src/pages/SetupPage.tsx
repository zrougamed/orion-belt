import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useRole } from "../auth/AuthContext";

export function SetupPage() {
  const role = useRole();
  const setup = useQuery({
    queryKey: ["setup"],
    queryFn: () =>
      api<{
        has_admin?: boolean;
        agents_connected?: number;
        machines?: number;
        ready?: boolean;
        checklist?: string[];
      }>("/setup/status"),
  });

  const d = setup.data;
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
          Bootstrap an admin (lab script or first-run). Confirm you can sign in at <span className="mono">/ui/login</span> with an SSH
          public key.
        </>
      ),
      done: !!d?.has_admin,
    },
    {
      title: "3. Enroll agents",
      body: (
        <>
          Open <Link to="/add-agent">Add agent</Link>, pick the host OS, generate the install script, and run it as root on each target.
          Watch <Link to="/agents">Agents</Link> until the tunnel shows <em>online</em>.
        </>
      ),
      done: (d?.agents_connected ?? 0) > 0,
    },
    {
      title: "4. Grant access",
      body: (
        <>
          Create users under <Link to="/users">Users</Link>, then grant machine access on <Link to="/permissions">Permissions</Link>{" "}
          (or approve <Link to="/requests">Access requests</Link>). Set allowed remote users (e.g. <span className="mono">root</span>).
        </>
      ),
      done: (d?.machines ?? 0) > 0 && !!d?.has_admin,
    },
    {
      title: "5. Harden auth",
      body: (
        <>
          On <Link to="/security">Security</Link>: enroll TOTP (QR), register WebAuthn keys, and add SSH keys to the key store. Admins:
          add Vite/production origins under <span className="mono">auth.webauthn.origins</span>.
        </>
      ),
      done: false,
    },
    {
      title: "6. Verify sessions",
      body: (
        <>
          Open <Link to="/terminal">Terminal</Link> or SSH via the gateway, then confirm recording playback on{" "}
          <Link to="/sessions">Sessions</Link>.
        </>
      ),
      done: !!d?.ready,
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
              <div>{d.has_admin ? "ready" : "missing"}</div>
            </div>
            <div>
              <div className="stat-label">Machines</div>
              <div>{d.machines ?? 0}</div>
            </div>
            <div>
              <div className="stat-label">Agents connected</div>
              <div>{d.agents_connected ?? 0}</div>
            </div>
            <div>
              <div className="stat-label">Ready</div>
              <div>{d.ready ? "yes" : "not yet"}</div>
            </div>
          </div>
        ) : null}
      </div>

      <div className="setup-steps">
        {steps.map((s) => (
          <div key={s.title} className={`card setup-step${s.done ? " done" : ""}`}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <h3 style={{ margin: 0 }}>{s.title}</h3>
              <BadgeDone done={s.done} />
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

function BadgeDone({ done }: { done: boolean }) {
  return <span className={`role-pill${done ? "" : ""}`}>{done ? "done" : "todo"}</span>;
}
