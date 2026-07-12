import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useAuth, useRole } from "../auth/AuthContext";
import { api } from "../lib/api";
import type { AccessRequest, Machine, Session } from "../lib/types";
import { Badge } from "../components/Badge";
import { fmtTime, shortId } from "../lib/format";

export function DashboardPage() {
  const { user, version } = useAuth();
  const role = useRole();
  const isOps = role === "admin" || role === "operator";

  const machines = useQuery({ queryKey: ["machines"], queryFn: () => api<Machine[]>("/machines") });
  const sessions = useQuery({
    queryKey: ["sessions", "active"],
    queryFn: () => api<Session[]>("/sessions/active"),
  });
  const pending = useQuery({
    queryKey: ["requests", "pending"],
    queryFn: () => api<AccessRequest[]>("/access-requests?status=pending"),
    enabled: isOps,
  });
  const setup = useQuery({
    queryKey: ["setup"],
    queryFn: () => api<{ agents_connected?: number; has_admin?: boolean; ready?: boolean }>("/setup/status"),
    enabled: isOps,
  });
  const agents = useQuery({
    queryKey: ["agents", "connected"],
    queryFn: async () => {
      const data = await api<{ agents?: string[] } | string[]>("/admin/agents/connected");
      if (Array.isArray(data)) return data;
      return data.agents || [];
    },
    enabled: isOps,
    refetchInterval: 15_000,
  });

  const machineList = machines.data || [];
  const connected = new Set((agents.data || []).map(String));
  const onlineCount = isOps
    ? machineList.filter((m) => connected.has(m.id) || connected.has(m.name)).length
    : null;
  const activeSessions = sessions.data || [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p>
            Welcome, {user?.username}. Build {version?.display || version?.version || "…"}.
          </p>
        </div>
        <div className="row">
          <Link className="btn secondary sm" to="/sessions">
            Sessions
          </Link>
          {isOps ? (
            <Link className="btn secondary sm" to="/agents">
              Agents
            </Link>
          ) : null}
        </div>
      </div>
      {isOps && setup.data && !setup.data.ready ? (
        <div className="card" style={{ marginBottom: "1rem" }}>
          <h3>Setup incomplete</h3>
          <p className="muted">Connect agents to finish first-run setup.</p>
          <Link className="btn sm" to="/setup">
            Open setup guide
          </Link>
        </div>
      ) : null}
      <div className="grid">
        <div className="card">
          <div className="stat-label">Machines</div>
          <div className="stat">{machines.data?.length ?? "—"}</div>
        </div>
        <div className="card">
          <div className="stat-label">Active sessions</div>
          <div className="stat">{sessions.data?.length ?? "—"}</div>
        </div>
        {isOps ? (
          <>
            <div className="card">
              <div className="stat-label">Agents online</div>
              <div className="stat">
                {agents.isLoading ? "…" : `${onlineCount ?? 0}/${machineList.length}`}
              </div>
            </div>
            <div className="card">
              <div className="stat-label">Pending requests</div>
              <div className="stat">{pending.data?.length ?? "—"}</div>
            </div>
          </>
        ) : (
          <div className="card">
            <div className="stat-label">Role</div>
            <div className="stat" style={{ fontSize: "1.25rem", textTransform: "capitalize" }}>
              {role}
            </div>
          </div>
        )}
      </div>

      {isOps ? (
        <div className="grid" style={{ marginTop: "1rem", gridTemplateColumns: "1fr 1fr" }}>
          <div className="card">
            <h3>Agent health</h3>
            {machineList.length === 0 ? (
              <div className="empty">No machines registered.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Machine</th>
                    <th>Tunnel</th>
                  </tr>
                </thead>
                <tbody>
                  {machineList.slice(0, 8).map((m) => {
                    const up = connected.has(m.id) || connected.has(m.name);
                    return (
                      <tr key={m.id}>
                        <td>{m.name}</td>
                        <td>
                          <Badge status={up ? "online" : "offline"}>{up ? "online" : "offline"}</Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
            {machineList.length > 8 ? (
              <p className="muted" style={{ marginTop: "0.65rem" }}>
                Showing 8 of {machineList.length} — see Agents for the full list.
              </p>
            ) : null}
            <Link className="btn secondary sm" to="/agents" style={{ marginTop: "0.75rem" }}>
              Manage agents
            </Link>
          </div>
          <div className="card">
            <h3>Active sessions</h3>
            {activeSessions.length === 0 ? (
              <div className="empty">No active sessions.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Started</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {activeSessions.slice(0, 8).map((s) => (
                    <tr key={s.id}>
                      <td className="mono">{shortId(s.id)}</td>
                      <td className="mono">{fmtTime(s.start_time)}</td>
                      <td>
                        <Badge status={s.status}>{s.status || "active"}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <Link className="btn secondary sm" to="/sessions" style={{ marginTop: "0.75rem" }}>
              View all sessions
            </Link>
          </div>
        </div>
      ) : null}
    </>
  );
}
