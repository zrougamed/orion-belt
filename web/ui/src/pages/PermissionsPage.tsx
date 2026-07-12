import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Machine, Permission, User } from "../lib/types";
import { fmtTime, shortId } from "../lib/format";
import { useToast } from "../components/Toast";
import { Badge } from "../components/Badge";

export function PermissionsPage() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const usersQ = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/users") });
  const machinesQ = useQuery({ queryKey: ["machines"], queryFn: () => api<Machine[]>("/machines") });
  const [userId, setUserId] = useState("");
  const [machineId, setMachineId] = useState("");
  const [accessType, setAccessType] = useState("both");
  const [remoteUsers, setRemoteUsers] = useState("root");
  const [durationHours, setDurationHours] = useState(0);

  const permsQ = useQuery({
    queryKey: ["permissions", "user", userId],
    queryFn: () => api<Permission[]>(`/permissions/user/${encodeURIComponent(userId)}`),
    enabled: !!userId,
  });

  const grant = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        user_id: userId,
        machine_id: machineId,
        access_type: accessType,
        remote_users: remoteUsers
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };
      if (durationHours > 0) body.duration_seconds = Math.round(durationHours * 3600);
      return api("/admin/permissions", { method: "POST", body: JSON.stringify(body) });
    },
    onSuccess: () => {
      toast("Permission granted");
      void qc.invalidateQueries({ queryKey: ["permissions", "user", userId] });
    },
    onError: (e: Error) => toast(e.message, "err"),
  });

  const userName = useMemo(() => {
    const map = new Map((usersQ.data || []).map((u) => [u.id, u.username]));
    return (id: string) => map.get(id) || shortId(id);
  }, [usersQ.data]);
  const machineName = useMemo(() => {
    const map = new Map((machinesQ.data || []).map((m) => [m.id, m.name]));
    return (id: string) => map.get(id) || shortId(id);
  }, [machinesQ.data]);

  function onGrant(e: FormEvent) {
    e.preventDefault();
    if (!userId || !machineId) {
      toast("Select user and machine", "err");
      return;
    }
    grant.mutate();
  }

  async function revoke(id: string) {
    try {
      await api(`/admin/permissions/${encodeURIComponent(id)}`, { method: "DELETE" });
      toast("Permission revoked");
      void qc.invalidateQueries({ queryKey: ["permissions", "user", userId] });
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), "err");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Permissions</h1>
          <p>Grant or revoke machine access (ReBAC) with optional remote users and TTL.</p>
        </div>
      </div>
      <form className="card" onSubmit={onGrant} style={{ marginBottom: "1rem" }}>
        <h3>Grant access</h3>
        <div className="form-grid">
          <div>
            <label className="field">User</label>
            <select value={userId} onChange={(e) => setUserId(e.target.value)} required>
              <option value="">Select…</option>
              {(usersQ.data || []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.username}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="field">Machine</label>
            <select value={machineId} onChange={(e) => setMachineId(e.target.value)} required>
              <option value="">Select…</option>
              {(machinesQ.data || []).map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="field">Access type</label>
            <select value={accessType} onChange={(e) => setAccessType(e.target.value)}>
              <option value="ssh">ssh</option>
              <option value="scp">scp</option>
              <option value="both">both</option>
            </select>
          </div>
          <div>
            <label className="field">Remote users (comma-separated)</label>
            <input value={remoteUsers} onChange={(e) => setRemoteUsers(e.target.value)} placeholder="root,ubuntu" />
          </div>
          <div>
            <label className="field">TTL hours (0 = no expiry)</label>
            <input type="number" min={0} value={durationHours} onChange={(e) => setDurationHours(Number(e.target.value) || 0)} />
          </div>
        </div>
        <button className="btn sm" type="submit" style={{ marginTop: "0.75rem" }} disabled={grant.isPending}>
          Grant
        </button>
      </form>
      <div className="card">
        <h3>Grants for {userId ? userName(userId) : "…"}</h3>
        {!userId ? (
          <div className="empty">Select a user to list permissions.</div>
        ) : permsQ.isLoading ? (
          <p className="muted">Loading…</p>
        ) : (permsQ.data || []).length === 0 ? (
          <div className="empty">No permissions.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Machine</th>
                <th>Access</th>
                <th>Remote users</th>
                <th>Granted</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(permsQ.data || []).map((p) => (
                <tr key={p.id}>
                  <td>{machineName(p.machine_id)}</td>
                  <td>
                    <Badge status={p.access_type}>{p.access_type}</Badge>
                  </td>
                  <td className="mono">{(p.remote_users || []).join(", ") || "—"}</td>
                  <td className="mono">{fmtTime(p.granted_at)}</td>
                  <td className="mono">{fmtTime(p.expires_at)}</td>
                  <td>
                    <button type="button" className="btn danger sm" onClick={() => void revoke(p.id)}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
