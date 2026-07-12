import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { AccessRequest, Machine, User } from "../lib/types";
import { Badge } from "../components/Badge";
import { fmtTime, shortId } from "../lib/format";
import { useAuth } from "../auth/AuthContext";
import { canApprove } from "../lib/nav";
import { useToast } from "../components/Toast";
import { Pagination, SortTh, TableToolbar, useTableState } from "../components/DataTable";

export function RequestsPage() {
  const { user } = useAuth();
  const approve = canApprove(user);
  const { toast } = useToast();
  const qc = useQueryClient();
  const reqs = useQuery({ queryKey: ["requests"], queryFn: () => api<AccessRequest[]>("/access-requests") });
  const machines = useQuery({ queryKey: ["machines"], queryFn: () => api<Machine[]>("/machines") });
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/users") });
  const table = useTableState<AccessRequest>({ pageSize: 25 });
  const [statusFilter, setStatusFilter] = useState("");
  const [machineId, setMachineId] = useState("");
  const [reason, setReason] = useState("");
  const [remote, setRemote] = useState("root");

  const create = useMutation({
    mutationFn: () =>
      api("/access-requests", {
        method: "POST",
        body: JSON.stringify({
          machine_id: machineId,
          remote_users: [remote],
          reason,
          duration: 3600,
        }),
      }),
    onSuccess: () => {
      toast("Request submitted");
      setReason("");
      void qc.invalidateQueries({ queryKey: ["requests"] });
    },
    onError: (e: Error) => toast(e.message, "err"),
  });

  function act(id: string, action: "approve" | "reject") {
    void api(`/admin/access-requests/${id}/${action}`, { method: "POST" })
      .then(() => {
        toast(action === "approve" ? "Approved" : "Rejected");
        void qc.invalidateQueries({ queryKey: ["requests"] });
      })
      .catch((e: Error) => toast(e.message, "err"));
  }

  const userName = (id: string) => users.data?.find((u) => u.id === id)?.username || shortId(id);
  const machineName = (id: string) => machines.data?.find((m) => m.id === id)?.name || shortId(id);

  function onCreate(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  const filtered = useMemo(() => {
    let rows = reqs.data || [];
    if (statusFilter) rows = rows.filter((r) => r.status === statusFilter);
    return rows;
  }, [reqs.data, statusFilter]);

  const processed = useMemo(() => {
    return table.process(
      filtered,
      (r, key) => {
        if (key === "user") return userName(r.user_id);
        if (key === "machine") return machineName(r.machine_id);
        if (key === "status") return r.status || "";
        if (key === "created") return r.created_at ? new Date(r.created_at).getTime() : 0;
        return "";
      },
      (r) =>
        `${userName(r.user_id)} ${machineName(r.machine_id)} ${(r.remote_users || []).join(" ")} ${r.status || ""} ${r.reason || ""}`,
    );
  }, [filtered, table.query, table.sortKey, table.sortDir, table.page, table.pageSize, users.data, machines.data]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Access requests</h1>
          <p>Request and approve temporary machine access.</p>
        </div>
      </div>
      <form className="card" onSubmit={onCreate} style={{ marginBottom: "1rem" }}>
        <h3>New request</h3>
        <div className="form-grid">
          <div>
            <label className="field">Machine</label>
            <select value={machineId} onChange={(e) => setMachineId(e.target.value)} required>
              <option value="">Select…</option>
              {(machines.data || []).map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="field">Remote user</label>
            <input value={remote} onChange={(e) => setRemote(e.target.value)} />
          </div>
          <div>
            <label className="field">Reason</label>
            <input value={reason} onChange={(e) => setReason(e.target.value)} required />
          </div>
        </div>
        <button className="btn sm" type="submit" style={{ marginTop: "0.75rem" }}>
          Submit
        </button>
      </form>
      <div className="card">
        <TableToolbar query={table.query} onQuery={table.setQuery} placeholder="Filter requests…">
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              table.setPage(0);
            }}
          >
            <option value="">All statuses</option>
            <option value="pending">pending</option>
            <option value="approved">approved</option>
            <option value="rejected">rejected</option>
          </select>
        </TableToolbar>
        <table>
          <thead>
            <tr>
              <SortTh label="User" col="user" sortKey={table.sortKey} sortDir={table.sortDir} onSort={table.toggleSort} />
              <SortTh label="Machine" col="machine" sortKey={table.sortKey} sortDir={table.sortDir} onSort={table.toggleSort} />
              <th>Remote</th>
              <SortTh label="Status" col="status" sortKey={table.sortKey} sortDir={table.sortDir} onSort={table.toggleSort} />
              <SortTh label="Created" col="created" sortKey={table.sortKey} sortDir={table.sortDir} onSort={table.toggleSort} />
              <th />
            </tr>
          </thead>
          <tbody>
            {processed.rows.map((r) => (
              <tr key={r.id}>
                <td>{userName(r.user_id)}</td>
                <td>{machineName(r.machine_id)}</td>
                <td className="mono">{(r.remote_users || []).join(", ")}</td>
                <td>
                  <Badge status={r.status}>{r.status}</Badge>
                </td>
                <td className="mono">{fmtTime(r.created_at)}</td>
                <td>
                  {approve && r.status === "pending" ? (
                    <div className="row">
                      <button type="button" className="btn sm" onClick={() => act(r.id, "approve")}>
                        Approve
                      </button>
                      <button type="button" className="btn secondary sm" onClick={() => act(r.id, "reject")}>
                        Reject
                      </button>
                    </div>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pagination
          page={processed.page}
          pageCount={processed.pageCount}
          total={processed.total}
          pageSize={table.pageSize}
          onPage={table.setPage}
        />
      </div>
    </>
  );
}
