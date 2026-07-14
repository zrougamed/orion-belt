import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";
import type { Notification } from "../lib/types";

const POLL_MS = 20_000;

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const qc = useQueryClient();

  const unread = useQuery({
    queryKey: ["notifications", "unread-count"],
    queryFn: () => api<{ unread: number }>("/notifications/unread-count"),
    refetchInterval: POLL_MS,
  });

  const list = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api<Notification[]>("/notifications?limit=30"),
    enabled: open,
    refetchInterval: open ? POLL_MS : false,
  });

  const markRead = useMutation({
    mutationFn: (id: string) => api(`/notifications/${id}/read`, { method: "POST" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  const markAllRead = useMutation({
    mutationFn: () => api("/notifications/read-all", { method: "POST" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    function onEsc(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onEsc);
    };
  }, []);

  const count = unread.data?.unread || 0;
  const items = list.data || [];

  return (
    <div className="notif-root" ref={rootRef}>
      <button
        type="button"
        className="notif-bell"
        aria-label="Notifications"
        onClick={() => setOpen((v) => !v)}
      >
        <BellIcon />
        {count > 0 ? <span className="notif-count">{count > 99 ? "99+" : count}</span> : null}
      </button>
      {open ? (
        <div className="notif-panel card" role="menu">
          <div className="notif-panel-head">
            <h3>Notifications</h3>
            {count > 0 ? (
              <button type="button" className="btn secondary sm" onClick={() => markAllRead.mutate()}>
                Mark all read
              </button>
            ) : null}
          </div>
          <div className="notif-list">
            {items.length === 0 ? <div className="empty">No notifications yet.</div> : null}
            {items.map((n) => (
              <button
                key={n.id}
                type="button"
                className={`notif-item${n.read_at ? "" : " unread"}`}
                onClick={() => !n.read_at && markRead.mutate(n.id)}
              >
                <div className="notif-item-title">{n.title}</div>
                {n.body ? <div className="notif-item-body">{n.body}</div> : null}
                <div className="notif-item-time muted mono">{fmtTime(n.created_at)}</div>
              </button>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function BellIcon() {
  return (
    <svg viewBox="0 0 24 24" width={18} height={18} fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 8a6 6 0 0 1 12 0c0 3.6 1 5.4 1.6 6.2.3.4 0 .9-.5.9H4.9c-.5 0-.8-.5-.5-.9C5 13.4 6 11.6 6 8Z" />
      <path d="M9.5 18.5a2.5 2.5 0 0 0 5 0" />
    </svg>
  );
}
