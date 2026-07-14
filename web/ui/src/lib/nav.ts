import type { Role } from "./types";

import iconDashboard from "../assets/icons/dashboard.png";
import iconSetup from "../assets/icons/setup.png";
import iconRequests from "../assets/icons/requests.png";
import iconMachines from "../assets/icons/machines.png";
import iconTerminal from "../assets/icons/terminal.png";
import iconFiles from "../assets/icons/files.png";
import iconSessions from "../assets/icons/sessions.png";
import iconUsers from "../assets/icons/users.png";
import iconPermissions from "../assets/icons/permissions.png";
import iconAgents from "../assets/icons/agents.png";
import iconAddAgent from "../assets/icons/add-agent.png";
import iconAudit from "../assets/icons/audit.png";
import iconSecurity from "../assets/icons/security.png";
import iconPlugins from "../assets/icons/plugins.png";

export function roleOf(user: { role?: string; is_admin?: boolean } | null | undefined): Role {
  if (!user) return "user";
  const r = user.role || "";
  if (r === "admin" || r === "operator" || r === "auditor") return r;
  if (user.is_admin) return "admin";
  if (r === "user") return "user";
  return (r as Role) || "user";
}

export function canApprove(user: { role?: string; is_admin?: boolean } | null | undefined): boolean {
  const r = roleOf(user);
  return r === "admin" || r === "operator";
}

export type NavItem = { id: string; label: string; icon: string; path: string };

const BASE: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: iconDashboard, path: "/" },
  { id: "setup", label: "Setup guide", icon: iconSetup, path: "/setup" },
  { id: "requests", label: "Access requests", icon: iconRequests, path: "/requests" },
  { id: "machines", label: "Machines", icon: iconMachines, path: "/machines" },
  { id: "terminal", label: "Terminal", icon: iconTerminal, path: "/terminal" },
  { id: "files", label: "Files", icon: iconFiles, path: "/files" },
  { id: "sessions", label: "Sessions", icon: iconSessions, path: "/sessions" },
  { id: "users", label: "Users", icon: iconUsers, path: "/users" },
  { id: "permissions", label: "Permissions", icon: iconPermissions, path: "/permissions" },
  { id: "agents", label: "Agents", icon: iconAgents, path: "/agents" },
  { id: "add-agent", label: "Add agent", icon: iconAddAgent, path: "/add-agent" },
  { id: "audit", label: "Audit", icon: iconAudit, path: "/audit" },
  { id: "security", label: "Security", icon: iconSecurity, path: "/security" },
  { id: "plugins", label: "Plugins", icon: iconPlugins, path: "/plugins" },
];

function pick(...ids: string[]): NavItem[] {
  return ids.map((id) => BASE.find((n) => n.id === id)!).filter(Boolean);
}

export const NAV: Record<Role, NavItem[]> = {
  admin: BASE,
  operator: BASE,
  auditor: pick("dashboard", "sessions", "users", "audit", "security"),
  user: pick("machines", "terminal", "files", "sessions", "requests", "audit", "security"),
};

export function defaultPathForRole(role: Role): string {
  return (NAV[role] || NAV.user)[0]?.path || "/";
}
