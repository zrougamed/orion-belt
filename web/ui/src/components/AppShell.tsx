import { NavLink, Outlet } from "react-router-dom";
import { useAuth, useRole } from "../auth/AuthContext";
import { NAV } from "../lib/nav";
import { CommandPalette } from "./CommandPalette";
import { NotificationBell } from "./NotificationBell";
import { ThemeToggle, useTheme } from "./ThemeToggle";

export function AppShell() {
  const { user, version, logout } = useAuth();
  const role = useRole();
  const items = NAV[role] || NAV.user;
  const ver = version?.display || version?.version || "…";
  const { theme, toggle } = useTheme();

  return (
    <div className="app-shell">
      <nav className="side">
        <div className="nav-brand">
          Orion <span>Belt</span>
        </div>
        <div className="nav-section">Console</div>
        {items.map((n) => (
          <NavLink
            key={n.id}
            to={n.path}
            end={n.path === "/"}
            className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
            style={{ textDecoration: "none" }}
          >
            <n.icon className="nav-ico" width={18} height={18} />
            {n.label}
          </NavLink>
        ))}
        <div className="nav-foot">
          <div className="who">
            <strong>{user?.username}</strong>
            <span className="role-pill">{role}</span>
            <div className="muted" style={{ marginTop: ".2rem", fontSize: ".75rem" }}>
              {user?.email}
            </div>
            <div className="muted mono" style={{ marginTop: ".35rem", fontSize: ".7rem" }}>
              {ver}
            </div>
          </div>
          <button type="button" className="btn secondary sm" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="workspace">
        <div className="topbar">
          <span>Privileged access console</span>
          <div className="topbar-right">
            <NotificationBell />
            <ThemeToggle theme={theme} onToggle={toggle} />
            <kbd className="kbd-hint">⌘K</kbd>
            <span className="version-chip">{ver}</span>
          </div>
        </div>
        <Outlet />
      </main>
      <CommandPalette />
    </div>
  );
}
