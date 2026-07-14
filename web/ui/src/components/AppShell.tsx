import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth, useRole } from "../auth/AuthContext";
import { NAV } from "../lib/nav";
import { CommandPalette } from "./CommandPalette";
import { LogoutIcon, PanelCollapseIcon, PanelExpandIcon } from "./icons";
import { NotificationBell } from "./NotificationBell";
import { ThemeToggle, useTheme } from "./ThemeToggle";

const NAV_COLLAPSE_KEY = "ob_nav_collapsed";

function initialCollapsed(): boolean {
  try {
    return localStorage.getItem(NAV_COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

function monogram(name?: string): string {
  if (!name) return "?";
  const parts = name.trim().split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

export function AppShell() {
  const { user, version, logout } = useAuth();
  const role = useRole();
  const items = NAV[role] || NAV.user;
  const ver = version?.display || version?.version || "…";
  const { theme, toggle } = useTheme();
  const [collapsed, setCollapsed] = useState(initialCollapsed);

  useEffect(() => {
    try {
      localStorage.setItem(NAV_COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [collapsed]);

  return (
    <div className={`app-shell${collapsed ? " nav-collapsed" : ""}`}>
      <nav className="side" aria-label="Main">
        <div className="nav-brand-row">
          {!collapsed ? (
            <div className="nav-brand" title="Orion Belt">
              Orion <em>Belt</em>
            </div>
          ) : null}
          <button
            type="button"
            className="nav-collapse-btn"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            onClick={() => setCollapsed((c) => !c)}
          >
            {collapsed ? <PanelExpandIcon width={16} height={16} /> : <PanelCollapseIcon width={16} height={16} />}
          </button>
        </div>

        <div className="nav-scroll">
          {!collapsed ? <div className="nav-section">Navigate</div> : null}
          {items.map((n) => (
            <NavLink
              key={n.id}
              to={n.path}
              end={n.path === "/"}
              title={n.label}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
              style={{ textDecoration: "none" }}
            >
              <n.icon className="nav-ico" width={18} height={18} />
              {!collapsed ? <span className="nav-label">{n.label}</span> : null}
            </NavLink>
          ))}
        </div>

        <div className="nav-foot">
          <div className="who" title={user?.email || user?.username}>
            <div className="who-avatar" aria-hidden>
              {monogram(user?.username)}
            </div>
            {!collapsed ? (
              <div className="who-meta">
                <div className="who-name">{user?.username}</div>
                <div className="who-sub">{role}</div>
              </div>
            ) : null}
            <button
              type="button"
              className="who-logout"
              title="Sign out"
              aria-label="Sign out"
              onClick={() => void logout()}
            >
              <LogoutIcon width={16} height={16} />
            </button>
          </div>
          {!collapsed ? <div className="nav-build muted mono">{ver}</div> : null}
        </div>
      </nav>

      <main className="workspace">
        <div className="topbar">
          <span className="topbar-title">Access</span>
          <div className="topbar-right">
            <NotificationBell />
            <ThemeToggle theme={theme} onToggle={toggle} />
            <kbd className="kbd-hint">⌘K</kbd>
            <span className="version-chip" title="Server build">
              {ver}
            </span>
          </div>
        </div>
        <Outlet />
      </main>
      <CommandPalette />
    </div>
  );
}
