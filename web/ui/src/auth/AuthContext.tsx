import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, clearAuth, loadStoredUser, persistAuth } from "../lib/api";
import { defaultPathForRole, roleOf } from "../lib/nav";
import type { User, VersionInfo } from "../lib/types";

type AuthState = {
  user: User | null;
  token: string;
  jwt: string;
  version: VersionInfo | null;
  ready: boolean;
  login: (session: string, user: User, jwt?: string) => void;
  logout: () => Promise<void>;
  refreshMe: () => Promise<User>;
  setUser: (u: User | null) => void;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => loadStoredUser<User>());
  const [token, setToken] = useState(() => localStorage.getItem("ob_session") || "");
  const [jwt, setJwt] = useState(() => localStorage.getItem("ob_jwt") || "");
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [ready, setReady] = useState(false);

  const login = useCallback((session: string, nextUser: User, nextJwt = "") => {
    setToken(session);
    setJwt(nextJwt);
    setUser(nextUser);
    persistAuth(session, nextJwt, nextUser);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api("/logout", { method: "POST" });
    } catch {
      /* ignore */
    }
    clearAuth();
    setToken("");
    setJwt("");
    setUser(null);
  }, []);

  const refreshMe = useCallback(async () => {
    const me = await api<User>("/auth/me");
    setUser(me);
    persistAuth(localStorage.getItem("ob_session") || "", localStorage.getItem("ob_jwt") || "", me);
    return me;
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const v = await api<VersionInfo>("/version");
        if (!cancelled) setVersion(v);
      } catch {
        /* ignore */
      }
      if (token) {
        try {
          await refreshMe();
        } catch {
          clearAuth();
          if (!cancelled) {
            setToken("");
            setJwt("");
            setUser(null);
          }
        }
      }
      if (!cancelled) setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [token, refreshMe]);

  const value = useMemo(
    () => ({ user, token, jwt, version, ready, login, logout, refreshMe, setUser }),
    [user, token, jwt, version, ready, login, logout, refreshMe],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside provider");
  return ctx;
}

export function useRole() {
  const { user } = useAuth();
  return roleOf(user);
}

export function useHomePath() {
  return defaultPathForRole(useRole());
}
