import { badgeClass } from "../lib/format";

export function Badge({ children, status }: { children: React.ReactNode; status?: string }) {
  return <span className={`badge ${badgeClass(status || String(children))}`}>{children}</span>;
}
