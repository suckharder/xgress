import React from "react";

// Hand-authored inline-SVG icon set (stroke-based, Lucide geometry). No runtime
// dependency, no network — every glyph ships in the bundle and satisfies the
// strict admin CSP. One keyed component keeps usage terse and consistent.

export type IconName =
  | "dashboard" | "hosts" | "certificates" | "middleware" | "access" | "security"
  | "bans" | "metrics" | "config" | "logs" | "settings"
  | "plus" | "edit" | "trash" | "close" | "copy" | "check" | "chevronDown"
  | "chevronRight" | "refresh" | "search" | "alert" | "info" | "external"
  | "panelLeft" | "logout" | "arrowRight" | "shield" | "lock" | "clock"
  | "download" | "upload" | "globe" | "play" | "pause" | "filter";

const P: Record<IconName, React.ReactNode> = {
  dashboard: <><rect x="3" y="3" width="7" height="9" rx="1.2" /><rect x="14" y="3" width="7" height="5" rx="1.2" /><rect x="14" y="12" width="7" height="9" rx="1.2" /><rect x="3" y="16" width="7" height="5" rx="1.2" /></>,
  hosts: <><circle cx="12" cy="12" r="9" /><line x1="3" y1="12" x2="21" y2="12" /><ellipse cx="12" cy="12" rx="4" ry="9" /></>,
  certificates: <><circle cx="12" cy="9" r="6" /><path d="M9.2 9.1l1.9 1.9 3.7-3.9" /><path d="M8.5 14.3 7 22l5-2.6L17 22l-1.5-7.7" /></>,
  middleware: <><path d="M12 2.5 21.5 8 12 13.5 2.5 8z" /><path d="M2.5 16 12 21.5 21.5 16" /><path d="M2.5 12 12 17.5 21.5 12" /></>,
  access: <><circle cx="8" cy="15" r="4.2" /><path d="M10.9 12.1 20 3" /><path d="M16.5 5.5 19 8" /><path d="M14.5 7.5 17 10" /></>,
  security: <><path d="M12 21.5c5-2.3 8-5.6 8-9.8V5.4L12 2.5 4 5.4v6.3c0 4.2 3 7.5 8 9.8z" /><path d="M9 12l2.1 2.1L15.2 10" /></>,
  bans: <><circle cx="12" cy="12" r="9" /><line x1="5.6" y1="5.6" x2="18.4" y2="18.4" /></>,
  metrics: <path d="M3 12h3.5l2.7 7 4-15 2.8 8H21" />,
  config: <><path d="M7.5 3.5A2.5 2.5 0 0 0 5 6v2.5A2.5 2.5 0 0 1 2.5 11 2.5 2.5 0 0 1 5 13.5V16a2.5 2.5 0 0 0 2.5 2.5" /><path d="M16.5 3.5A2.5 2.5 0 0 1 19 6v2.5a2.5 2.5 0 0 0 2.5 2.5 2.5 2.5 0 0 0-2.5 2.5V16a2.5 2.5 0 0 1-2.5 2.5" /></>,
  logs: <><rect x="3" y="4.5" width="18" height="15" rx="1.6" /><path d="M7 9.5l3 2.5-3 2.5" /><line x1="12.5" y1="15" x2="16.5" y2="15" /></>,
  settings: <><line x1="4" y1="8" x2="20" y2="8" /><circle cx="9" cy="8" r="2.4" /><line x1="4" y1="16" x2="20" y2="16" /><circle cx="15" cy="16" r="2.4" /></>,
  plus: <><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></>,
  edit: <><path d="M4 20.5h4.2L20 8.7l-4.2-4.2L4 16.3z" /><line x1="14.2" y1="6.3" x2="18.4" y2="10.5" /></>,
  trash: <><line x1="4" y1="7" x2="20" y2="7" /><path d="M9 7V4.5h6V7" /><path d="M6.5 7l1 13h9l1-13" /></>,
  close: <><line x1="6" y1="6" x2="18" y2="18" /><line x1="18" y1="6" x2="6" y2="18" /></>,
  copy: <><rect x="9" y="9" width="12" height="12" rx="2" /><path d="M6 15H4.5A1.5 1.5 0 0 1 3 13.5V4.5A1.5 1.5 0 0 1 4.5 3h9A1.5 1.5 0 0 1 15 4.5V6" /></>,
  check: <path d="M4.5 12.5l4.5 4.5L19.5 6.5" />,
  chevronDown: <path d="M6 9.5l6 6 6-6" />,
  chevronRight: <path d="M9.5 6l6 6-6 6" />,
  refresh: <><path d="M20.5 12a8.5 8.5 0 1 1-2.6-6.1" /><path d="M20.5 3.5V9H15" /></>,
  search: <><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.6" y2="16.6" /></>,
  alert: <><path d="M12 3.5 21.5 20H2.5z" /><line x1="12" y1="10" x2="12" y2="14" /><circle cx="12" cy="17.2" r="0.6" fill="currentColor" stroke="none" /></>,
  info: <><circle cx="12" cy="12" r="9" /><line x1="12" y1="11" x2="12" y2="16.5" /><circle cx="12" cy="7.8" r="0.6" fill="currentColor" stroke="none" /></>,
  external: <><path d="M14 4h6v6" /><line x1="20" y1="4" x2="11" y2="13" /><path d="M18 13.5V19a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5.5" /></>,
  panelLeft: <><rect x="3" y="4.5" width="18" height="15" rx="1.6" /><line x1="9" y1="4.5" x2="9" y2="19.5" /></>,
  logout: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 16.5l4.5-4.5L16 7.5" /><line x1="20.5" y1="12" x2="9" y2="12" /></>,
  arrowRight: <><line x1="4" y1="12" x2="19" y2="12" /><path d="M13.5 6.5 19 12l-5.5 5.5" /></>,
  shield: <path d="M12 21.5c5-2.3 8-5.6 8-9.8V5.4L12 2.5 4 5.4v6.3c0 4.2 3 7.5 8 9.8z" />,
  lock: <><rect x="4.5" y="10.5" width="15" height="10.5" rx="1.8" /><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5.2l3.4 2" /></>,
  download: <><path d="M12 3.5v12" /><path d="M7 11l5 5 5-5" /><path d="M4.5 20.5h15" /></>,
  upload: <><path d="M12 20.5v-12" /><path d="M7 13l5-5 5 5" /><path d="M4.5 3.5h15" /></>,
  globe: <><circle cx="12" cy="12" r="9" /><line x1="3" y1="12" x2="21" y2="12" /><ellipse cx="12" cy="12" rx="4" ry="9" /></>,
  play: <path d="M7 4.5l12 7.5-12 7.5z" fill="currentColor" stroke="none" />,
  pause: <><rect x="6.5" y="5" width="3.5" height="14" rx="1" fill="currentColor" stroke="none" /><rect x="14" y="5" width="3.5" height="14" rx="1" fill="currentColor" stroke="none" /></>,
  filter: <path d="M3.5 5.5h17l-6.7 8v5.2l-3.6 1.8v-7L3.5 5.5z" />,
};

export function Icon({
  name, size = 18, strokeWidth = 1.75, className, style,
}: {
  name: IconName; size?: number; strokeWidth?: number; className?: string; style?: React.CSSProperties;
}) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"
      className={className} style={style} aria-hidden="true" focusable="false"
    >
      {P[name]}
    </svg>
  );
}
