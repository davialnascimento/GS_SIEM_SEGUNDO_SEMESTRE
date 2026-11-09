import React from 'react';

const paths = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1.4"/><rect x="14" y="3" width="7" height="7" rx="1.4"/><rect x="3" y="14" width="7" height="7" rx="1.4"/><rect x="14" y="14" width="7" height="7" rx="1.4"/></>,
  alert: <><path d="M12 3 2 20h20L12 3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></>,
  radar: <><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="m12 12 6-6"/><circle cx="18" cy="6" r="1"/></>,
  bot: <><rect x="4" y="7" width="16" height="13" rx="3"/><path d="M12 3v4M9 3h6"/><path d="M8 13h.01M16 13h.01"/><path d="M9 17h6"/></>,
  terminal: <><rect x="2.5" y="3.5" width="19" height="17" rx="2"/><path d="m7 9 3 3-3 3M12 15h5"/></>,
  chevron: <path d="m9 18 6-6-6-6"/>,
  down: <path d="m6 9 6 6 6-6"/>,
  arrow: <><path d="M4 12h16"/><path d="m14 6 6 6-6 6"/></>,
  search: <><circle cx="11" cy="11" r="7"/><path d="m16 16 5 5"/></>,
  filter: <><path d="M3 5h18M6 12h12M9 19h6"/><circle cx="8" cy="5" r="2" fill="currentColor" stroke="none"/><circle cx="16" cy="12" r="2" fill="currentColor" stroke="none"/></>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l4 2"/></>,
  activity: <path d="M2 12h4l3-7 5 14 3-7h5"/>,
  shield: <><path d="M12 2 4 5v6c0 5.1 3.3 8.9 8 11 4.7-2.1 8-5.9 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></>,
  globe: <><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c-5 4-5 14 0 18M12 3c5 4 5 14 0 18"/></>,
  bolt: <path d="m13 2-9 12h7l-1 8 10-13h-7l0-7Z"/>,
  database: <><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></>,
  play: <path d="m7 4 13 8-13 8V4Z"/>,
  refresh: <><path d="M20 7v5h-5"/><path d="M4 17v-5h5"/><path d="M5.5 9A7.5 7.5 0 0 1 19 7l1 5M4 12l1 5a7.5 7.5 0 0 0 13.5-2"/></>,
  download: <><path d="M12 3v12m-5-5 5 5 5-5"/><path d="M4 17v4h16v-4"/></>,
  upload: <><path d="M12 18V5m-5 5 5-5 5 5"/><path d="M4 17v4h16v-4"/></>,
  settings: <><circle cx="12" cy="12" r="3"/><path d="m10 2-.5 2.3-2 1L5.3 4 3 8l1.8 1.7v4.6L3 16l2.3 4 2.2-1.3 2 1L10 22h4l.5-2.3 2-1 2.2 1.3 2.3-4-1.8-1.7V9.7L21 8l-2.3-4-2.2 1.3-2-1L14 2h-4Z"/></>,
  plus: <path d="M12 5v14M5 12h14"/>,
  x: <path d="M5 5 19 19M19 5 5 19"/>,
  logout: <><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5"/><path d="M14 7l5 5-5 5M19 12H9"/></>,
  user: <><circle cx="12" cy="8" r="4"/><path d="M4 21c0-5 3.5-8 8-8s8 3 8 8"/></>,
  users: <><circle cx="9" cy="8" r="3"/><path d="M2 20c0-4 3-7 7-7s7 3 7 7M17 5c4 0 4 6 0 6M18 14c2.5.5 4 2.5 4 6"/></>,
  key: <><circle cx="8" cy="15" r="5"/><path d="m12 11 9-9M16 7l3 3M13 10l3 3"/></>,
  lock: <><rect x="4" y="10" width="16" height="12" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 15v3"/></>,
  eye: <><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  info: <><circle cx="12" cy="12" r="10"/><path d="M12 11v6M12 7h.01"/></>,
  file: <><path d="M5 2h9l5 5v15H5V2Z"/><path d="M14 2v5h5M8 12h8M8 16h8"/></>,
  message: <><path d="M3 4h18v14H8l-5 4V4Z"/><path d="M7 9h10M7 13h7"/></>,
  send: <><path d="m22 2-7 20-4-9-9-4 20-7Z"/><path d="m11 13 11-11"/></>,
  menu: <path d="M4 6h16M4 12h16M4 18h16"/>,
  ellipsis: <><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></>,
};

export default function Icon({ name, size = 18, strokeWidth = 1.8, className = '', ...props }) {
  return <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" {...props}>{paths[name] || paths.activity}</svg>;
}
