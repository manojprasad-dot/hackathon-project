// Hand-picked minimal stroke icons (24x24 viewBox), inlined as strings so the
// extension never fetches assets over the network — consistent with the
// project's offline-first constraint.

export const ICONS = {
  "shield-check": '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
  "clock": '<circle cx="12" cy="12" r="8.5"/><path d="M12 8v4l3 2"/>',
  "type": '<path d="M5 6h14M12 6v13M9 19h6"/>',
  "link": '<path d="M9 15l6-6"/><path d="M8 12l-2.5 2.5a3.5 3.5 0 0 0 5 5L13 17"/><path d="M16 12l2.5-2.5a3.5 3.5 0 0 0-5-5L11 7"/>',
  "route": '<circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="6" r="2.5"/><path d="M8 18h5a4 4 0 0 0 4-4v-4"/>',
  "server": '<rect x="3.5" y="4" width="17" height="6" rx="1.5"/><rect x="3.5" y="14" width="17" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
  "key-round": '<circle cx="8" cy="14.5" r="4"/><path d="M11 11.5L19 3.5M16 6.5l2.5 2.5M13.5 9l2 2"/>',
  "shuffle": '<path d="M4 6h3.5L16 18h4"/><path d="M4 18h3.5L11 13"/><path d="M17 4l3 2-3 2M17 20l3-2-3-2"/>',
  "wifi-off": '<path d="M3 9a15 15 0 0 1 4.5-2.8M20.9 9A15 15 0 0 0 16 6.2M8.5 12.5a8 8 0 0 1 7 0M11 16a3.5 3.5 0 0 1 2 0"/><path d="M2 2l20 20"/><path d="M12 19h.01"/>',
  "shield": '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/>',
  "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 13.5a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V19.5a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H4.5a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34H10a1.7 1.7 0 0 0 1-1.55V4.5a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87V10a1.7 1.7 0 0 0 1.55 1H19.5a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.56 1z"/>',
  "external-link": '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14L21 3"/>',
  "flag": '<path d="M5 3v18"/><path d="M5 4h13l-2.5 4L18 12H5"/>',
  "cpu": '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="10" y="10" width="4" height="4"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>',
  "database": '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.5"/><path d="M4.5 5.5V18c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5V5.5"/><path d="M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5"/>',
  "history": '<path d="M3 3v5h5"/><path d="M3.1 13a9 9 0 1 0 2.6-6.4L3 8.9"/><path d="M12 7v5l4 2"/>',
  "chevron-right": '<path d="M9 6l6 6-6 6"/>',
};

export function icon(name, size = 16) {
  const body = ICONS[name] || ICONS["shield"];
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
}
