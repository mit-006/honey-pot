// Shared vocabulary: protocols, event types, categories. Used by the engine, simulator, seed and API.

export const CATEGORIES = {
  brute_force: "Brute force",
  web_exploit: "Web exploit",
  enumeration: "Enumeration",
  cred_stuffing: "Cred. stuffing",
  port_scan: "Port scanning",
  other: "Other",
};

export const PROTOCOLS = [
  "SSH",
  "HTTP",
  "MySQL",
  "SMB",
  "Redis",
  "RDP",
  "FTP",
  "DNS",
];

export const DEFAULT_PORTS = {
  SSH: 22,
  HTTP: 8080,
  MySQL: 3306,
  SMB: 445,
  Redis: 6379,
  RDP: 3389,
  FTP: 21,
  DNS: 53,
};

// protocol: which decoy protocol serves it (null = any decoy)
export const EVENT_TYPES = {
  "ssh.brute_force": {
    label: "Brute force",
    category: "brute_force",
    protocol: "SSH",
    weight: 30,
    showAttempts: true,
    alertTitle: (d) => `Brute force burst on ${d}`,
  },
  "http.sqli": {
    label: "SQL injection probe",
    category: "web_exploit",
    protocol: "HTTP",
    weight: 20,
    sev: "high",
    alertTitle: () => "SQL injection campaign",
  },
  "http.webshell": {
    label: "Web shell upload",
    category: "web_exploit",
    protocol: "HTTP",
    weight: 2,
    sev: "critical",
    alertTitle: () => "Web shell upload attempt",
  },
  "http.lfi": {
    label: "Path traversal probe",
    category: "web_exploit",
    protocol: "HTTP",
    weight: 2,
    sev: "medium",
    alertTitle: (d) => `Path traversal on ${d}`,
  },
  "mysql.cred_stuffing": {
    label: "Credential stuffing",
    category: "cred_stuffing",
    protocol: "MySQL",
    weight: 12,
    sev: "high",
    alertTitle: (d) => `Credential stuffing, ${d}`,
  },
  "smb.enum": {
    label: "Share enumeration",
    category: "enumeration",
    protocol: "SMB",
    weight: 10,
    sev: "medium",
    alertTitle: () => "SMB share enumeration",
  },
  "rdp.nla": {
    label: "NLA downgrade attempt",
    category: "enumeration",
    protocol: "RDP",
    weight: 1.5,
    sev: "medium",
    alertTitle: () => "Repeated RDP downgrade",
  },
  "redis.info": {
    label: "Unauthenticated INFO",
    category: "enumeration",
    protocol: "Redis",
    weight: 1.5,
    sev: "low",
    alertTitle: (d) => `Unauthenticated Redis recon, ${d}`,
  },
  "redis.config": {
    label: "CONFIG GET attempt",
    category: "enumeration",
    protocol: "Redis",
    weight: 1,
    sev: "low",
    alertTitle: (d) => `Redis CONFIG probing, ${d}`,
  },
  "ftp.anon": {
    label: "Anonymous login",
    category: "enumeration",
    protocol: "FTP",
    weight: 2,
    sev: "low",
    alertTitle: () => "Anonymous FTP login",
  },
  "dns.axfr": {
    label: "Zone transfer request",
    category: "enumeration",
    protocol: "DNS",
    weight: 1,
    sev: "info",
    alertTitle: () => "DNS zone transfer attempt",
  },
  "net.portscan": {
    label: "Port scan sweep",
    category: "port_scan",
    protocol: null,
    weight: 1.5,
    sev: "medium",
    alertTitle: (d) => `Port scan against ${d}`,
  },
};

export const typeLabel = (key) =>
  EVENT_TYPES[key] ? EVENT_TYPES[key].label : key;

export function severityFor(typeKey, attempts) {
  if (typeKey === "ssh.brute_force") {
    if (attempts >= 150) return "critical";
    if (attempts >= 60) return "high";
    if (attempts >= 20) return "medium";
    return "low";
  }
  return (EVENT_TYPES[typeKey] && EVENT_TYPES[typeKey].sev) || "low";
}

export function conditionText(rule) {
  const metric = {
    count: "events",
    attempts: "attempts",
    distinct: "distinct values",
  }[rule.metric];
  return `${metric} ${rule.op === ">=" ? "≥" : ">"} ${rule.threshold} in ${rule.window_s} s`;
}

export const SEED_RULES = [
  {
    name: "SSH brute force",
    code: "SSH-BRUTE",
    match_type: "ssh.brute_force",
    metric: "attempts",
    op: ">",
    threshold: 20,
    window_s: 60,
    severity: "critical",
    notify: "Email + dashboard",
    condition_text: "failed_login > N in 60 s",
    enabled: 1,
  },
  {
    name: "Web shell upload",
    code: "WEB-UPLOAD",
    match_type: "http.webshell",
    metric: "count",
    op: ">=",
    threshold: 1,
    window_s: 300,
    severity: "critical",
    notify: "Email + dashboard",
    condition_text: "upload.ext in [php, jsp, aspx]",
    enabled: 1,
  },
  {
    name: "SQL injection pattern",
    code: "WEB-SQLI",
    match_type: "http.sqli",
    metric: "count",
    op: ">=",
    threshold: 3,
    window_s: 900,
    severity: "high",
    notify: "Email + dashboard",
    condition_text: "payload matches sqli_sigs",
    enabled: 1,
  },
  {
    name: "Credential stuffing",
    code: "DB-CRED",
    match_type: "mysql.cred_stuffing",
    metric: "distinct",
    op: ">",
    threshold: 10,
    window_s: 300,
    severity: "high",
    notify: "Dashboard",
    condition_text: "unique_users > N per IP, 5 min",
    enabled: 1,
  },
  {
    name: "Share enumeration",
    code: "SMB-ENUM",
    match_type: "smb.enum",
    metric: "attempts",
    op: ">",
    threshold: 5,
    window_s: 300,
    severity: "medium",
    notify: "Dashboard",
    condition_text: "smb.tree_connect per IP",
    enabled: 1,
  },
  {
    name: "Port scan sweep",
    code: "NET-SCAN",
    match_type: "net.portscan",
    metric: "distinct",
    op: ">",
    threshold: 15,
    window_s: 30,
    severity: "medium",
    notify: "Dashboard",
    condition_text: "distinct_ports > N in 30 s",
    enabled: 0,
  },
  {
    name: "Anonymous FTP login",
    code: "FTP-ANON",
    match_type: "ftp.anon",
    metric: "count",
    op: ">=",
    threshold: 1,
    window_s: 300,
    severity: "low",
    notify: "Dashboard",
    condition_text: "ftp.user = anonymous",
    enabled: 1,
  },
];

// 16 decoys, 4 segments. (name, protocol, host, segment, health, enabled)
export const SEED_DECOYS = [
  ["ssh-dmz-01", "SSH", "10.20.1.14", "DMZ", "online", 1],
  ["ssh-dmz-02", "SSH", "10.20.1.15", "DMZ", "online", 1],
  ["web-admin-02", "HTTP", "10.20.1.21", "DMZ", "online", 1],
  ["web-portal-01", "HTTP", "10.20.1.22", "DMZ", "online", 1],
  ["web-upload-03", "HTTP", "10.20.1.23", "DMZ", "online", 1],
  ["dns-edge-01", "DNS", "10.20.1.53", "DMZ", "online", 1],
  ["mysql-db-03", "MySQL", "10.20.2.9", "Data", "online", 1],
  ["mysql-db-04", "MySQL", "10.20.2.10", "Data", "online", 1],
  ["smb-files-01", "SMB", "10.20.2.15", "Data", "degraded", 1],
  ["smb-files-02", "SMB", "10.20.2.16", "Data", "online", 1],
  ["ftp-archive-01", "FTP", "10.20.2.21", "Data", "online", 1],
  ["redis-cache-01", "Redis", "10.20.3.4", "Corp", "online", 1],
  ["redis-cache-02", "Redis", "10.20.3.5", "Corp", "online", 1],
  ["rdp-jump-01", "RDP", "10.20.3.18", "Corp", "online", 0],
  ["rdp-jump-02", "RDP", "10.20.4.18", "Edge", "online", 1],
  ["ssh-edge-03", "SSH", "10.20.4.30", "Edge", "online", 1],
];

// ISO2 -> display name (illustrative geo labels for simulated documentation-range IPs)
export const COUNTRIES = {
  DE: "Germany",
  NL: "Netherlands",
  CN: "China",
  RU: "Russia",
  US: "United States",
  BR: "Brazil",
  IN: "India",
  VN: "Vietnam",
  KR: "South Korea",
  FR: "France",
  GB: "United Kingdom",
  ID: "Indonesia",
  "??": "Unknown",
};
