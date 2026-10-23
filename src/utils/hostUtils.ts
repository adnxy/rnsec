const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Extract the lowercase hostname (IPv6 without brackets) from a URL or a bare `host[:port][/path]`.
 * Returns null for relative paths and anything that does not parse.
 */
export function extractHost(urlOrHost: string): string | null {
  const input = (urlOrHost ?? '').trim();
  if (!input || input.startsWith('/') && !input.startsWith('//')) return null;

  let candidate = input;
  if (input.startsWith('//')) candidate = `http:${input}`;
  else if (!SCHEME.test(input)) candidate = `http://${input}`;

  try {
    const host = new URL(candidate).hostname.toLowerCase().replace(/\.$/, '');
    const unwrapped = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    return unwrapped || null;
  } catch {
    return null;
  }
}

function parseIpv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  return octets.every(o => o <= 255) ? octets : null;
}

/** RFC 5737 documentation ranges plus the limited broadcast address: never a real server. */
function isReservedIpv4([a, b, c, d]: number[]): boolean {
  return (
    (a === 192 && b === 0 && c === 2) || // 192.0.2.0/24 TEST-NET-1
    (a === 198 && b === 51 && c === 100) || // 198.51.100.0/24 TEST-NET-2
    (a === 203 && b === 0 && c === 113) || // 203.0.113.0/24 TEST-NET-3
    (a === 255 && b === 255 && c === 255 && d === 255)
  );
}

/**
 * Classify an IPv4 literal: 'invalid' (not four octets <= 255, e.g. `300.1.1.1`), 'private'
 * (loopback, RFC1918, link-local, 10.0.2.2, 0.0.0.0), 'reserved' (documentation ranges,
 * broadcast) or 'public'.
 */
export function classifyIpv4(ip: string): 'invalid' | 'private' | 'reserved' | 'public' {
  const octets = parseIpv4(ip);
  if (!octets) return 'invalid';
  if (isPrivateIpv4(octets)) return 'private';
  return isReservedIpv4(octets) ? 'reserved' : 'public';
}

function isPrivateIpv4([a, b]: number[]): boolean {
  return (
    a === 127 || // loopback
    a === 10 || // includes 10.0.2.2 (Android emulator) and 10.0.3.2 (Genymotion)
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) || // link-local
    a === 0 // 0.0.0.0
  );
}

function isPrivateIpv6(host: string): boolean {
  if (host === '::1' || host === '::') return true;
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true; // fc00::/7 unique local
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true; // fe80::/10 link-local
  // IPv4-mapped (URL normalises ::ffff:127.0.0.1 to ::ffff:7f00:1)
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (mapped) {
    const hi = parseInt(mapped[1], 16);
    const lo = parseInt(mapped[2], 16);
    return isPrivateIpv4([hi >> 8, hi & 255, lo >> 8, lo & 255]);
  }
  return false;
}

/**
 * True for hosts that only exist on the developer's machine or LAN: localhost, loopback,
 * the Android emulator host (10.0.2.2), RFC1918 ranges, link-local, `*.local`, `*.localhost`.
 * Parses the URL rather than regex-matching, so `110.0.0.1` or `notlocalhost.example.com` are not local.
 */
export function isLocalOrPrivateHost(urlOrHost: string): boolean {
  const host = extractHost(urlOrHost);
  if (!host) return false;

  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === 'host.docker.internal') return true;

  const v4 = parseIpv4(host);
  if (v4) return isPrivateIpv4(v4);
  if (host.includes(':')) return isPrivateIpv6(host);
  return false;
}
