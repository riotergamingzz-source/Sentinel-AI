/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  SentinelAI — Cloudflare Worker Backend                     ║
 * ║  Deploy FREE at: https://workers.cloudflare.com             ║
 * ║  Zero cost · Global edge · No server needed                 ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * SETUP INSTRUCTIONS:
 * 1. Go to https://workers.cloudflare.com → Create account (free)
 * 2. Create a new Worker → paste this entire file
 * 3. Go to Settings → Variables → add these secrets:
 *    - ABUSEIPDB_KEY  = your AbuseIPDB API key
 *    - ANTHROPIC_KEY  = your Anthropic API key  (optional)
 *    - WORKER_SECRET  = any random string e.g. "sentinelai-2025-xyz"
 * 4. Deploy → copy your worker URL (e.g. https://sentinel.yourname.workers.dev)
 * 5. Paste that URL into the frontend's BACKEND_URL setting
 *
 * FREE TIER: 100,000 requests/day — more than enough for a SOC team
 */

// ──────────────────────────────────────────────────────────────
//  CORS HEADERS
// ──────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Worker-Secret',
  'Content-Type': 'application/json',
};

function cors(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: CORS });
}
function err(msg, status = 400) {
  return cors({ error: msg }, status);
}

// ──────────────────────────────────────────────────────────────
//  RATE LIMITER  (simple in-memory per IP, resets on cold start)
// ──────────────────────────────────────────────────────────────
const rateLimits = new Map();
function checkRate(ip, limit = 60, windowMs = 60000) {
  const now = Date.now();
  const entry = rateLimits.get(ip) || { count: 0, start: now };
  if (now - entry.start > windowMs) { entry.count = 0; entry.start = now; }
  entry.count++;
  rateLimits.set(ip, entry);
  return entry.count <= limit;
}

// ──────────────────────────────────────────────────────────────
//  MAIN HANDLER
// ──────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

    // Rate limit: 60 requests per minute per IP
    if (!checkRate(clientIP)) {
      return err('Rate limit exceeded. Try again in a minute.', 429);
    }

    // ── ROUTES ──────────────────────────────────────────────

    // GET /health — uptime check
    if (path === '/health' || path === '/') {
      return cors({
        status: 'online',
        version: '2.0.0',
        service: 'SentinelAI Worker',
        timestamp: new Date().toISOString(),
        capabilities: {
          abuseipdb: !!env.ABUSEIPDB_KEY,
          anthropic: !!env.ANTHROPIC_KEY,
          geolocation: true,
          hibp: true,
        },
      });
    }

    // POST /ip/check — AbuseIPDB lookup
    if (path === '/ip/check' && request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const { ip } = body;
      if (!ip) return err('Missing ip field');
      if (!env.ABUSEIPDB_KEY) return err('AbuseIPDB key not configured on worker', 503);

      const resp = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`,
        { headers: { Key: env.ABUSEIPDB_KEY, Accept: 'application/json' } }
      );
      const data = await resp.json();
      if (!resp.ok) return err(data?.errors?.[0]?.detail || 'AbuseIPDB error', resp.status);
      return cors(data);
    }

    // POST /ip/geo — ip-api.com geolocation proxy
    if (path === '/ip/geo' && request.method === 'POST') {
      const { ip } = await request.json().catch(() => ({}));
      if (!ip) return err('Missing ip field');

      const resp = await fetch(
        `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting,mobile`
      );
      const data = await resp.json();
      return cors(data);
    }

    // POST /ip/bulk — Bulk IP scan (max 20)
    if (path === '/ip/bulk' && request.method === 'POST') {
      const { ips } = await request.json().catch(() => ({}));
      if (!Array.isArray(ips) || ips.length === 0) return err('Missing ips array');
      const batch = ips.slice(0, 20);

      const results = await Promise.allSettled(
        batch.map(async (ip) => {
          const geo = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode,city,isp,proxy,hosting,query`).then(r => r.json());
          let abuse = null;
          if (env.ABUSEIPDB_KEY) {
            const ar = await fetch(
              `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
              { headers: { Key: env.ABUSEIPDB_KEY, Accept: 'application/json' } }
            );
            if (ar.ok) abuse = (await ar.json()).data;
          }
          return { ip, geo, abuse };
        })
      );

      return cors(results.map(r => r.status === 'fulfilled' ? r.value : { ip: 'error', error: r.reason?.message }));
    }

    // POST /email/analyze — Claude AI email analysis
    if (path === '/email/analyze' && request.method === 'POST') {
      const { content } = await request.json().catch(() => ({}));
      if (!content) return err('Missing content field');
      if (!env.ANTHROPIC_KEY) return err('Anthropic key not configured on worker', 503);

      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': env.ANTHROPIC_KEY,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 800,
          system: `You are an elite email security analyst at an antivirus company. Analyze emails for threats. Return ONLY valid JSON, no markdown, no prose. Schema:
{
  "verdict": "PHISHING|SPAM|MALWARE|BEC|SUSPICIOUS|LEGITIMATE",
  "confidence": 0-100,
  "spf": "PASS|FAIL|UNKNOWN",
  "dkim": "PASS|FAIL|UNKNOWN",
  "dmarc": "PASS|FAIL|UNKNOWN",
  "sender_legit": true|false,
  "spoofed": true|false,
  "social_engineering": ["tactic1","tactic2"],
  "malicious_urls": ["url1"],
  "suspicious_patterns": ["pattern1"],
  "action": "BLOCK|QUARANTINE|FLAG|ALLOW",
  "summary": "One sentence verdict"
}`,
          messages: [{ role: 'user', content: `Analyze this email:\n\n${content.substring(0, 3000)}` }],
        }),
      });

      if (!resp.ok) {
        const e = await resp.json().catch(() => ({}));
        return err(e?.error?.message || `Anthropic error ${resp.status}`, resp.status);
      }
      const data = await resp.json();
      const text = data.content?.[0]?.text || '{}';
      try {
        const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
        return cors(parsed);
      } catch {
        return cors({ verdict: 'UNKNOWN', summary: text, confidence: 0 });
      }
    }

    // POST /password/check — HIBP k-anonymity proxy
    if (path === '/password/check' && request.method === 'POST') {
      const { prefix } = await request.json().catch(() => ({}));
      if (!prefix || prefix.length !== 5) return err('Invalid prefix (need 5 hex chars)');

      const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true', 'User-Agent': 'SentinelAI-SecuritySOC/2.0' },
      });
      if (!resp.ok) return err(`HIBP error ${resp.status}`, resp.status);
      const text = await resp.text();
      return new Response(text, { headers: { ...CORS, 'Content-Type': 'text/plain' } });
    }

    // POST /dns/check — DNS/MX record check for email domain
    if (path === '/dns/check' && request.method === 'POST') {
      const { domain } = await request.json().catch(() => ({}));
      if (!domain) return err('Missing domain field');

      const [mx, spf, dmarc] = await Promise.allSettled([
        fetch(`https://dns.google/resolve?name=${domain}&type=MX`).then(r => r.json()),
        fetch(`https://dns.google/resolve?name=${domain}&type=TXT`).then(r => r.json()),
        fetch(`https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`).then(r => r.json()),
      ]);

      const mxRecords = mx.status === 'fulfilled' ? (mx.value.Answer || []).map(a => a.data) : [];
      const txtRecords = spf.status === 'fulfilled' ? (spf.value.Answer || []).map(a => a.data) : [];
      const dmarcRecords = dmarc.status === 'fulfilled' ? (dmarc.value.Answer || []).map(a => a.data) : [];

      const spfRecord = txtRecords.find(t => t.includes('v=spf1')) || null;
      const dmarcRecord = dmarcRecords[0] || null;

      return cors({
        domain,
        mx: mxRecords,
        spf: spfRecord,
        spf_valid: !!spfRecord,
        dmarc: dmarcRecord,
        dmarc_valid: !!dmarcRecord,
        has_mx: mxRecords.length > 0,
      });
    }

    // POST /threat/ioc — IOC (Indicator of Compromise) check via URLhaus
    if (path === '/threat/ioc' && request.method === 'POST') {
      const { url: targetUrl } = await request.json().catch(() => ({}));
      if (!targetUrl) return err('Missing url field');

      try {
        const resp = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `url=${encodeURIComponent(targetUrl)}`,
        });
        const data = await resp.json();
        return cors({
          url: targetUrl,
          found: data.query_status === 'is_listed',
          status: data.query_status,
          threat: data.threat || null,
          tags: data.tags || [],
          urlhaus_reference: data.urlhaus_reference || null,
        });
      } catch (e) {
        return cors({ url: targetUrl, found: false, error: e.message });
      }
    }

    return err('Route not found', 404);
  },
};
