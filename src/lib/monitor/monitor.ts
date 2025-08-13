import * as dns from 'node:dns/promises';
import * as tls from 'node:tls';
import { performance } from 'node:perf_hooks';
import * as psl from 'psl';

// Only HTTP-reachable ports in serverless
const HTTP_PORTS = [
    { port: 80, scheme: 'http' },
    { port: 443, scheme: 'https' },
    { port: 8080, scheme: 'http' }
];

function abortableTimeout(ms: number) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), ms);
    return { controller, id };
}

async function safeHeadOrGet(url: string, timeoutMs = 8000) {
    const { controller, id } = abortableTimeout(timeoutMs);
    try {
        let res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal as any });
        if (!res.ok || res.status === 405) {
            res = await fetch(url, { method: 'GET', redirect: 'follow', signal: controller.signal as any });
        }
        return res;
    } finally {
        clearTimeout(id);
    }
}

async function rdapDomainInfo(domain: string) {
    // RDAP works over HTTPS and is allowed on Vercel
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        headers: { Accept: 'application/rdap+json' }
    });
    if (!res.ok) throw new Error(`RDAP failed with ${res.status}`);
    const data = await res.json() as any;

    let expiration: Date | null = null;
    if (Array.isArray(data?.events)) {
        const exp = data.events.find((e: any) =>
            typeof e?.eventAction === 'string' && /expire|expiration/i.test(e.eventAction)
        );
        if (exp?.eventDate) {
            const d = new Date(exp.eventDate);
            if (!Number.isNaN(d.getTime())) expiration = d;
        }
    }

    return {
        raw: data,
        expirationDate: expiration,
        daysUntilExpiry: expiration ? Math.round((expiration.getTime() - Date.now()) / 86400000) : null
    };
}

export async function monitorWebsite(inputUrl: string) {
    const timestamp = new Date().toISOString();
    const url = inputUrl.trim();
    const hostname = new URL(url).hostname;

    const result: any = { url, timestamp };

    /** Website Monitoring + Response Time (HTTP-based) **/
    try {
        const t0 = performance.now();
        const resp = await safeHeadOrGet(url, 8000);
        const t1 = performance.now();
        result.websiteMonitoring = {
            status: resp.ok ? 'online' : 'offline',
            statusCode: resp.status
        };
        result.responseTime = {
            value: Math.round(t1 - t0),
            unit: 'ms',
            status: (t1 - t0) < 500 ? 'good' : 'slow'
        };
    } catch (e: any) {
        result.websiteMonitoring = { status: 'offline', statusCode: null, error: e?.message ?? 'fetch failed' };
        result.responseTime = { value: null, unit: 'ms', status: 'error' };
    }

    /** DNS Monitoring (independent lookups, don't fail all on one error) **/
    const dnsResult: any = { status: 'resolved', records: {} };
    try {
        const [a, mx, txt, ns] = await Promise.allSettled([
            dns.resolve4(hostname),
            dns.resolveMx(hostname),
            dns.resolveTxt(hostname),
            dns.resolveNs(hostname),
        ]);
        if (a.status === 'fulfilled') dnsResult.records.A = a.value;
        if (mx.status === 'fulfilled') dnsResult.records.MX = mx.value.map(r => r.exchange);
        if (txt.status === 'fulfilled') dnsResult.records.TXT = (txt.value as string[][]).flat();
        if (ns.status === 'fulfilled') dnsResult.records.NS = ns.value;
        result.dnsMonitoring = dnsResult;
    } catch {
        result.dnsMonitoring = { status: 'error' };
    }

    /** SSL Monitoring (TLS handshake, Node runtime only) **/
    try {
        const data = await new Promise<any>((resolve, reject) => {
            const socket = tls.connect({
                host: hostname,
                port: 443,
                servername: hostname,
                timeout: 6000
            });

            socket.once('secureConnect', () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve(cert);
            });
            socket.once('timeout', () => {
                socket.destroy();
                reject(new Error('TLS timeout'));
            });
            socket.once('error', (err) => {
                socket.destroy();
                reject(err);
            });
        });

        const validFrom = new Date(data.valid_from);
        const validTo = new Date(data.valid_to);
        const daysUntilExpiry = Math.round((validTo.getTime() - Date.now()) / 86400000);

        result.sslMonitoring = {
            status: daysUntilExpiry > 0 ? 'valid' : 'expired',
            certificate: {
                issuer: data.issuer?.O ?? data.issuer?.CN ?? 'Unknown',
                subject: data.subject?.CN ?? hostname,
                validFrom: validFrom.toISOString(),
                validTo: validTo.toISOString(),
                daysUntilExpiry
            }
        };
    } catch (e: any) {
        result.sslMonitoring = { status: 'error', error: e?.message ?? 'TLS failed' };
    }

    /** Domain Expiration (RDAP over HTTP) **/
    try {
        const parsed = psl.parse(hostname) as psl.ParsedDomain;
        const domainName = parsed?.domain ?? hostname.split('.').slice(-2).join('.');
        const rdap = await rdapDomainInfo(domainName);
        result.domainExpiration = {
            status: 'success',
            daysUntilExpiry: rdap.daysUntilExpiry,
            expirationDate: rdap.expirationDate ? rdap.expirationDate.toISOString() : null,
            data: rdap.raw
        };
    } catch (e: any) {
        result.domainExpiration = { status: 'error', error: e?.message ?? 'RDAP failed' };
    }

    /** Port Monitoring (serverless-safe: HTTP ports only) **/
    result.portMonitoring = {};
    await Promise.all(HTTP_PORTS.map(async ({ port, scheme }) => {
        const target = `${scheme}://${hostname}${(scheme === 'http' && port !== 80) || (scheme === 'https' && port !== 443) ? `:${port}` : ''}/`;
        const t0 = performance.now();
        try {
            const resp = await safeHeadOrGet(target, 5000);
            const rt = Math.round(performance.now() - t0);
            result.portMonitoring[port] = { status: 'open', responseTime: rt, statusCode: resp.status };
        } catch {
            result.portMonitoring[port] = { status: 'closed-or-filtered' };
        }
    }));
    // Explicitly mark skipped ports
    const skipped = [21, 22, 23, 25, 53, 110, 143, 993, 995, 3306, 5432].filter(p => !HTTP_PORTS.some(h => h.port === p));
    for (const p of skipped) {
        result.portMonitoring[p] = { status: 'skipped_serverless' };
    }

    /** Ping Monitoring (HTTP-based reachability) **/
    try {
        const t0 = performance.now();
        await safeHeadOrGet(url, 6000);
        const t1 = performance.now();
        result.pingMonitoring = { status: 'reachable', time: Math.round(t1 - t0), unit: 'ms', method: 'http' };
    } catch (e: any) {
        result.pingMonitoring = { status: 'unreachable', method: 'http', error: e?.message ?? 'fetch failed' };
    }

    return result;
}



// import dns from 'dns/promises';
// import tls from 'tls';
// import net from 'net';
// import fetch from 'node-fetch';
// import * as psl from 'psl';
// import whois from 'whois-json';
// import ping from 'ping';
// import { performance } from 'perf_hooks';

// const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080];

// export async function monitorWebsite(url: string) {
//     const timestamp = new Date().toISOString();
//     const hostname = new URL(url).hostname;

//     const result: any = {
//         url,
//         timestamp
//     };

//     /** Website Monitoring + Response Time **/
//     try {
//         const start = performance.now();
//         const resp = await fetch(url, { method: 'GET' });
//         const end = performance.now();

//         result.websiteMonitoring = {
//             status: resp.ok ? 'online' : 'offline',
//             statusCode: resp.status
//         };
//         result.responseTime = {
//             value: Math.round(end - start),
//             unit: 'ms',
//             status: end - start < 500 ? 'good' : 'slow'
//         };
//     } catch {
//         result.websiteMonitoring = { status: 'offline', statusCode: null };
//         result.responseTime = { value: null, unit: 'ms', status: 'error' };
//     }

//     /** DNS Monitoring **/
//     try {
//         result.dnsMonitoring = {
//             status: 'resolved',
//             records: {
//                 A: await dns.resolve4(hostname),
//                 MX: (await dns.resolveMx(hostname)).map(r => r.exchange),
//                 TXT: (await dns.resolveTxt(hostname)).flat(),
//                 NS: await dns.resolveNs(hostname)
//             }
//         };
//     } catch {
//         result.dnsMonitoring = { status: 'error' };
//     }

//     /** SSL Monitoring **/
//     try {
//         const socket = tls.connect(443, hostname, { servername: hostname });
//         await new Promise(res => socket.once('secureConnect', res));
//         const cert = socket.getPeerCertificate();
//         socket.end();

//         const daysUntilExpiry = Math.round(
//             (new Date(cert.valid_to).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
//         );

//         result.sslMonitoring = {
//             status: daysUntilExpiry > 0 ? 'valid' : 'expired',
//             certificate: {
//                 issuer: cert.issuer.O,
//                 validFrom: new Date(cert.valid_from).toISOString(),
//                 validTo: new Date(cert.valid_to).toISOString(),
//                 daysUntilExpiry
//             }
//         };
//     } catch {
//         result.sslMonitoring = { status: 'error' };
//     }

//     /** Domain Expiration (WHOIS) **/
//     /** Domain Expiration (WHOIS) **/
//     /** Domain Expiration (WHOIS) **/
//     try {
//         const parsed = psl.parse(hostname);
//         let domainName: string | null = null;

//         if (typeof parsed === 'object' && 'domain' in parsed && parsed.domain) {
//             domainName = parsed.domain;
//         } else {
//             const parts = hostname.split('.');
//             if (parts.length >= 2) {
//                 domainName = parts.slice(-2).join('.');
//             }
//         }

//         if (domainName) {
//             try {
//                 const whoisData = await whois(domainName) as Record<string, any>;

//                 // Look for expiration date in multiple possible fields
//                 const expiryField = Object.keys(whoisData).find(key =>
//                     key.toLowerCase().includes('expiry') ||
//                     key.toLowerCase().includes('expiration') ||
//                     key.toLowerCase().includes('paid-till')
//                 );

//                 let daysUntilExpiry: number | null = null;
//                 if (expiryField) {
//                     const rawValue = whoisData[expiryField];
//                     if (rawValue) {
//                         const expiryDate = new Date(rawValue);
//                         if (!isNaN(expiryDate.getTime())) {
//                             daysUntilExpiry = Math.round(
//                                 (expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
//                             );
//                         }
//                     }
//                 }

//                 result.domainExpiration = {
//                     status: 'success',
//                     daysUntilExpiry,
//                     data: whoisData
//                 };
//             } catch (err: any) {
//                 result.domainExpiration = { status: 'error', error: err.message };
//             }
//         } else {
//             result.domainExpiration = { status: 'error', error: 'Unable to determine domain name' };
//         }
//     } catch (err: any) {
//         result.domainExpiration = { status: 'error', error: err.message };
//     }



//     /** Port Monitoring **/
//     result.portMonitoring = {};
//     await Promise.all(COMMON_PORTS.map(port => new Promise<void>(resolve => {
//         const socket = net.connect(port, hostname);
//         const start = performance.now();
//         socket.setTimeout(2000);
//         socket.on('connect', () => {
//             const rt = Math.round(performance.now() - start);
//             result.portMonitoring[port] = { status: 'open', responseTime: rt };
//             socket.destroy();
//             resolve();
//         });
//         socket.on('timeout', () => {
//             result.portMonitoring[port] = { status: 'timeout' };
//             socket.destroy();
//             resolve();
//         });
//         socket.on('error', () => {
//             result.portMonitoring[port] = { status: 'timeout' };
//             resolve();
//         });
//     })));

//     /** Ping Monitoring **/
//     try {
//         const pingRes = await ping.promise.probe(hostname, { timeout: 2 });
//         if (pingRes.alive) {
//             result.pingMonitoring = { status: 'reachable', time: pingRes.time };
//         } else {
//             result.pingMonitoring = { status: 'unreachable' };
//         }
//     } catch (err: any) {
//         result.pingMonitoring = { status: 'error', error: err.message };
//     }

//     return result;
// }
