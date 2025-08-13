import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';
import fetch from 'node-fetch';
import * as psl from 'psl';
import whois from 'whois-json';
import ping from 'ping';
import { performance } from 'perf_hooks';

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080];

export async function monitorWebsite(url: string) {
    const timestamp = new Date().toISOString();
    const hostname = new URL(url).hostname;

    const result: any = {
        url,
        timestamp
    };

    /** Website Monitoring + Response Time **/
    try {
        const start = performance.now();
        const resp = await fetch(url, { method: 'GET' });
        const end = performance.now();

        result.websiteMonitoring = {
            status: resp.ok ? 'online' : 'offline',
            statusCode: resp.status
        };
        result.responseTime = {
            value: Math.round(end - start),
            unit: 'ms',
            status: end - start < 500 ? 'good' : 'slow'
        };
    } catch {
        result.websiteMonitoring = { status: 'offline', statusCode: null };
        result.responseTime = { value: null, unit: 'ms', status: 'error' };
    }

    /** DNS Monitoring **/
    try {
        result.dnsMonitoring = {
            status: 'resolved',
            records: {
                A: await dns.resolve4(hostname),
                MX: (await dns.resolveMx(hostname)).map(r => r.exchange),
                TXT: (await dns.resolveTxt(hostname)).flat(),
                NS: await dns.resolveNs(hostname)
            }
        };
    } catch {
        result.dnsMonitoring = { status: 'error' };
    }

    /** SSL Monitoring **/
    try {
        const socket = tls.connect(443, hostname, { servername: hostname });
        await new Promise(res => socket.once('secureConnect', res));
        const cert = socket.getPeerCertificate();
        socket.end();

        const daysUntilExpiry = Math.round(
            (new Date(cert.valid_to).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
        );

        result.sslMonitoring = {
            status: daysUntilExpiry > 0 ? 'valid' : 'expired',
            certificate: {
                issuer: cert.issuer.O,
                validFrom: new Date(cert.valid_from).toISOString(),
                validTo: new Date(cert.valid_to).toISOString(),
                daysUntilExpiry
            }
        };
    } catch {
        result.sslMonitoring = { status: 'error' };
    }

    /** Domain Expiration (WHOIS) **/
    /** Domain Expiration (WHOIS) **/
    /** Domain Expiration (WHOIS) **/
    try {
        const parsed = psl.parse(hostname);
        let domainName: string | null = null;

        if (typeof parsed === 'object' && 'domain' in parsed && parsed.domain) {
            domainName = parsed.domain;
        } else {
            const parts = hostname.split('.');
            if (parts.length >= 2) {
                domainName = parts.slice(-2).join('.');
            }
        }

        if (domainName) {
            try {
                const whoisData = await whois(domainName) as Record<string, any>;

                // Look for expiration date in multiple possible fields
                const expiryField = Object.keys(whoisData).find(key =>
                    key.toLowerCase().includes('expiry') ||
                    key.toLowerCase().includes('expiration') ||
                    key.toLowerCase().includes('paid-till')
                );

                let daysUntilExpiry: number | null = null;
                if (expiryField) {
                    const rawValue = whoisData[expiryField];
                    if (rawValue) {
                        const expiryDate = new Date(rawValue);
                        if (!isNaN(expiryDate.getTime())) {
                            daysUntilExpiry = Math.round(
                                (expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
                            );
                        }
                    }
                }

                result.domainExpiration = {
                    status: 'success',
                    daysUntilExpiry,
                    data: whoisData
                };
            } catch (err: any) {
                result.domainExpiration = { status: 'error', error: err.message };
            }
        } else {
            result.domainExpiration = { status: 'error', error: 'Unable to determine domain name' };
        }
    } catch (err: any) {
        result.domainExpiration = { status: 'error', error: err.message };
    }



    /** Port Monitoring **/
    result.portMonitoring = {};
    await Promise.all(COMMON_PORTS.map(port => new Promise<void>(resolve => {
        const socket = net.connect(port, hostname);
        const start = performance.now();
        socket.setTimeout(2000);
        socket.on('connect', () => {
            const rt = Math.round(performance.now() - start);
            result.portMonitoring[port] = { status: 'open', responseTime: rt };
            socket.destroy();
            resolve();
        });
        socket.on('timeout', () => {
            result.portMonitoring[port] = { status: 'timeout' };
            socket.destroy();
            resolve();
        });
        socket.on('error', () => {
            result.portMonitoring[port] = { status: 'timeout' };
            resolve();
        });
    })));

    /** Ping Monitoring **/
    try {
        const pingRes = await ping.promise.probe(hostname, { timeout: 2 });
        if (pingRes.alive) {
            result.pingMonitoring = { status: 'reachable', time: pingRes.time };
        } else {
            result.pingMonitoring = { status: 'unreachable' };
        }
    } catch (err: any) {
        result.pingMonitoring = { status: 'error', error: err.message };
    }

    return result;
}
