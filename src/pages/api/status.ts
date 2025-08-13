// pages/api/monitor.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { monitorWebsite } from '@/lib/monitor/monitor';

// adjust path to your function

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    // Allow only GET requests
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    // Get URL from request header
    const url = req.headers['x-monitor-url'] as string;

    if (!url) {
        return res.status(400).json({ error: 'URL header (x-monitor-url) is required' });
    }

    try {
        const report = await monitorWebsite(url);
        res.setHeader('Content-Type', 'application/json');
        res.status(200).json([report]); // always return an array
    } catch (err: any) {
        res.status(500).json({ error: err.message || 'Internal Server Error' });
    }
}
