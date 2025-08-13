import type { NextApiRequest, NextApiResponse } from 'next';
import { monitorWebsite } from '@/lib/monitor/monitor';

export const config = { api: { bodyParser: false } }; // not required, but ok

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed. Use GET.' });
    }
    const urlHeader = req.headers['x-monitor-url'];
    const target = Array.isArray(urlHeader) ? urlHeader[0] : urlHeader;
    if (!target) {
        return res.status(400).json({ error: 'Missing x-monitor-url header' });
    }
    try {
        const data = await monitorWebsite(target);
        res.setHeader('Content-Type', 'application/json');
        return res.status(200).json(data);
    } catch (e: any) {
        return res.status(500).json({ error: e?.message ?? 'Internal error' });
    }
}




// // pages/api/monitor.ts
// import type { NextApiRequest, NextApiResponse } from 'next';
// import { monitorWebsite } from '@/lib/monitor/monitor';

// // adjust path to your function

// export default async function handler(
//     req: NextApiRequest,
//     res: NextApiResponse
// ) {
//     // Allow only GET requests
//     if (req.method !== 'GET') {
//         return res.status(405).json({ error: 'Method Not Allowed' });
//     }

//     // Get URL from request header
//     const url = req.headers['x-monitor-url'] as string;

//     if (!url) {
//         return res.status(400).json({ error: 'URL header (x-monitor-url) is required' });
//     }

//     try {
//         const report = await monitorWebsite(url);
//         res.setHeader('Content-Type', 'application/json');
//         res.status(200).json([report]); // always return an array
//     } catch (err: any) {
//         res.status(500).json({ error: err.message || 'Internal Server Error' });
//     }
// }
