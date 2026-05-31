require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = 3000;

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

if (!ANTHROPIC_API_KEY) {
  console.error('❌  Missing API key. Please create a .env file with your ANTHROPIC_API_KEY.');
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Simple rate limiter: max 5 requests per minute per IP
const rateLimitMap = {};
function isRateLimited(ip) {
  const now = Date.now();
  if (!rateLimitMap[ip]) rateLimitMap[ip] = [];
  rateLimitMap[ip] = rateLimitMap[ip].filter(t => now - t < 60000);
  if (rateLimitMap[ip].length >= 5) return true;
  rateLimitMap[ip].push(now);
  return false;
}

app.post('/analyze', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  if (isRateLimited(ip)) {
    return res.status(429).json({
      error: 'Too many requests. Please wait a minute and try again.'
    });
  }

  const { message, url } = req.body;

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ error: 'No message provided.' });
  }

  if (message.length > 5000) {
    return res.status(400).json({ error: 'Message is too long. Please keep it under 5000 characters.' });
  }

  const systemPrompt = `You are CyberMonk, an expert AI scam detection system built to protect everyday people in India from cyber fraud. Your job is to analyze messages and tell users clearly whether they are scams.

You MUST respond with valid JSON only. No markdown, no explanation, no text outside the JSON object.

Respond in this exact format:
{
  "risk_score": <number between 0 and 100>,
  "verdict": "<one of: Scam Detected | Likely Scam | Suspicious | Looks Safe>",
  "level": "<one of: danger | warning | success>",
  "scam_type": "<short label e.g. Bank Phishing | OTP Fraud | Lottery Scam | Fake Job | Customs Scam | Investment Scam | Impersonation | Legitimate Message>",
  "summary": "<1-2 plain sentences a non-tech person can understand. Do not use jargon.>",
  "signals": [
    { "name": "Urgency",   "value": "<e.g. Extreme / High / Low / None>",       "color": "<red|amber|green>" },
    { "name": "Sender",    "value": "<e.g. Fake / Suspicious / Looks real>",    "color": "<red|amber|green>" },
    { "name": "Request",   "value": "<e.g. OTP / Money / Info only / Nothing>", "color": "<red|amber|green>" },
    { "name": "Language",  "value": "<e.g. Manipulative / Mixed / Normal>",     "color": "<red|amber|green>" },
    { "name": "Links",     "value": "<e.g. Dangerous / Suspicious / Safe / No links>", "color": "<red|amber|green>" }
  ],
  "red_flags": ["<specific finding in plain English>", "..."],
  "positive_signals": ["<specific finding in plain English>", "..."],
  "advice": "<2-3 sentences of clear, simple, actionable advice for a non-tech Indian user. If it is a scam, tell them to report to 1930.>"
}

Risk score rules:
- 80 to 100 = Scam Detected  (level: danger)
- 50 to 79  = Likely Scam    (level: warning)
- 20 to 49  = Suspicious     (level: warning)
- 0  to 19  = Looks Safe     (level: success)

Write everything in simple, friendly English. Imagine you are explaining to someone's grandmother.
For Indian context, watch for: KBC lottery scams, bank KYC fraud, OTP theft, customs/parcel scams, fake job offers, investment/crypto fraud.
red_flags should be empty array [] if message is safe.
positive_signals should be empty array [] if message is a clear scam.`;

  const userContent = `Please analyze this message for scams:

MESSAGE:
${message.trim()}${url ? `\n\nURL INCLUDED IN MESSAGE:\n${url.trim()}` : ''}`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model:      'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        system:     systemPrompt,
        messages:   [{ role: 'user', content: userContent }]
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('Anthropic API error:', response.status, errText);
      if (response.status === 401) {
        return res.status(500).json({ error: 'Invalid API key. Please check your .env file.' });
      }
      return res.status(500).json({ error: 'AI service error. Please try again in a moment.' });
    }

    const data    = await response.json();
    const rawText = data.content.map(c => c.text || '').join('');
    const cleaned = rawText.replace(/```json|```/g, '').trim();
    const result  = JSON.parse(cleaned);

    return res.json(result);

  } catch (err) {
    console.error('Server error:', err.message);
    if (err instanceof SyntaxError) {
      return res.status(500).json({ error: 'AI returned an unexpected response. Please try again.' });
    }
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'CyberMonk is running' });
});

app.listen(PORT, () => {
  console.log('');
  console.log('  ✅  CyberMonk is running!');
  console.log('');
  console.log('  👉  Open this in your browser:');
  console.log(`      http://localhost:${PORT}`);
  console.log('');
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});