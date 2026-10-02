/**
 * worker-chat.js — Cloudflare Worker Backend for Sarari Duck
 * Endpoint: POST /api/chat
 * Handles conversational queries with rate limiting, origin protection, and security headers.
 */

const SYSTEM_PROMPT = `You are "Sarari Duck", the 24/7 AI assistant for SARARI Digital — a premier web engineering company in Maiduguri, Borno State, Nigeria.

PERSONALITY:
Friendly, warm, and exceptionally patient. Like a sharp, reliable technical colleague. Cheerful, encouraging, and clear.

TONE & STYLE:
- UK English throughout (optimised, organisation, programme, colour).
- Short, punchy sentences (maximum 20 words per sentence).
- Direct and practical. No corporate jargon or robotic pleasantries.
- Never use emojis.
- Never apologise excessively.
- Keep every reply under 120 words.
- If unsure of custom technical requirements, state so honestly and direct the user to Abraham on WhatsApp.

SERVICES & PRICING:
1. Digital Presence Setup — from ₦75,000 (Delivery: 48 hours)
2. Landing Page — from ₦95,000 (Delivery: 3–5 days)
3. Business Website — from ₦250,000 (Delivery: 7–10 days)
4. Media & Institutional Platform — from ₦650,000 (Delivery: 14–21 days)
5. AI Automation — from ₦350,000 (Delivery: 2 weeks)
6. Care Plan — ₦30,000/month

THE SARARI STANDARD:
1. No templates — every layout is custom-engineered from scratch.
2. No hostage domains — domain, DNS, and hosting accounts belong 100% to the client.
3. No hidden fees — exact itemised quotation prior to work.
4. No account managers — clients work directly with Abraham, Lead Engineer.
5. No post-launch silence — 30 days of included post-launch support with every project.
6. Minimum engagement value is ₦95,000 for bespoke web builds.

COMMERCIAL POLICIES:
- Payment Terms: 50% deposit to commence; 50% upon final delivery and client acceptance.
- Payment Method: Direct Nigerian bank transfer in NGN.
- Domain & Hosting: Non-refundable once provisioned with registrar.
- Post-Year-One Renewals: Shared hosting renewal from ₦60,000/year; VPS from ₦150,000/year; or full-service Care Plan at ₦30,000/month.

FOUNDING COLLABORATION:
SARARI Digital is accepting three founding clients across our core verticals:
1. Radio and Media Organisations in Borno State
2. Hospitality & Premier Hotels
3. NGOs, Research Bodies, and Educational Institutions
Founding clients receive private pricing in exchange for a verified case study, testimonial, and introductions.

MULTILINGUAL CAPABILITIES:
Detect the user's language and respond naturally in that language:
- English
- Hausa (using Boko / Latin script)
- Hausa-English mix (Nigerian conversational style)

Common Hausa phrases and responses:
- Sannu / Sannu da zuwa -> Hello / Welcome
- Yaya aiki? -> How is work going?
- Nawa ne kudin website? -> State pricing clearly starting from ₦95,000
- Yaushe zai kammala? -> State delivery timeline clearly (3–10 days depending on tier)
- Na gode -> You are welcome / Ba komai

BOUNDARIES:
- Never invent unlisted services, fictional team members, or arbitrary discounts.
- Never discuss partisan politics, religion, or competitor agencies.
- If asked unrelated questions: "That is outside what I can assist with. You can speak directly with Abraham on WhatsApp: https://wa.me/2349128387069"
- Always conclude with a polite, natural next step or WhatsApp handover.`;

// In-memory rate limiting map: IP -> { count: number, resetTime: number }
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour window

function isOriginAllowed(origin) {
  if (!origin) return false;
  if (origin === 'https://sararidigital.com.ng') return true;
  if (origin === 'https://www.sararidigital.com.ng') return true;
  if (origin.endsWith('.vercel.app')) return true;
  if (origin.endsWith('.pages.dev')) return true;
  if (origin.endsWith('.github.io')) return true;
  if (origin.startsWith('http://localhost:')) return true;
  return false;
}

function getCorsHeaders(origin) {
  const allowed = isOriginAllowed(origin) ? origin : 'https://sararidigital.com.ng';
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  // Periodic eviction if map grows
  if (rateLimitMap.size > 2000) {
    for (const [key, val] of rateLimitMap.entries()) {
      if (now > val.resetTime) {
        rateLimitMap.delete(key);
      }
    }
  }

  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1 };
  }

  if (entry.count >= RATE_LIMIT_MAX) {
    return { allowed: false, remaining: 0 };
  }

  entry.count += 1;
  return { allowed: true, remaining: RATE_LIMIT_MAX - entry.count };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const corsHeaders = getCorsHeaders(origin);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // Endpoint gate
    if (url.pathname !== '/api/chat') {
      return new Response(JSON.stringify({ error: 'Endpoint not found.' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed. Use POST.' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // Rate limiting
    const clientIp = request.headers.get('CF-Connecting-IP') || 
                     request.headers.get('X-Forwarded-For') || 
                     '127.0.0.1';
    
    const rateCheck = checkRateLimit(clientIp);
    if (!rateCheck.allowed) {
      return new Response(
        JSON.stringify({
          error: 'Rate limit reached (20 queries per hour). For urgent questions, message Abraham directly on WhatsApp: https://wa.me/2349128387069'
        }),
        {
          status: 429,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        }
      );
    }

    // Verify server-side API key exists
    const apiKey = env.AI_API_KEY;
    if (!apiKey) {
      return new Response(
        JSON.stringify({
          error: 'Assistant backend key is not configured. Please chat with Abraham on WhatsApp: https://wa.me/2349128387069'
        }),
        {
          status: 503,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        }
      );
    }

    // Parse and sanitize payload
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(
        JSON.stringify({ error: 'Invalid JSON request payload.' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        }
      );
    }

    if (!body || !Array.isArray(body.messages) || body.messages.length === 0) {
      return new Response(
        JSON.stringify({ error: 'Payload must contain a non-empty messages array.' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        }
      );
    }

    // Retain only last 10 messages and truncate length to avoid token abuse
    const recentMessages = body.messages.slice(-10);
    const sanitizedMessages = [];

    for (const msg of recentMessages) {
      if (!msg || typeof msg !== 'object') continue;
      const role = msg.role === 'assistant' ? 'assistant' : 'user';
      let content = typeof msg.content === 'string' ? msg.content.trim() : '';
      if (!content) continue;
      if (content.length > 1500) content = content.substring(0, 1500);
      sanitizedMessages.push({ role, content });
    }

    if (sanitizedMessages.length === 0) {
      return new Response(
        JSON.stringify({ error: 'No valid message content provided.' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        }
      );
    }

    const endpoint = env.AI_ENDPOINT || 'https://tokenra.io/v1/chat/completions';
    const model = env.AI_MODEL || 'stealth/ox-alpha';

    const providerPayload = {
      model,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        ...sanitizedMessages
      ],
      temperature: 0.3,
      max_tokens: 450
    };

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(providerPayload)
      });

      if (!response.ok) {
        return new Response(
          JSON.stringify({
            error: 'AI service temporarily unavailable. Chat directly on WhatsApp: https://wa.me/2349128387069'
          }),
          {
            status: 502,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          }
        );
      }

      const data = await response.json();
      const reply = data.choices?.[0]?.message?.content || 
                    'I am unable to answer right now. You can speak with Abraham on WhatsApp: https://wa.me/2349128387069';

      return new Response(
        JSON.stringify({ reply }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        }
      );
    } catch {
      return new Response(
        JSON.stringify({
          error: 'Connection error communicating with AI service. Please reach us on WhatsApp: https://wa.me/2349128387069'
        }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        }
      );
    }
  }
};
