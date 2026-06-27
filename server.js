const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// ── ROUTING: landing page for visitors, /app for logged-in users ──
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'landing.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use(express.static('public'));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'agentedge-secret-2026';

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY);

// ── AUTH MIDDLEWARE ──
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── SIGNUP ── (sets 7-day trial automatically)
app.post('/api/signup', async (req, res) => {
  const { name, email, password, plan } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const { data, error } = await supabase
      .from('users')
      .insert({ name, email: email.toLowerCase(), password: hash, plan: plan || 'Solo', trial_ends_at: trialEndsAt })
      .select()
      .single();
    if (error) return res.status(400).json({ error: 'Email already exists' });
    const token = jwt.sign(
      { id: data.id, email: data.email, name: data.name, plan: data.plan, trial_ends_at: data.trial_ends_at },
      JWT_SECRET, { expiresIn: '30d' }
    );
    res.json({ token, user: { name: data.name, email: data.email, plan: data.plan, trial_ends_at: data.trial_ends_at } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LOGIN ── (returns trial_ends_at so client can show countdown)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user } = await supabase
      .from('users')
      .select()
      .eq('email', email.toLowerCase())
      .single();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, plan: user.plan, trial_ends_at: user.trial_ends_at },
      JWT_SECRET, { expiresIn: '30d' }
    );
    res.json({ token, user: { name: user.name, email: user.email, plan: user.plan, trial_ends_at: user.trial_ends_at } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── SAVE OUTPUT ──
app.post('/api/outputs', authMiddleware, async (req, res) => {
  const { tool, preview, full_output } = req.body;
  try {
    const { data, error } = await supabase
      .from('outputs')
      .insert({ user_id: req.user.id, tool, preview, full_output })
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Could not save output' });
  }
});

// ── GET OUTPUTS ──
app.get('/api/outputs', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase
      .from('outputs')
      .select()
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(50);
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: 'Could not fetch outputs' });
  }
});

// ── SAVE BRAND ──
app.post('/api/brand', authMiddleware, async (req, res) => {
  const brand = req.body;
  try {
    const { data } = await supabase
      .from('brand_settings')
      .upsert({ user_id: req.user.id, ...brand, updated_at: new Date() }, { onConflict: 'user_id' })
      .select()
      .single();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Could not save brand' });
  }
});

// ── GET BRAND ──
app.get('/api/brand', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase
      .from('brand_settings')
      .select()
      .eq('user_id', req.user.id)
      .single();
    res.json(data || {});
  } catch (e) {
    res.json({});
  }
});

// ── AI GENERATE ──
app.post('/api/generate', authMiddleware, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'No prompt' });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1500,
        stream: true,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6).trim();
          if (data === '[DONE]') { res.write('data: [DONE]\n\n'); continue; }
          try {
            const parsed = JSON.parse(data);
            if (parsed.type === 'content_block_delta' && parsed.delta?.text) {
              res.write(`data: ${JSON.stringify({ text: parsed.delta.text })}\n\n`);
            }
          } catch {}
        }
      }
    }
    res.end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'API error' });
  }
});

app.listen(3000, () => console.log('AgentEdge running on port 3000'));
