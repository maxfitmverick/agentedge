const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

app.use(express.static('public'));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'agentedge-secret-2026';
const APP_URL = process.env.APP_URL || 'https://agentedgecrm.io';

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY);

const SEAT_LIMITS = { Solo: 1, Pro: 3, Brokerage: Infinity };

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function makeToken(user, trialEndsAt) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name, plan: user.plan, org_id: user.org_id, role: user.role, trial_ends_at: trialEndsAt || user.trial_ends_at },
    JWT_SECRET, { expiresIn: '30d' }
  );
}

// ── SIGNUP ──
app.post('/api/signup', async (req, res) => {
  const { name, email, password, plan } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const chosenPlan = plan || 'Solo';

    // Create user first
    const { data: user, error: userErr } = await supabase
      .from('users')
      .insert({ name, email: email.toLowerCase(), password: hash, plan: chosenPlan, trial_ends_at: trialEndsAt, role: 'owner' })
      .select().single();
    if (userErr) return res.status(400).json({ error: 'Email already exists' });

    // Create org for this owner
    const { data: org, error: orgErr } = await supabase
      .from('organizations')
      .insert({ owner_id: user.id, name: name + "'s Team", plan: chosenPlan })
      .select().single();
    if (orgErr) throw orgErr;

    // Link user to org
    await supabase.from('users').update({ org_id: org.id }).eq('id', user.id);

    const token = makeToken({ ...user, org_id: org.id }, trialEndsAt);
    res.json({ token, user: { name: user.name, email: user.email, plan: user.plan, org_id: org.id, role: 'owner', trial_ends_at: trialEndsAt } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user } = await supabase.from('users').select().eq('email', email.toLowerCase()).single();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = makeToken(user);
    res.json({ token, user: { name: user.name, email: user.email, plan: user.plan, org_id: user.org_id, role: user.role, trial_ends_at: user.trial_ends_at } });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── ME (trial check) ──
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('name,email,plan,trial_ends_at,org_id,role').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });
    const trialExpired = user.trial_ends_at ? new Date() > new Date(user.trial_ends_at) : false;
    res.json({ ...user, trial_expired: trialExpired });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ── TEAM: get members ──
app.get('/api/team', authMiddleware, async (req, res) => {
  try {
    const { data: me } = await supabase.from('users').select('org_id, plan, role').eq('id', req.user.id).single();
    if (!me?.org_id) return res.json({ members: [], invites: [], seats_used: 1, seat_limit: 1, plan: me?.plan || 'Solo' });

    const { data: members } = await supabase.from('users').select('id, name, email, role, created_at').eq('org_id', me.org_id);
    const { data: invites } = await supabase.from('invites').select('id, email, accepted, created_at').eq('org_id', me.org_id).eq('accepted', false);

    const seatLimit = SEAT_LIMITS[me.plan] || 1;
    res.json({ members: members || [], invites: invites || [], seats_used: (members || []).length, seat_limit: seatLimit === Infinity ? 'Unlimited' : seatLimit, plan: me.plan });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ── TEAM: invite agent ──
app.post('/api/team/invite', authMiddleware, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const { data: me } = await supabase.from('users').select('org_id, plan, role').eq('id', req.user.id).single();
    if (me.role !== 'owner') return res.status(403).json({ error: 'Only the account owner can invite agents' });

    // Check seat limit
    const { data: members } = await supabase.from('users').select('id').eq('org_id', me.org_id);
    const { data: pendingInvites } = await supabase.from('invites').select('id').eq('org_id', me.org_id).eq('accepted', false);
    const totalUsed = (members?.length || 0) + (pendingInvites?.length || 0);
    const seatLimit = SEAT_LIMITS[me.plan] || 1;

    if (totalUsed >= seatLimit) {
      return res.status(403).json({ error: `Your ${me.plan} plan only allows ${seatLimit} seat${seatLimit !== 1 ? 's' : ''}. Upgrade to add more agents.` });
    }

    // Check not already a member
    const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).eq('org_id', me.org_id).single();
    if (existing) return res.status(400).json({ error: 'That agent is already on your team' });

    const token = crypto.randomBytes(32).toString('hex');
    await supabase.from('invites').insert({ org_id: me.org_id, email: email.toLowerCase(), token });

    // TODO: send real email — for now return the invite link
    const inviteLink = `${APP_URL}/join?token=${token}`;
    res.json({ success: true, invite_link: inviteLink, message: `Invite link created for ${email}` });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── TEAM: remove member ──
app.delete('/api/team/member/:userId', authMiddleware, async (req, res) => {
  try {
    const { data: me } = await supabase.from('users').select('org_id, role').eq('id', req.user.id).single();
    if (me.role !== 'owner') return res.status(403).json({ error: 'Only the owner can remove members' });
    if (req.params.userId === req.user.id) return res.status(400).json({ error: "You can't remove yourself" });

    await supabase.from('users').update({ org_id: null, role: 'owner' }).eq('id', req.params.userId).eq('org_id', me.org_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ── TEAM: cancel invite ──
app.delete('/api/team/invite/:inviteId', authMiddleware, async (req, res) => {
  try {
    const { data: me } = await supabase.from('users').select('org_id, role').eq('id', req.user.id).single();
    if (me.role !== 'owner') return res.status(403).json({ error: 'Only the owner can cancel invites' });
    await supabase.from('invites').delete().eq('id', req.params.inviteId).eq('org_id', me.org_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ── JOIN via invite link ──
app.get('/join', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/');
  // Serve index.html — JS will read the token from URL and show signup form
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/join', async (req, res) => {
  const { token, name, password } = req.body;
  if (!token || !name || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { data: invite } = await supabase.from('invites').select().eq('token', token).eq('accepted', false).single();
    if (!invite) return res.status(400).json({ error: 'Invalid or expired invite link' });

    const { data: org } = await supabase.from('organizations').select().eq('id', invite.org_id).single();
    if (!org) return res.status(400).json({ error: 'Organization not found' });

    // Check seats again before accepting
    const { data: members } = await supabase.from('users').select('id').eq('org_id', invite.org_id);
    const seatLimit = SEAT_LIMITS[org.plan] || 1;
    if ((members?.length || 0) >= seatLimit) {
      return res.status(403).json({ error: 'This team has no available seats. Ask the owner to upgrade their plan.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const { data: user, error } = await supabase.from('users')
      .insert({ name, email: invite.email, password: hash, plan: org.plan, org_id: invite.org_id, role: 'agent' })
      .select().single();
    if (error) return res.status(400).json({ error: 'Account already exists for this email' });

    // Mark invite accepted
    await supabase.from('invites').update({ accepted: true }).eq('id', invite.id);

    const jwtToken = makeToken(user);
    res.json({ token: jwtToken, user: { name: user.name, email: user.email, plan: user.plan, org_id: user.org_id, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── OUTPUTS ──
app.post('/api/outputs', authMiddleware, async (req, res) => {
  const { tool, preview, full_output } = req.body;
  try {
    const { data, error } = await supabase.from('outputs').insert({ user_id: req.user.id, tool, preview, full_output }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Could not save output' }); }
});

app.get('/api/outputs', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('outputs').select().eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
    res.json(data || []);
  } catch (e) { res.status(500).json({ error: 'Could not fetch outputs' }); }
});

// ── BRAND ──
app.post('/api/brand', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('brand_settings').upsert({ user_id: req.user.id, ...req.body, updated_at: new Date() }, { onConflict: 'user_id' }).select().single();
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Could not save brand' }); }
});

app.get('/api/brand', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('brand_settings').select().eq('user_id', req.user.id).single();
    res.json(data || {});
  } catch (e) { res.json({}); }
});


// ══════════════════════════════
// TEAM / SEATS
// ══════════════════════════════

const SEAT_LIMITS = { Solo: 1, Pro: 3, Brokerage: Infinity };
const crypto = require('crypto');

// ── GET TEAM ── (list all members in org)
app.get('/api/team', authMiddleware, async (req, res) => {
  try {
    const { data: me } = await supabase.from('users').select('org_id, role, plan').eq('id', req.user.id).single();
    if (!me?.org_id) return res.status(400).json({ error: 'No organization found' });

    const { data: members } = await supabase
      .from('users')
      .select('id, name, email, role, created_at')
      .eq('org_id', me.org_id);

    const { data: invites } = await supabase
      .from('invites')
      .select('id, email, accepted, created_at')
      .eq('org_id', me.org_id)
      .eq('accepted', false);

    const limit = SEAT_LIMITS[me.plan] || 1;
    res.json({
      members: members || [],
      pending_invites: invites || [],
      seats_used: (members || []).length,
      seat_limit: limit === Infinity ? 'unlimited' : limit,
      plan: me.plan,
      role: me.role
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── INVITE AGENT ──
app.post('/api/team/invite', authMiddleware, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const { data: me } = await supabase.from('users').select('org_id, role, plan').eq('id', req.user.id).single();
    if (!me?.org_id) return res.status(400).json({ error: 'No organization found' });
    if (me.role !== 'owner') return res.status(403).json({ error: 'Only the owner can invite agents' });

    // Check seat limit
    const { data: members } = await supabase.from('users').select('id').eq('org_id', me.org_id);
    const { data: pending } = await supabase.from('invites').select('id').eq('org_id', me.org_id).eq('accepted', false);
    const totalUsed = (members || []).length + (pending || []).length;
    const limit = SEAT_LIMITS[me.plan] || 1;
    if (totalUsed >= limit) {
      return res.status(403).json({ error: `Your ${me.plan} plan allows ${limit} seat${limit===1?'':'s'}. Upgrade to add more agents.` });
    }

    // Check not already a member
    const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).eq('org_id', me.org_id).single();
    if (existing) return res.status(400).json({ error: 'This agent is already on your team' });

    // Create invite token
    const token = crypto.randomBytes(32).toString('hex');
    const { error: invErr } = await supabase.from('invites').insert({ org_id: me.org_id, email: email.toLowerCase(), token });
    if (invErr) return res.status(400).json({ error: 'Invite already sent to this email' });

    const inviteUrl = `${req.protocol}://${req.get('host')}/join?token=${token}`;
    res.json({ success: true, invite_url: inviteUrl, message: `Invite link created for ${email}` });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── REMOVE AGENT ──
app.delete('/api/team/member/:memberId', authMiddleware, async (req, res) => {
  try {
    const { data: me } = await supabase.from('users').select('org_id, role').eq('id', req.user.id).single();
    if (!me?.org_id || me.role !== 'owner') return res.status(403).json({ error: 'Only the owner can remove agents' });
    if (req.params.memberId === req.user.id) return res.status(400).json({ error: 'You cannot remove yourself' });

    await supabase.from('users').update({ org_id: null, role: 'owner' }).eq('id', req.params.memberId).eq('org_id', me.org_id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── CANCEL INVITE ──
app.delete('/api/team/invite/:inviteId', authMiddleware, async (req, res) => {
  try {
    const { data: me } = await supabase.from('users').select('org_id, role').eq('id', req.user.id).single();
    if (!me?.org_id || me.role !== 'owner') return res.status(403).json({ error: 'Not authorized' });
    await supabase.from('invites').delete().eq('id', req.params.inviteId).eq('org_id', me.org_id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── ACCEPT INVITE (join page) ──
app.get('/join', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/');
  // Serve the main app — JS will handle the join flow
  res.sendFile(require('path').join(__dirname, 'public', 'index.html'));
});

app.post('/api/team/accept', async (req, res) => {
  const { token, name, password } = req.body;
  if (!token || !name || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    // Find invite
    const { data: invite } = await supabase.from('invites').select('*, organizations(plan)').eq('token', token).eq('accepted', false).single();
    if (!invite) return res.status(400).json({ error: 'Invite link is invalid or already used' });

    // Check seats again
    const { data: members } = await supabase.from('users').select('id').eq('org_id', invite.org_id);
    const limit = SEAT_LIMITS[invite.organizations?.plan || 'Solo'] || 1;
    if ((members || []).length >= limit) return res.status(403).json({ error: 'This team has no available seats' });

    // Check if email already has an account
    const { data: existing } = await supabase.from('users').select('id').eq('email', invite.email).single();
    if (existing) {
      // Just add them to the org
      await supabase.from('users').update({ org_id: invite.org_id, role: 'agent' }).eq('id', existing.id);
    } else {
      // Create new account
      const hash = await bcrypt.hash(password, 10);
      const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      await supabase.from('users').insert({ name, email: invite.email, password: hash, plan: invite.organizations?.plan || 'Solo', org_id: invite.org_id, role: 'agent', trial_ends_at: trialEndsAt });
    }

    // Mark invite accepted
    await supabase.from('invites').update({ accepted: true }).eq('id', invite.id);

    // Log them in
    const { data: user } = await supabase.from('users').select().eq('email', invite.email).single();
    const jwtToken = jwt.sign({ id: user.id, email: user.email, name: user.name, plan: user.plan, org_id: user.org_id, role: user.role, trial_ends_at: user.trial_ends_at }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token: jwtToken, user: { name: user.name, email: user.email, plan: user.plan, org_id: user.org_id, role: user.role, trial_ends_at: user.trial_ends_at } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── AI GENERATE ──
app.post('/api/generate', authMiddleware, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'No prompt' });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1500, stream: true, messages: [{ role: 'user', content: prompt }] })
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
