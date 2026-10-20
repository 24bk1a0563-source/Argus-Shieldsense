/**
 * ShieldSense - Node.js Backend Server & Google OAuth 2.0 / Gmail API Gateway
 * 
 * Flow:
 * 1. GET /auth/google -> Redirects to accounts.google.com/o/oauth2/v2/auth
 * 2. GET /auth/google/callback -> Exchanges code for access_token with client_secret server-side
 * 3. GET /api/auth/status -> Returns authentication and configuration status
 * 4. GET /api/gmail/messages -> Fetches and parses real messages from Gmail REST API
 * 5. POST /api/auth/logout -> Clears authentication session
 */

require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const https = require('https');
const querystring = require('querystring');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cookieParser(process.env.SESSION_SECRET || 'shieldsense_secret'));
// Serve only the frontend files (never server.js, .env or package.json)
const PUBLIC_FILES = ['index.html', 'style.css', 'analyzer.js', 'app.js'];
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
PUBLIC_FILES.forEach((file) => {
  app.get('/' + file, (req, res) => res.sendFile(path.join(__dirname, file)));
});

// In-Memory Token Sessions (Keyed by session ID)
const SESSIONS = new Map();

// Helper to make HTTPS requests without external dependencies
function httpsRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ statusCode: res.statusCode, data: parsed });
          } else {
            resolve({ statusCode: res.statusCode, error: parsed });
          }
        } catch (e) {
          resolve({ statusCode: res.statusCode, data: body });
        }
      });
    });

    req.on('error', (err) => reject(err));

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

// ==========================================
// 1. GOOGLE OAUTH 2.0 ROUTES
// ==========================================

/**
 * Step 1: Initiate OAuth 2.0 flow
 */
app.get('/auth/google', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = process.env.REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;

  if (!clientId || clientId.trim() === '' || clientId.includes('your_google_client_id')) {
    return res.redirect('/?oauth_error=credentials_missing#dashboard/settings');
  }

  const scopes = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
  ].join(' ');

  const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + querystring.stringify({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: scopes,
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'true'
  });

  res.redirect(authUrl);
});

/**
 * Step 2: OAuth 2.0 Callback Route
 * Receives code from Google, securely exchanges for token server-side
 */
app.get('/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error) {
    return res.redirect(`/?oauth_error=${encodeURIComponent(error)}#dashboard/settings`);
  }

  if (!code) {
    return res.redirect('/?oauth_error=no_code#dashboard/settings');
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;

  if (!clientId || !clientSecret) {
    return res.redirect('/?oauth_error=credentials_missing#dashboard/settings');
  }

  try {
    // Exchange authorization code for tokens
    const postData = querystring.stringify({
      code: code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    });

    const tokenResponse = await httpsRequest({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, postData);

    if (tokenResponse.error || !tokenResponse.data.access_token) {
      console.error('Google token exchange error:', tokenResponse);
      const errMsg = tokenResponse.error && tokenResponse.error.error_description 
        ? tokenResponse.error.error_description 
        : 'token_exchange_failed';
      return res.redirect(`/?oauth_error=${encodeURIComponent(errMsg)}#dashboard/settings`);
    }

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    // Fetch user profile info (email)
    let userEmail = 'authenticated-user@gmail.com';
    try {
      const userinfoRes = await httpsRequest({
        hostname: 'www.googleapis.com',
        path: '/oauth2/v2/userinfo',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${access_token}`
        }
      });
      if (userinfoRes.data && userinfoRes.data.email) {
        userEmail = userinfoRes.data.email;
      }
    } catch (e) {
      console.warn('Could not fetch userinfo:', e.message);
    }

    // Generate Session ID & Store Token securely server-side
    const sessionId = 'sess_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    SESSIONS.set(sessionId, {
      accessToken: access_token,
      refreshToken: refresh_token,
      email: userEmail,
      createdAt: Date.now(),
      expiresAt: Date.now() + (expires_in * 1000)
    });

    // Set secure HTTP-only cookie
    res.cookie('shieldsense_session', sessionId, {
      httpOnly: true,
      secure: false, // localhost
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Redirect to ShieldSense Dashboard
    res.redirect('/#dashboard');

  } catch (err) {
    console.error('OAuth Callback exception:', err);
    res.redirect(`/?oauth_error=${encodeURIComponent(err.message)}#dashboard/settings`);
  }
});

// ==========================================
// 2. API ENDPOINTS
// ==========================================

/**
 * Check Authentication & Configuration Status
 */
app.get('/api/auth/status', (req, res) => {
  const sessionId = req.cookies.shieldsense_session;
  const clientId = process.env.GOOGLE_CLIENT_ID || '';
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
  const isConfigured = Boolean(clientId && clientSecret && !clientId.includes('your_google_client_id'));

  if (sessionId && SESSIONS.has(sessionId)) {
    const session = SESSIONS.get(sessionId);
    return res.json({
      authenticated: true,
      configured: isConfigured,
      email: session.email,
      clientId: clientId ? clientId.substring(0, 15) + '...' : ''
    });
  }

  res.json({
    authenticated: false,
    configured: isConfigured,
    email: null,
    clientId: clientId ? clientId.substring(0, 15) + '...' : ''
  });
});

/**
 * Fetch Real Gmail Messages via Gmail REST API
 */
app.get('/api/gmail/messages', async (req, res) => {
  const sessionId = req.cookies.shieldsense_session;

  if (!sessionId || !SESSIONS.has(sessionId)) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'No active authenticated Gmail session.'
    });
  }

  const session = SESSIONS.get(sessionId);
  const token = session.accessToken;

  try {
    // 1. List messages from Gmail API
    const listRes = await httpsRequest({
      hostname: 'gmail.googleapis.com',
      path: '/gmail/v1/users/me/messages?maxResults=12',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (listRes.error || !listRes.data || !listRes.data.messages) {
      return res.json({
        messages: [],
        count: 0,
        account: session.email
      });
    }

    const messageList = listRes.data.messages;
    const parsedEmails = [];

    // 2. Fetch details for each message
    for (const msgRef of messageList) {
      try {
        const detailRes = await httpsRequest({
          hostname: 'gmail.googleapis.com',
          path: `/gmail/v1/users/me/messages/${msgRef.id}?format=full`,
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (detailRes.data && detailRes.data.payload) {
          const payload = detailRes.data.payload;
          const headers = payload.headers || [];

          const subjectHeader = headers.find(h => h.name.toLowerCase() === 'subject');
          const fromHeader = headers.find(h => h.name.toLowerCase() === 'from');
          const dateHeader = headers.find(h => h.name.toLowerCase() === 'date');

          // Extract text body
          let bodyText = detailRes.data.snippet || '';
          if (payload.parts && payload.parts.length > 0) {
            for (const part of payload.parts) {
              if (part.mimeType === 'text/plain' && part.body && part.body.data) {
                bodyText = Buffer.from(part.body.data, 'base64').toString('utf-8');
                break;
              }
            }
          }

          // Extract attachments
          const attachments = [];
          if (payload.parts) {
            payload.parts.forEach(part => {
              if (part.filename && part.filename.length > 0) {
                attachments.push({
                  name: part.filename,
                  size: (part.body && part.body.size) ? part.body.size : 102400
                });
              }
            });
          }

          // Extract URLs from body
          const urlRegex = /(https?:\/\/[^\s<>"']+)|(www\.[^\s<>"']+)/gi;
          const extractedLinks = (bodyText.match(urlRegex) || []).slice(0, 5);

          parsedEmails.push({
            id: detailRes.data.id,
            sender: fromHeader ? fromHeader.value : 'Unknown Sender',
            subject: subjectHeader ? subjectHeader.value : '(No Subject)',
            date: dateHeader ? new Date(dateHeader.value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Today',
            body: bodyText,
            links: extractedLinks,
            attachments: attachments,
            isQuarantined: false
          });
        }
      } catch (e) {
        console.warn(`Error parsing message ${msgRef.id}:`, e.message);
      }
    }

    res.json({
      messages: parsedEmails,
      count: parsedEmails.length,
      account: session.email
    });

  } catch (err) {
    console.error('Error fetching Gmail messages:', err);
    res.status(500).json({ error: 'gmail_api_error', message: err.message });
  }
});

/**
 * Logout / Disconnect
 */
app.post('/api/auth/logout', (req, res) => {
  const sessionId = req.cookies.shieldsense_session;
  if (sessionId && SESSIONS.has(sessionId)) {
    SESSIONS.delete(sessionId);
  }
  res.clearCookie('shieldsense_session');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🛡️ ShieldSense Server running on http://localhost:${PORT}`);
  console.log(`Google OAuth Callback: http://localhost:${PORT}/auth/google/callback`);
  console.log(`====================================================`);
});
