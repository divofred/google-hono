import crypto from 'node:crypto';
import { Context, Hono } from 'hono';
import { serveStatic } from 'hono/cloudflare-workers';

const app = new Hono();

function generateJWT(payload: string, secret: any, expiresIn: string) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(payload);
  const signature = sign(`${encodedHeader}.${encodedPayload}`, secret);
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function base64UrlEncode(str: string) {
  const base64 = btoa(str);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sign(data: string, secret: any) {
  const key = parseKey(secret);
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  const signature = hmac.digest('base64');
  return base64UrlEncode(signature);
}

function parseKey(key: any) {
  return crypto.createHash('sha256').update(key).digest();
}

function parseCookie(cookieHeader: string | null, cookieName: string) {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.split('=');
    if (name.trim() === cookieName) {
      return value.trim();
    }
  }
  return null;
}

function decodeJWT(token: { split: (arg0: string) => [any, any] }) {
  const [encodedHeader, encodedPayload] = token.split('.');
  const header = JSON.parse(base64UrlDecode(encodedHeader));
  const payload = JSON.parse(base64UrlDecode(encodedPayload));
  return { header, payload };
}

function base64UrlDecode(str: string) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4 === 0 ? 0 : 4 - (base64.length % 4);
  const paddedBase64 = base64 + '==='.slice(0, padding);
  return atob(paddedBase64);
}

app.get('/auth/callback/google', async (c: Context) => {
  const code = new URL(c.req.raw.url).searchParams.get('code');
  if (!code) return;
  try {
    const tokenEndpoint = new URL('https://accounts.google.com/o/oauth2/token');
    tokenEndpoint.searchParams.set('code', code);
    tokenEndpoint.searchParams.set('grant_type', 'authorization_code');
    // Get the Google Client ID from the env
    tokenEndpoint.searchParams.set('client_id', c.env.GOOGLE_CLIENT_ID);
    // Get the Google Secret from the env
    tokenEndpoint.searchParams.set('client_secret', c.env.GOOGLE_CLIENT_SECRET);
    // Add your own callback URL
    tokenEndpoint.searchParams.set('redirect_uri', c.env.GOOGLE_CALLBACK_URL);
    const tokenResponse = await fetch(
      tokenEndpoint.origin + tokenEndpoint.pathname,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: tokenEndpoint.searchParams.toString()
      }
    );
    const tokenData: any = await tokenResponse.json();
    // Get the access_token from the Token fetch response
    const accessToken = tokenData.access_token;
    const userInfoResponse = await fetch(
      'https://www.googleapis.com/oauth2/v2/userinfo',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );
    // Get user info via that fetched access_token
    const userInfo = await userInfoResponse.json();
    // Destructure email, name, picture from the users' Google Account Info
    const { email, name, picture }: any = userInfo;
    const tokenPayload = JSON.stringify({ email, name, picture });
    // Create a Cookie for the payload, i.e. user info as above
    // Set the expiration to say 1 hour
    const cookie = generateJWT(tokenPayload, c.env.AUTH_SECRET, '1h');
    return new Response(null, {
      status: 302,
      headers: {
        Location: '/',
        // This is the key here, place the cookie in the browser
        'Set-Cookie': `custom_auth=${cookie}; Path=/; HttpOnly`
      }
    });
  } catch (error) {
    console.error('Error fetching user info:', error);
  }
});

app.get('/auth/google', (c: Context) => {
  const authorizationUrl = new URL(
    'https://accounts.google.com/o/oauth2/v2/auth'
  );
  // Get the Google Client ID from the env
  authorizationUrl.searchParams.set('client_id', c.env.GOOGLE_CLIENT_ID);
  // Add your own callback URL
  authorizationUrl.searchParams.set('redirect_uri', c.env.GOOGLE_CALLBACK_URL);

  authorizationUrl.searchParams.set('prompt', 'consent');
  authorizationUrl.searchParams.set('response_type', 'code');
  authorizationUrl.searchParams.set('scope', 'openid email profile');
  authorizationUrl.searchParams.set('access_type', 'offline');
  // Redirect the user to Google Login
  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizationUrl.toString()
    }
  });
});
app.get(
  '/',
  serveStatic({
    root: './',
    rewriteRequestPath: path => path.replace(/^\/\w+/g, '/index.html')
  })
);

app.get(
  '/login',
  serveStatic({ root: './', rewriteRequestPath: path => '/login.html' })
);

app.get('/user', async (c: Context) => {
  // Get the cookie header in Hono
  const cookieHeader = c.req.raw.headers.get('Cookie');
  // Parse the custom_auth cookie to get the user auth values (if logged in)
  const cookie: any = parseCookie(cookieHeader, 'custom_auth');
  if (cookie) {
    const { payload }: { header: any; payload: any } = decodeJWT(cookie);
    // Just for demonstration purposes
    if (payload) {
      return c.json(payload);
    }
  }

  return c.json({});
});

app.get('/logout', async (c: Context) => {
  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': 'custom_auth=; Path=/; HttpOnly; Max-Age=0'
    }
  });
});

app.get('/test', async (c: Context) => {});
export default app;
