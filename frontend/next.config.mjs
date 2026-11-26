import { createRequire } from 'module';
import path from 'path';

// v1.6.4.8: expose the real package version to the client so it can never be
// hand-typed stale again (TopNav/CommandBar/JSON-LD previously hardcoded
// "v1.6.2" in five separate places). createRequire (not the `with { type:
// "json" }` import-attribute syntax) so this works regardless of the Node
// version running next build in any given environment.
const require = createRequire(import.meta.url);
const pkg = require('./package.json');

// Proxy target for the backend API. In production this MUST be provided
// explicitly (or the app will talk to its own origin and rely on an external
// reverse proxy). There is deliberately no hard-coded fallback to a hosted
// backend: shipping one meant every copy of the dashboard silently sent its
// API traffic (and keys) to a third-party origin.
const BACKEND_URL =
  process.env.BACKEND_URL || 'http://localhost:8000';

/** @type {import('next').NextConfig} */
const nextConfig = {
  allowedDevOrigins: ['*.trycloudflare.com'],
  env: {
    NEXT_PUBLIC_AEGIS_VERSION: pkg.version,
  },
  turbopack: {
    root: path.resolve('.'),
  },
  // Baseline browser hardening. The FastAPI middleware sets these on API
  // responses, but the HTML everybody actually loads is served by Next, and
  // next dev / next start do not add any of them on their own — so the
  // dashboard was framing-enabled and had no nosniff/referrer policy.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          {
            key: 'Permissions-Policy',
            value: 'geolocation=(), microphone=(), camera=(), payment=()',
          },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains',
          },
        ],
      },
    ];
  },
  async rewrites() {
    if (!BACKEND_URL) {
      return [];
    }
    return [
      {
        source: '/api/v1/:path*',
        destination: `${BACKEND_URL}/api/v1/:path*`,
      },
      {
        source: '/docs',
        destination: `${BACKEND_URL}/docs`,
      },
      {
        source: '/openapi.json',
        destination: `${BACKEND_URL}/openapi.json`,
      },
      {
        source: '/ws',
        destination: `${BACKEND_URL}/ws`,
      },
    ];
  },
};

export default nextConfig;
