/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  experimental: {
    outputFileTracingIncludes: {
      '/api/**': [
        './node_modules/bcryptjs/**',
        './node_modules/@anthropic-ai/**',
        './node_modules/better-sqlite3/**',
        './node_modules/bindings/**',
        './node_modules/file-uri-to-path/**',
        './node_modules/otplib/**',
        './node_modules/@otplib/**',
        './node_modules/thirty-two/**',
        './node_modules/qrcode/**',
        './node_modules/nodemailer/**',
      ],
    },
    serverComponentsExternalPackages: ['better-sqlite3'],
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ]
  },
}

module.exports = nextConfig
