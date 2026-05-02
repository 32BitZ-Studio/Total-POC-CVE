/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    localPatterns: [
      {
        pathname: '/allowed/**',
      },
    ],
  },
  async rewrites() {
    return [
      {
        source: '/allowed/:path*',
        destination: 'http://127.0.0.1:4300/private/:path*',
      },
    ]
  },
}

module.exports = nextConfig
