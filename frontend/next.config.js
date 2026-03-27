// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

/** @type {import('next').NextConfig} */
const nextConfig = {
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

// Static export mode: NEXT_EXPORT=1 npm run build
// Produces frontend/out/ with pure static files for Go server embedding.
if (process.env.NEXT_EXPORT === '1') {
  nextConfig.output = 'export'
} else {
  // Dev mode: proxy API requests to Go backend
  nextConfig.rewrites = async () => [
    {
      source: '/api/:path*',
      destination: 'http://localhost:7395/api/:path*',
    },
  ]
}

module.exports = nextConfig
