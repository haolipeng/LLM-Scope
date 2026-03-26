// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

/** @type {import('next').NextConfig} */
const nextConfig = {
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:7395/api/:path*',
      },
    ];
  },
}

module.exports = nextConfig
