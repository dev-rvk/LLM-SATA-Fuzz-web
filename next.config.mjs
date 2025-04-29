/** @type {import('next').NextConfig} */

const nextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  webpack: (config, { isServer }) => {
    // Add loaders for XML, TXT files
    config.module.rules.push({
      test: /\.(xml|txt)$/,
      use: 'raw-loader',
      exclude: /node_modules/,
    });
    config.module.rules.push({
      test: /output\/llm\/generated_artifacts\/.+\.js$/,
      use: 'raw-loader',
      type: 'javascript/auto'
    });

    return config;
  },
}

export default nextConfig