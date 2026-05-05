import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
    server: {
        host: "::",
        port: 5173,
    },
    plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
    resolve: {
        alias: {
            "@": path.resolve(__dirname, "./src"),
        },
    },
    build: {
        rollupOptions: {
            output: {
                manualChunks: {
                    // React and core dependencies
                    'react-vendor': ['react', 'react-dom', 'react-router-dom'],

                    // UI library dependencies
                    'ui-vendor': [
                        '@radix-ui/react-dialog',
                        '@radix-ui/react-dropdown-menu',
                        '@radix-ui/react-select',
                        '@radix-ui/react-toast',
                        '@radix-ui/react-tooltip',
                        '@radix-ui/react-collapsible',
                        '@radix-ui/react-navigation-menu',
                        '@radix-ui/react-tabs',
                        '@radix-ui/react-accordion',
                        '@radix-ui/react-alert-dialog',
                        '@radix-ui/react-popover',
                        '@radix-ui/react-progress',
                        '@radix-ui/react-slider',
                        '@radix-ui/react-switch',
                        '@radix-ui/react-checkbox',
                        '@radix-ui/react-label',
                        '@radix-ui/react-scroll-area',
                        '@radix-ui/react-separator',
                        '@radix-ui/react-slot',
                        'lucide-react',
                        'class-variance-authority',
                        'clsx',
                        'tailwind-merge'
                    ],

                    // Data fetching and state management
                    'data-vendor': [
                        '@tanstack/react-query'
                    ],

                    // Form handling
                    'form-vendor': [
                        'react-hook-form',
                        '@hookform/resolvers',
                        'zod'
                    ],

                    // Utility libraries
                    'utils-vendor': [
                        'date-fns',
                        'sonner'
                    ],

                    // Chart and visualization (if used)
                    'chart-vendor': [
                        'recharts'
                    ]
                },
                // Optimize chunk file names
                chunkFileNames: (chunkInfo) => {
                    const facadeModuleId = chunkInfo.facadeModuleId
                        ? chunkInfo.facadeModuleId.split('/').pop()?.replace('.tsx', '').replace('.ts', '')
                        : 'chunk';
                    return `assets/${facadeModuleId}-[hash].js`;
                },
                assetFileNames: (assetInfo) => {
                    const info = assetInfo.name?.split('.') ?? [];
                    const extType = info[info.length - 1];
                    if (/\.(png|jpe?g|svg|gif|tiff|bmp|ico)$/i.test(assetInfo.name ?? '')) {
                        return `assets/images/[name]-[hash][extname]`;
                    }
                    if (/\.(woff2?|eot|ttf|otf)$/i.test(assetInfo.name ?? '')) {
                        return `assets/fonts/[name]-[hash][extname]`;
                    }
                    return `assets/${extType}/[name]-[hash][extname]`;
                }
            }
        },
        // Optimize chunk size
        chunkSizeWarningLimit: 600,
        // Enable source maps for better debugging
        sourcemap: mode === 'development',
        // Optimize CSS
        cssCodeSplit: true,
        // Minify options
        minify: 'esbuild',
        // Target modern browsers
        target: 'esnext',
        // Enable compression
        reportCompressedSize: true
    },
    // Optimize dependencies
    optimizeDeps: {
        include: [
            'react',
            'react-dom',
            'react-router-dom',
            '@tanstack/react-query',
            'lucide-react'
        ]
    }
}));
