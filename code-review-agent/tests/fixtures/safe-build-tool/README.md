# Build Runner

A JavaScript build tool that compiles and bundles project assets. Runs predefined build steps like TypeScript compilation, CSS processing, and asset copying.

## Usage

```bash
node builder.js build
node builder.js clean
node builder.js watch
```

## Build Steps

1. Clean dist/ directory
2. Compile TypeScript
3. Process CSS with PostCSS
4. Copy static assets
5. Generate source maps
