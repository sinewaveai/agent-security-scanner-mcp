const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const DIST = path.join(__dirname, 'dist');

const BUILD_STEPS = [
  { name: 'typescript', cmd: 'npx', args: ['tsc', '--outDir', DIST] },
  { name: 'css', cmd: 'npx', args: ['postcss', 'src/styles/*.css', '--dir', path.join(DIST, 'css')] },
  { name: 'assets', cmd: 'cp', args: ['-r', 'public/', path.join(DIST, 'public')] },
];

function clean() {
  if (fs.existsSync(DIST)) {
    fs.rmSync(DIST, { recursive: true });
    console.log('Cleaned dist/');
  }
}

async function runStep(step) {
  return new Promise((resolve, reject) => {
    console.log(`Running: ${step.name}`);
    execFile(step.cmd, step.args, { cwd: __dirname }, (error, stdout, stderr) => {
      if (error) {
        console.error(`${step.name} failed:`, stderr);
        reject(error);
        return;
      }
      console.log(`${step.name} done:`, stdout.trim());
      resolve(stdout);
    });
  });
}

async function build() {
  fs.mkdirSync(DIST, { recursive: true });
  for (const step of BUILD_STEPS) {
    await runStep(step);
  }
  console.log('Build complete!');
}

const command = process.argv[2] || 'build';
if (command === 'clean') {
  clean();
} else if (command === 'build') {
  clean();
  build().catch((err) => {
    console.error('Build failed:', err.message);
    process.exit(1);
  });
}
