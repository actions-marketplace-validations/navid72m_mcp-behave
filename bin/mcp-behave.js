#!/usr/bin/env node

const { spawn, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const PKG_NAME = 'mcp-behave';
const args = process.argv.slice(2);

function commandExists(cmd) {
  try {
    const res = spawnSync(cmd, ['--version'], { stdio: 'ignore' });
    return res.status === 0;
  } catch {
    return false;
  }
}

function findPython() {
  for (const cmd of ['python3', 'python']) {
    try {
      const res = spawnSync(cmd, ['--version'], { stdio: 'ignore' });
      if (res.status === 0) return cmd;
    } catch {}
  }
  return null;
}

function runCommand(command, cmdArgs) {
  const child = spawn(command, cmdArgs, {
    stdio: 'inherit',
    env: process.env,
  });

  child.on('error', (err) => {
    console.error(`[mcp-behave] Failed to start '${command}':`, err.message);
    process.exit(1);
  });

  child.on('close', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 0);
    }
  });

  process.on('SIGINT', () => child.kill('SIGINT'));
  process.on('SIGTERM', () => child.kill('SIGTERM'));
}

function main() {
  // 1. Prefer uvx if available (fastest, isolated)
  if (commandExists('uvx')) {
    return runCommand('uvx', [PKG_NAME, ...args]);
  }

  // 2. Try pipx if available
  if (commandExists('pipx')) {
    return runCommand('pipx', ['run', PKG_NAME, ...args]);
  }

  // 3. Fallback to python3 / python
  const pythonCmd = findPython();
  if (!pythonCmd) {
    console.error('[mcp-behave] Error: Python 3 is required to run mcp-behave.');
    console.error('Please install Python 3 (https://www.python.org) or uv (https://astral.sh/uv).');
    process.exit(1);
  }

  // Check if mcp_behave is already installed in the active Python environment
  const importCheck = spawnSync(pythonCmd, ['-c', 'import mcp_behave'], { stdio: 'ignore' });
  if (importCheck.status === 0) {
    return runCommand(pythonCmd, ['-m', 'mcp_behave.cli', ...args]);
  }

  // If not installed, use an isolated cache venv so we don't mutate system packages
  const cacheBase = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  const venvDir = path.join(cacheBase, 'mcp-behave', 'npm-venv');
  const venvBin = process.platform === 'win32'
    ? path.join(venvDir, 'Scripts', 'mcp-behave.exe')
    : path.join(venvDir, 'bin', 'mcp-behave');

  if (!fs.existsSync(venvBin)) {
    console.error('[mcp-behave] First-time setup: preparing environment in ~/.cache/mcp-behave/npm-venv...');
    fs.mkdirSync(path.dirname(venvDir), { recursive: true });

    const venvCreate = spawnSync(pythonCmd, ['-m', 'venv', venvDir], { stdio: 'inherit' });
    if (venvCreate.status !== 0) {
      console.error('[mcp-behave] Warning: could not create venv, falling back to direct run.');
      return runCommand(pythonCmd, ['-m', 'mcp_behave.cli', ...args]);
    }

    const pipBin = process.platform === 'win32'
      ? path.join(venvDir, 'Scripts', 'pip.exe')
      : path.join(venvDir, 'bin', 'pip');

    const pipInstall = spawnSync(pipBin, ['install', '--upgrade', PKG_NAME], { stdio: 'inherit' });
    if (pipInstall.status !== 0) {
      console.error('[mcp-behave] Error: failed to install mcp-behave.');
      process.exit(1);
    }
  }

  return runCommand(venvBin, args);
}

main();
