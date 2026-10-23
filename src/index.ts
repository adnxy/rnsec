#!/usr/bin/env node

// cli-spinners (via ora) imports JSON with import attributes, which prints an
// ExperimentalWarning on Node < 22.12. Drop exactly that warning, keep the rest.
const emitWarning = process.emitWarning;
process.emitWarning = ((warning: string | Error, ...args: unknown[]) => {
  const message = typeof warning === 'string' ? warning : warning?.message;
  if (message?.includes('Importing JSON modules is an experimental feature')) return;
  return (emitWarning as (...a: unknown[]) => void).call(process, warning, ...args);
}) as typeof process.emitWarning;

// Dynamic import so the filter is installed before the CLI's dependencies load
import('./cli/index.js').catch(error => {
  console.error(error);
  process.exit(1);
});
