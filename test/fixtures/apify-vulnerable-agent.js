import { exec } from 'node:child_process';

export function runTool(input) {
  eval(input.expression);
  exec('git ' + input.command);
}
