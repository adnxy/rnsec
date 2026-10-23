/**
 * Parse JSON with comments and trailing commas (JSONC). Comment markers inside
 * string literals (e.g. glob patterns such as "src/**\/*.ts") are preserved.
 */
export function stripJsonComments(input: string): string {
  let out = '';
  let i = 0;
  let inString = false;

  while (i < input.length) {
    const ch = input[i];
    const next = input[i + 1];

    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += next ?? '';
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i++;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      i++;
    } else if (ch === '/' && next === '/') {
      while (i < input.length && input[i] !== '\n') i++;
    } else if (ch === '/' && next === '*') {
      i += 2;
      while (i < input.length && !(input[i] === '*' && input[i + 1] === '/')) i++;
      i += 2;
    } else {
      out += ch;
      i++;
    }
  }

  return removeTrailingCommas(out);
}

function removeTrailingCommas(input: string): string {
  let out = '';
  let inString = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += input[++i] ?? '';
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === ',') {
      let j = i + 1;
      while (j < input.length && /\s/.test(input[j])) j++;
      if (input[j] === '}' || input[j] === ']') continue;
    }
    out += ch;
  }

  return out;
}

export function parseJsonc<T = unknown>(input: string): T {
  return JSON.parse(stripJsonComments(input)) as T;
}
