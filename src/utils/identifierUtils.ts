/**
 * Split an identifier into lowercase word tokens: `userAuthToken` / `USER_AUTH_TOKEN` /
 * `user-auth-token` -> ['user', 'auth', 'token']; `parseJWTToken` -> ['parse', 'jwt', 'token'].
 */
export function identifierTokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(t => t.toLowerCase());
}

/**
 * True when the identifier contains one of `terms` as a whole word (or a two/three-word
 * compound such as `apikey` matching `api` + `Key`). `bypass` does not match `pass`;
 * `userTokens` matches `token`.
 */
export function identifierHasTerm(name: string, terms: ReadonlySet<string>): boolean {
  const tokens = identifierTokens(name);
  for (let i = 0; i < tokens.length; i++) {
    let joined = '';
    for (let j = i; j < Math.min(tokens.length, i + 3); j++) {
      joined += tokens[j];
      if (terms.has(joined) || (joined.endsWith('s') && terms.has(joined.slice(0, -1)))) return true;
    }
  }
  return false;
}

/**
 * True when the identifier *ends* with one of `terms` (its head word): `userToken` and
 * `API_KEY` match `token` / `apikey`, `tokenCount` does not.
 */
export function identifierEndsWithTerm(name: string, terms: ReadonlySet<string>): boolean {
  const tokens = identifierTokens(name);
  for (let take = 1; take <= Math.min(3, tokens.length); take++) {
    const joined = tokens.slice(-take).join('');
    if (terms.has(joined) || (joined.endsWith('s') && terms.has(joined.slice(0, -1)))) return true;
  }
  return false;
}

/** Replace comment text with spaces (keeps offsets and line numbers stable). */
export function blankComments(source: string, ast: any): string {
  const comments: any[] = ast?.comments ?? [];
  if (comments.length === 0) return source;
  let out = '';
  let last = 0;
  for (const c of comments) {
    if (typeof c.start !== 'number' || typeof c.end !== 'number') continue;
    out += source.slice(last, c.start) + source.slice(c.start, c.end).replace(/[^\n]/g, ' ');
    last = c.end;
  }
  return out + source.slice(last);
}
