export function extractSnippet(content: string, line: number, contextLines: number = 2): string {
  const lines = content.split('\n');
  const start = Math.max(0, line - contextLines - 1);
  const end = Math.min(lines.length, line + contextLines);
  return lines.slice(start, end).join('\n');
}

export function containsSensitiveKeyword(text: string): boolean {
  const keywords = ['token', 'password', 'auth', 'secret', 'api_key', 'apikey', 'credentials'];
  const lowerText = text.toLowerCase();
  return keywords.some(keyword => lowerText.includes(keyword));
}

export function looksLikeSecret(value: string): boolean {
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    return true;
  }
  
  if (/^AKIA[0-9A-Z]{16}$/.test(value)) {
    return true;
  }
  
  if (value.length > 30 && /^[A-Za-z0-9+/=_-]+$/.test(value)) {
    return true;
  }
  
  return false;
}

export function getLineNumber(content: string, position: number): number {
  const lines = content.substring(0, position).split('\n');
  return lines.length;
}

