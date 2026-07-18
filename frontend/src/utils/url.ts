export function isSafeUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function safeHref(url: string | null | undefined): string | undefined {
  return isSafeUrl(url) ? url! : undefined;
}

/** Accept a backend-provided route only when it remains on this origin. */
export function safeInternalHref(url: string | null | undefined): string | undefined {
  const value = url?.trim();
  if (!value || !value.startsWith('/') || value.startsWith('//')) return undefined;
  try {
    const base = new URL('https://adversarygraph.invalid');
    const parsed = new URL(value, base);
    if (parsed.origin !== base.origin) return undefined;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return undefined;
  }
}
