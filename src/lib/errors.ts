export class CommandError extends Error {
  constructor(
    public category: string,
    message: string,
  ) {
    super(message);
    this.name = 'CommandError';
  }
}

export function normalizeError(error: unknown): CommandError {
  if (error instanceof CommandError) return error;
  if (error && typeof error === 'object' && 'category' in error && 'message' in error) {
    return new CommandError(String(error.category), String(error.message));
  }
  const message = error instanceof Error ? error.message : String(error);
  const prefix = message.toLowerCase();
  const category = prefix.includes('io error')
    ? 'io'
    : prefix.includes('pe file error')
      ? 'pe'
      : prefix.includes('certificate') || prefix.includes('password')
        ? 'certificate'
        : prefix.includes('timestamp') || prefix.includes('http')
          ? 'timestamp'
          : prefix.includes('tsa') || prefix.includes('server')
            ? 'tsa'
            : prefix.includes('signing')
              ? 'signing'
              : 'unknown';
  return new CommandError(category, message);
}

export function errorKey(error: unknown): string {
  const category = normalizeError(error).category;
  const keys: Record<string, string> = {
    io: 'ioError',
    pe: 'peError',
    certificate: 'certError',
    signing: 'signingError',
    timestamp: 'timestampError',
    tsa: 'tsaError',
    unavailable: 'unavailableError',
  };
  return `wb.${keys[category] ?? 'unknownError'}`;
}
