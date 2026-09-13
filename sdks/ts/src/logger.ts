/** Minimal pluggable logger. Swap `logger.sink` to route or silence SDK logs. */
export interface LogSink {
  info(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
}

export const logger: { sink: LogSink } = {
  sink: {
    info: (msg, ...a) => console.info(`[trust-infra] ${msg}`, ...a),
    warn: (msg, ...a) => console.warn(`[trust-infra] ${msg}`, ...a),
  },
};
