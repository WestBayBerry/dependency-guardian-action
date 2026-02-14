/**
 * Logger abstraction to decouple the detection engine from @actions/core.
 * The GitHub Action sets this to use core.info/warning/debug.
 * The API server uses the default console-based implementation.
 */
export interface Logger {
  info(message: string): void;
  warning(message: string): void;
  debug(message: string): void;
}

const consoleLogger: Logger = {
  info: (msg) => console.log(`[INFO] ${msg}`),
  warning: (msg) => console.warn(`[WARN] ${msg}`),
  debug: (msg) => {
    if (process.env.DEBUG) console.log(`[DEBUG] ${msg}`);
  },
};

let _logger: Logger = consoleLogger;

export function setLogger(logger: Logger): void {
  _logger = logger;
}

export function getLogger(): Logger {
  return _logger;
}

export const logger = new Proxy({} as Logger, {
  get(_, prop: string) {
    return (_logger as unknown as Record<string, unknown>)[prop];
  },
});
