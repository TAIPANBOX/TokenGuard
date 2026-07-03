export declare const VERSION: string;
export declare const DEFAULT_GATEWAY: string;

/** Base URL to hand to a provider client's `baseURL`. */
export declare function gatewayUrl(gateway?: string): string;

/** Full URL of the Anthropic-style messages endpoint. */
export declare function messagesUrl(gateway?: string): string;

export interface RunHeaderOptions {
  budgetUsd?: number;
  taskType?: string;
  parentRunId?: string;
  tags?: Record<string, string>;
}

/**
 * Build the `X-Fuse-*` attribution headers for a run. Only `runId` is required;
 * without it the gateway treats a call as an unmanaged pass-through.
 */
export declare function runHeaders(
  runId: string,
  opts?: RunHeaderOptions,
): Record<string, string>;
