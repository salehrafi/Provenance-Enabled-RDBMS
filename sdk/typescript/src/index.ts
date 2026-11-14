// Provenance Cloud client for Node 20+ and browsers. Zero dependencies; uses fetch and Web Crypto.
// Retries network errors, 429 (honouring Retry-After) and 502/503/504 with exponential backoff. Event
// ingestion is idempotent on (source, id), so a retry that already succeeded is harmless.

export interface CloudEvent {
  id: string;
  source: string;
  type: string;
  data: Record<string, unknown>;
  subject?: string;
  time?: Date | string;
  [extension: string]: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly body: Record<string, unknown>;
  constructor(status: number, body: Record<string, unknown>) {
    super(`${status} ${body.code ?? ""}: ${body.detail ?? ""}`);
    this.status = status;
    this.body = body;
    this.code = body.code as string | undefined;
    this.requestId = body.request_id as string | undefined;
  }
}

const iso = (t?: Date | string): string => (typeof t === "string" ? t : (t ?? new Date()).toISOString());
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface ClientOptions {
  maxRetries?: number;
  fetch?: typeof fetch;
}

export class Client {
  private base: string;
  private apiKey: string;
  private opts: ClientOptions;

  constructor(baseUrl: string, apiKey: string, opts: ClientOptions = {}) {
    this.base = baseUrl.replace(/\/$/, "") + "/api/v1";
    this.apiKey = apiKey;
    this.opts = opts;
  }

  private async request<T>(method: string, path: string, body?: unknown, params?: Record<string, string | number | undefined>): Promise<T> {
    const retries = this.opts.maxRetries ?? 4;
    const doFetch = this.opts.fetch ?? fetch;
    const entries = Object.entries(params ?? {}).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)] as [string, string]);
    const query = entries.length ? "?" + new URLSearchParams(entries).toString() : "";
    let delay = 500;
    for (let attempt = 0; ; attempt++) {
      try {
        const r = await doFetch(this.base + path + query, {
          method,
          headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        if (r.ok) return (r.status === 204 ? undefined : await r.json()) as T;
        if (![429, 502, 503, 504].includes(r.status) || attempt >= retries) {
          throw new ApiError(r.status, await r.json().catch(() => ({ detail: r.statusText })));
        }
        delay = Math.max(delay, Number(r.headers.get("retry-after") ?? 0) * 1000);
      } catch (e) {
        if (e instanceof ApiError || attempt >= retries) throw e;
      }
      await sleep(Math.min(delay, 30_000));
      delay *= 2;
    }
  }

  /** Send one event. `duplicate` is true when this exact event id was already recorded. */
  sendEvent(e: CloudEvent): Promise<Record<string, unknown> & { duplicate: boolean }> {
    return this.request("POST", "/events", { specversion: "1.0", ...e, time: iso(e.time) });
  }

  sendEvents(events: CloudEvent[]) {
    return this.request<{ created: number; duplicates: number; failed: number; results: Record<string, unknown>[] }>(
      "POST", "/events:batch", events.map((e) => ({ specversion: "1.0", ...e, time: iso(e.time) })));
  }

  async *iterEvents(filter: { source?: string; type?: string; subject?: string } = {}, pageSize = 100): AsyncGenerator<Record<string, unknown>> {
    let cursor: number | undefined;
    for (;;) {
      const page = await this.request<{ items: Record<string, unknown>[]; next_cursor: number | null }>(
        "GET", "/ingested-events", undefined, { ...filter, cursor, limit: pageSize });
      yield* page.items;
      if (!page.next_cursor) return;
      cursor = page.next_cursor;
    }
  }

  reconcile(r: { source: string; entity: string; records: { external_id: string; fields: Record<string, unknown> }[]; complete?: boolean; as_of?: Date | string }) {
    return this.request<Record<string, unknown>>("POST", "/reconciliations", { ...r, as_of: r.as_of ? iso(r.as_of) : undefined });
  }

  verifyAudit(checkpoints: unknown[] = []) {
    return this.request<{ ok: boolean; reason?: string; checked: number }>("POST", "/audit/verify", { checkpoints });
  }

  checkpoints(limit = 100) {
    return this.request<{ items: unknown[] }>("GET", "/audit/checkpoints", undefined, { limit });
  }

  async history(entity: string, pk: string) {
    return (await this.request<{ history: unknown[] }>("GET", `/provenance/${entity}/${pk}/history`)).history;
  }

  asOf(entity: string, pk: string, at: Date | string) {
    return this.request<Record<string, unknown>>("GET", `/provenance/${entity}/${pk}/as-of`, undefined, { at: iso(at) });
  }
}

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Verify a Standard Webhooks delivery; throws on failure. Deduplicate on the `webhook-id` header. */
export async function verifyWebhook(secret: string, headers: Record<string, string>, body: string, toleranceSeconds = 300): Promise<void> {
  const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const id = h["webhook-id"];
  const ts = h["webhook-timestamp"];
  const sigs = h["webhook-signature"];
  if (!id || !ts || !sigs || !Number.isFinite(Number(ts))) throw new Error("missing or malformed webhook headers");
  if (Math.abs(Date.now() / 1000 - Number(ts)) > toleranceSeconds) throw new Error("timestamp outside the tolerance window");
  const key = await crypto.subtle.importKey("raw", unb64(secret.replace(/^whsec_/, "")), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = b64(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${id}.${ts}.${body}`))));
  const ok = sigs.split(" ").some((c) => {
    const [v, s] = c.split(",");
    return v === "v1" && s === expected;
  });
  if (!ok) throw new Error("signature mismatch");
}
