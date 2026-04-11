import { prove } from "@immuva/sdk";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ImmuvaOpenAIOptions {
  /** Your agent identifier */
  agent_id: string;
  /** Ed25519 public key (hex, 64 chars) */
  public_key_hex: string;
  /** Ed25519 private key (hex, 128 chars) */
  private_key_hex: string;
  /**
   * Called after each successful proof generation.
   * Non-blocking — errors are caught and logged silently.
   */
  onProof?: (result: { proof: unknown; response: unknown }) => void;
  /**
   * If true, errors during proof generation are thrown.
   * Default: false (silent — LLM call is never blocked by proof errors).
   */
  throwOnProofError?: boolean;
}

// ── Minimal types for OpenAI SDK compatibility ────────────────────────────────
// We use generic types so this package doesn't require openai as a hard dep at
// build time — only at runtime (peer dependency).

interface ChatCompletionCreateParamsBase {
  model: string;
  messages: Array<{ role: string; content: string | null }>;
  [key: string]: unknown;
}

interface ChatCompletion {
  id:      string;
  model:   string;
  object:  string;
  choices: Array<{
    index:         number;
    finish_reason: string | null;
    message:       { role: string; content: string | null };
  }>;
  usage?: {
    prompt_tokens:     number;
    completion_tokens: number;
    total_tokens:      number;
  };
  [key: string]: unknown;
}

// ── ImmuvaOpenAIWrapper ───────────────────────────────────────────────────────

/**
 * Wraps an OpenAI client to automatically generate a cryptographic Immuva proof
 * after each `chat.completions.create()` call.
 *
 * The proof is generated non-blocking — it never delays or blocks the LLM
 * response returned to the caller.
 *
 * @example
 * ```typescript
 * import OpenAI from 'openai'
 * import { ImmuvaOpenAIWrapper } from '@immuva/openai'
 *
 * const openai = new OpenAI()
 * const keys   = await keygen({ out: './my-agent' })
 *
 * const client = new ImmuvaOpenAIWrapper(openai, {
 *   agent_id:        'my-agent',
 *   public_key_hex:  keys.publicKeyHex,
 *   private_key_hex: keys.privateKeyHex,
 *   onProof: (r) => console.log('Proof generated:', r.proof),
 * })
 *
 * // Exact same API as the raw OpenAI client:
 * const response = await client.chat.completions.create({
 *   model:    'gpt-4o',
 *   messages: [{ role: 'user', content: 'Approve payment of €42?' }],
 * })
 * ```
 */
export class ImmuvaOpenAIWrapper {
  private readonly opts: ImmuvaOpenAIOptions;
  private readonly _client: unknown;

  constructor(openaiClient: unknown, opts: ImmuvaOpenAIOptions) {
    this._client = openaiClient;
    this.opts    = opts;
  }

  get chat() {
    return {
      completions: {
        create: async (
          params: ChatCompletionCreateParamsBase
        ): Promise<ChatCompletion> => {
          // Call the underlying OpenAI client
          const client = this._client as any;
          const response: ChatCompletion = await client.chat.completions.create(params);

          // Generate proof asynchronously — never blocks the response
          this._proveAsync(params, response);

          return response;
        },
      },
    };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private _proveAsync(
    params: ChatCompletionCreateParamsBase,
    response: ChatCompletion
  ): void {
    const choice       = response.choices[0];
    const finishReason = choice?.finish_reason ?? "unknown";

    prove({
      event: {
        // Privacy-first: never include message content in the proof event.
        // Only structural metadata is captured.
        kind:             "LLM_DECISION",
        model:            params.model,
        messages_count:   params.messages.length,
        response_id:      response.id,
        finish_reason:    finishReason,
        prompt_tokens:    response.usage?.prompt_tokens   ?? null,
        completion_tokens:response.usage?.completion_tokens ?? null,
      },
      agent_id:        this.opts.agent_id,
      public_key_hex:  this.opts.public_key_hex,
      private_key_hex: this.opts.private_key_hex,
      resultset_present: true,
      evidence: {
        effective: "LLM_RESPONSE",
        required:  "LLM_RESPONSE",
        qualified: finishReason === "stop",
      },
      outcome: {
        value: finishReason,
        basis: "LLM_RESPONSE",
      },
    })
      .then((result) => {
        this.opts.onProof?.({ proof: result, response });
      })
      .catch((err) => {
        if (this.opts.throwOnProofError) throw err;
        console.error("[immuva/openai] proof generation failed:", err?.message ?? err);
      });
  }
}
