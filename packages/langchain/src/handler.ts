import { BaseCallbackHandler } from "@langchain/core/callbacks/base";
import type { Serialized } from "@langchain/core/load/serializable";
import type { ChainValues } from "@langchain/core/utils/types";
import type { LLMResult } from "@langchain/core/outputs";
import { prove } from "@immuva/sdk";

export interface ImmuvaCallbackHandlerInput {
  /** Agent identifier recorded in every proof. */
  agent_id: string;
  /** Ed25519 public key hex (64 hex chars). */
  public_key_hex: string;
  /** Ed25519 private key hex (64 hex chars). */
  private_key_hex: string;
  /** Optional callback invoked for each generated proof. */
  onProof?: (record: ImmuvaProofRecord) => void | Promise<void>;
}

export interface ImmuvaProofRecord {
  kind: "llm" | "tool" | "chain";
  name: string;
  proof: Record<string, unknown>;
}

/**
 * LangChain callback handler that wraps LLM, tool, and chain outputs
 * in Immuva ProofBundles signed with Ed25519.
 *
 * @example
 * ```ts
 * import { ImmuvaCallbackHandler } from "@immuva/langchain";
 *
 * const handler = new ImmuvaCallbackHandler({
 *   agent_id: "my-agent",
 *   public_key_hex: process.env.IMMUVA_PUBLIC_KEY!,
 *   private_key_hex: process.env.IMMUVA_PRIVATE_KEY!,
 *   onProof: (r) => console.log(r.kind, r.proof),
 * });
 *
 * const chain = RunnableSequence.from([...]).withConfig({ callbacks: [handler] });
 * ```
 */
export class ImmuvaCallbackHandler extends BaseCallbackHandler {
  readonly name = "ImmuvaCallbackHandler";

  private readonly agentId: string;
  private readonly publicKeyHex: string;
  private readonly privateKeyHex: string;
  private readonly onProof?: (record: ImmuvaProofRecord) => void | Promise<void>;

  constructor(input: ImmuvaCallbackHandlerInput) {
    super();
    this.agentId      = input.agent_id;
    this.publicKeyHex = input.public_key_hex;
    this.privateKeyHex = input.private_key_hex;
    this.onProof      = input.onProof;
  }

  private async proveAndNotify(
    kind: ImmuvaProofRecord["kind"],
    name: string,
    decision: string,
    extra: Record<string, unknown> = {}
  ): Promise<void> {
    try {
      const proof = await prove({
        event: {
          kind: `LANGCHAIN_${kind.toUpperCase()}`,
          agent_id: this.agentId,
          name,
          decision,
          ...extra,
        },
        public_key_hex: this.publicKeyHex,
        private_key_hex: this.privateKeyHex,
      });
      await this.onProof?.({ kind, name, proof });
    } catch {
      // Non-blocking — never crash the LangChain chain
    }
  }

  override async handleLLMEnd(output: LLMResult, _runId: string, _parentRunId?: string, tags?: string[], metadata?: Record<string, unknown>, runName?: string): Promise<void> {
    const text = output.generations[0]?.[0]?.text ?? "";
    await this.proveAndNotify("llm", runName ?? "llm", "generate", {
      tokens: output.llmOutput?.tokenUsage ?? {},
      output_length: text.length,
    });
  }

  override async handleToolEnd(output: string, _runId: string, _parentRunId?: string, tags?: string[], metadata?: Record<string, unknown>, runName?: string): Promise<void> {
    await this.proveAndNotify("tool", runName ?? "tool", "execute", {
      output_length: output.length,
    });
  }

  override async handleChainEnd(outputs: ChainValues, _runId: string, _parentRunId?: string, tags?: string[], metadata?: Record<string, unknown>): Promise<void> {
    const outputKeys = Object.keys(outputs);
    await this.proveAndNotify("chain", "chain", "complete", {
      output_keys: outputKeys,
    });
  }

  override handleLLMStart(_llm: Serialized, _prompts: string[]): void {}
  override handleChainStart(_chain: Serialized, _inputs: ChainValues): void {}
  override handleToolStart(_tool: Serialized, _input: string): void {}
}
