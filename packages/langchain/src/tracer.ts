import { BaseTracer, type Run } from "@langchain/core/tracers/base";
import { prove } from "@immuva/sdk";

export interface ImmuvaTracerInput {
  agent_id: string;
  public_key_hex: string;
  private_key_hex: string;
  onProof?: (proof: Record<string, unknown>) => void | Promise<void>;
}

/**
 * LangChain tracer that records every Run completion as an Immuva ProofBundle.
 * Useful for full tracing pipelines where you want end-to-end auditability.
 */
export class ImmuvaTracer extends BaseTracer {
  readonly name = "ImmuvaTracer";

  private readonly agentId: string;
  private readonly publicKeyHex: string;
  private readonly privateKeyHex: string;
  private readonly onProof?: (proof: Record<string, unknown>) => void | Promise<void>;

  constructor(input: ImmuvaTracerInput) {
    super();
    this.agentId       = input.agent_id;
    this.publicKeyHex  = input.public_key_hex;
    this.privateKeyHex = input.private_key_hex;
    this.onProof       = input.onProof;
  }

  protected async persistRun(run: Run): Promise<void> {
    if (run.end_time == null) return;

    try {
      const proof = await prove({
        event: {
          kind: `LANGCHAIN_${run.run_type.toUpperCase()}_RUN`,
          agent_id: this.agentId,
          run_id: run.id,
          run_type: run.run_type,
          name: run.name,
          decision: run.error ? "error" : "complete",
          latency_ms: run.end_time - run.start_time,
        },
        public_key_hex: this.publicKeyHex,
        private_key_hex: this.privateKeyHex,
      });
      await this.onProof?.(proof);
    } catch {
      // Non-blocking
    }
  }
}
