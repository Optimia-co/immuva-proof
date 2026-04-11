import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeOperationError } from "n8n-workflow";
import { prove, verify, proveSession } from "@immuva/sdk";

export class ImmuvaProof implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Immuva Proof",
    name: "immuvaProof",
    icon: "file:immuva.svg",
    group: ["transform"],
    version: 1,
    subtitle: '={{$parameter["operation"]}}',
    description: "Generate and verify cryptographic proofs for AI agent actions",
    defaults: { name: "Immuva Proof" },
    inputs: ["main"],
    outputs: ["main"],
    credentials: [
      {
        name: "immuvaApi",
        required: true,
      },
    ],
    properties: [
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        options: [
          {
            name: "Prove",
            value: "prove",
            description: "Generate a ProofBundle for an agent action",
            action: "Generate a proof bundle for an agent action",
          },
          {
            name: "Verify",
            value: "verify",
            description: "Verify an existing ProofBundle",
            action: "Verify an existing proof bundle",
          },
          {
            name: "Prove Session",
            value: "proveSession",
            description: "Generate a SessionBundle for multiple events",
            action: "Generate a session bundle for multiple events",
          },
        ],
        default: "prove",
      },
      // === PROVE ===
      {
        displayName: "Agent ID",
        name: "agentId",
        type: "string",
        default: "",
        required: true,
        displayOptions: { show: { operation: ["prove"] } },
        description: "Unique identifier for the agent performing the action",
      },
      {
        displayName: "Event Kind",
        name: "eventKind",
        type: "string",
        default: "AGENT_ACTION",
        displayOptions: { show: { operation: ["prove"] } },
        description: "Type of event being proved (e.g. PAYMENT_DECISION, TOOL_CALL)",
      },
      {
        displayName: "Decision",
        name: "decision",
        type: "string",
        default: "approve",
        displayOptions: { show: { operation: ["prove"] } },
        description: "The decision taken by the agent",
      },
      {
        displayName: "Extra Fields (JSON)",
        name: "extraFields",
        type: "json",
        default: "{}",
        displayOptions: { show: { operation: ["prove"] } },
        description: "Additional fields to include in the event (as JSON object)",
      },
      // === VERIFY ===
      {
        displayName: "Proof Bundle (JSON)",
        name: "proofBundle",
        type: "json",
        default: "{}",
        required: true,
        displayOptions: { show: { operation: ["verify"] } },
        description: "The ProofBundle JSON to verify",
      },
      // === PROVE SESSION ===
      {
        displayName: "Events (JSON Array)",
        name: "events",
        type: "json",
        default: "[]",
        required: true,
        displayOptions: { show: { operation: ["proveSession"] } },
        description: "Array of session events: [{ event, outcome?, evidence? }]",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const credentials = await this.getCredentials("immuvaApi");
    const publicKeyHex  = credentials.publicKeyHex as string;
    const privateKeyHex = credentials.privateKeyHex as string;

    const results: INodeExecutionData[] = [];

    for (let i = 0; i < items.length; i++) {
      const operation = this.getNodeParameter("operation", i) as string;

      try {
        if (operation === "prove") {
          const agentId   = this.getNodeParameter("agentId", i) as string;
          const kind      = this.getNodeParameter("eventKind", i) as string;
          const decision  = this.getNodeParameter("decision", i) as string;
          const extra     = JSON.parse(this.getNodeParameter("extraFields", i) as string ?? "{}");

          const proof = await prove({
            event: { kind, agent_id: agentId, decision, ...extra },
            public_key_hex: publicKeyHex,
            private_key_hex: privateKeyHex,
          });

          results.push({ json: proof as any });

        } else if (operation === "verify") {
          const bundleStr = this.getNodeParameter("proofBundle", i) as string;
          const bundle    = JSON.parse(bundleStr);
          const result    = await verify(bundle);
          results.push({ json: result as any });

        } else if (operation === "proveSession") {
          const eventsStr = this.getNodeParameter("events", i) as string;
          const events    = JSON.parse(eventsStr);
          const session   = await proveSession(events, publicKeyHex, privateKeyHex);
          results.push({ json: session as any });

        } else {
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
        }
      } catch (error) {
        if (this.continueOnFail()) {
          results.push({ json: { error: (error as Error).message } });
        } else {
          throw error;
        }
      }
    }

    return [results];
  }
}
