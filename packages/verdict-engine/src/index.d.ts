import { StubInput, ViolationCode, VerdictStatus } from "@immuva/protocol";
export declare function computeStatus(input: StubInput): {
    status: VerdictStatus;
    violations: ViolationCode[];
};
