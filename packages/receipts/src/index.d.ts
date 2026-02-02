import { StubReceipt } from "@immuva/protocol";
export declare function validateReceiptKindWhitelist(receipts: StubReceipt[]): boolean;
export declare function validateNoReceiptAfterNonClosable(receipts: StubReceipt[]): boolean;
export declare function hasNonClosableSignal(receipts: StubReceipt[]): boolean;
