"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateSignatureModelV1 = validateSignatureModelV1;
exports.validateKeyBinding = validateKeyBinding;
const index_js_1 = require("../../canonical/dist/index.js");
function validateSignatureModelV1(input) {
    if (!input.signing)
        return true;
    const canonical = input.canonical_event ?? "";
    const want = (0, index_js_1.sha256HexUtf8)(canonical);
    return input.signing.signature === want;
}
function validateKeyBinding(input) {
    if (!input.key_binding || !input.signing)
        return true;
    return input.key_binding.public_key === input.signing.public_key;
}
