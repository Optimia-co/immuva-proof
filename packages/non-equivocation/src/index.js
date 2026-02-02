"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeCanonicalEvents = normalizeCanonicalEvents;
exports.isNonEquivocating = isNonEquivocating;
const index_js_1 = require("../../canonical/dist/index.js");
function normalizeCanonicalEvents(canonical_events) {
    if (!canonical_events || canonical_events.length === 0)
        return [];
    const normalized = [];
    for (const s of canonical_events) {
        try {
            const obj = JSON.parse(s);
            normalized.push((0, index_js_1.canonicalizeJson)(obj).canonical);
        }
        catch {
            return null;
        }
    }
    return normalized;
}
function isNonEquivocating(normalized) {
    const uniq = new Set(normalized);
    return uniq.size <= 1;
}
