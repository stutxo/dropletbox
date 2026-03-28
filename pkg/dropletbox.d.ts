/* tslint:disable */
/* eslint-disable */

export class DropletboxApp {
    free(): void;
    [Symbol.dispose](): void;
    clearUpload(): any;
    create_invoice(request: any): Promise<any>;
    currentSwap(): any;
    currentUpload(): any;
    currentUploadPreview(): any;
    exportSnapshot(): any;
    static fromSnapshot(snapshot: any): DropletboxApp;
    constructor();
    poll_once(): Promise<any>;
    quoteInvoice(request: any): Promise<any>;
    retryPendingSwap(): Promise<any>;
    setUpload(request: any): any;
    wallet(): any;
}

export function decodeRevealPayload(tx_hex: string): any;

export function start(): void;

export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_dropletboxapp_free: (a: number, b: number) => void;
    readonly decodeRevealPayload: (a: number, b: number, c: number) => void;
    readonly dropletboxapp_clearUpload: (a: number, b: number) => void;
    readonly dropletboxapp_create_invoice: (a: number, b: number) => number;
    readonly dropletboxapp_currentSwap: (a: number, b: number) => void;
    readonly dropletboxapp_currentUpload: (a: number, b: number) => void;
    readonly dropletboxapp_currentUploadPreview: (a: number, b: number) => void;
    readonly dropletboxapp_exportSnapshot: (a: number, b: number) => void;
    readonly dropletboxapp_fromSnapshot: (a: number, b: number) => void;
    readonly dropletboxapp_new: (a: number) => void;
    readonly dropletboxapp_poll_once: (a: number) => number;
    readonly dropletboxapp_quoteInvoice: (a: number, b: number) => number;
    readonly dropletboxapp_retryPendingSwap: (a: number) => number;
    readonly dropletboxapp_setUpload: (a: number, b: number, c: number) => void;
    readonly dropletboxapp_wallet: (a: number, b: number) => void;
    readonly start: () => void;
    readonly version: (a: number) => void;
    readonly rustsecp256k1zkp_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1zkp_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_12_context_create: (a: number) => number;
    readonly rustsecp256k1_v0_12_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_12_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_12_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly __wasm_bindgen_func_elem_3996: (a: number, b: number, c: number, d: number) => void;
    readonly __wasm_bindgen_func_elem_3998: (a: number, b: number, c: number, d: number) => void;
    readonly __wasm_bindgen_func_elem_1921: (a: number, b: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export5: (a: number, b: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
