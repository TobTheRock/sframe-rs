// A wasm worker can't boot with zero JS: Trunk emits the worker's wasm-bindgen
// glue as a classic (no-modules) script that only *defines* `wasm_bindgen`.
// This bootstrap loads it and calls the initializer, which runs the worker's
// `main` and registers the `onrtctransform` handler.
importScripts("./worker.js");
wasm_bindgen("./worker_bg.wasm");
