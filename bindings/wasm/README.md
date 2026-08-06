# crabs-wasm

WebAssembly bindings for the [CRABS](https://github.com/vijayee/CRABS) cryptographic attribute-based state machine library.

Runs in **any environment with a WASM runtime**: browsers, Node.js, Deno, Bun, Cloudflare Workers, Vercel Edge Functions, and standalone runtimes (Wasmtime, WasmEdge).

## Installation

```bash
npm install crabs-wasm
```

That's it — the pre-built `crabs.wasm` (1.7MB) ships with the package. No compilation needed. The same binary works in every environment.

### Rebuilding from source (optional)

If you need to rebuild the WASM module from source:

```bash
# Prerequisites: Emscripten SDK, OpenSSL source, openabe-to-c project
cd bindings/wasm
npm run build   # runs ../../build_wasm.sh
```

## Quick Start

```javascript
const { Node, KeyPair } = require('crabs-wasm');

async function main() {
  // Create a CRABS node (async — loads the WASM module)
  const node = await Node.create('admin', { ordering: 'hlc' });

  // Generate a user keypair
  const aliceKey = await KeyPair.generate();
  console.log('Alice public key:', aliceKey.publicKeyHex());

  // Register the user
  await node.registerUser('alice', aliceKey.publicKeyHex(), 'role:member');

  // Get the node's signing key
  const nodeKey = node.getNodeKey();
  console.log('Node public key:', nodeKey.publicKeyHex);

  node.destroy();
}

main();
```

## Architecture

This package wraps the CRABS C library compiled to WebAssembly via Emscripten:

```
crabs.wasm (1.7MB)  ←  CRABS + OpenABE + RELIC + OpenSSL (all compiled to WASM)
crabs.js   (77KB)   ←  Emscripten JS glue (loads and interfaces with the .wasm)
index.js            ←  High-level JavaScript API (this package)
```

The `.wasm` binary is platform-agnostic — the same file runs everywhere.

## API

The API mirrors `crabs-node` (the N-API bindings). See `../node/index.d.ts` for the full type definitions. Key classes:

- **`Node`** — CRABS node (attribute machine + state + ABE master key)
- **`KeyPair`** — ECDSA secp256k1 keypair
- **`Operation`** — A signed state-machine operation

## Differences from crabs-node

| | crabs-node (N-API) | crabs-wasm (this package) |
|---|---|---|
| Runtime | Node.js only | Any WASM runtime (browser, Node, edge, etc.) |
| Loading | Synchronous (`require`) | Async (WASM module load) |
| Performance | Native speed | ~2-5x slower (WASM overhead) |
| ABE keygen | ~2-5 seconds | ~5-15 seconds |
| Binary size | Links against system libs | 1.7MB self-contained `.wasm` |

## License

MIT