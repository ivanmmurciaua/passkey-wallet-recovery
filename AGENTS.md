# Guide for AI coding agents

This repository is a proof of concept for **recoverable passkey smart wallets**: a Safe whose signer is a WebAuthn passkey (P-256), and a recovery module that rotates a lost passkey to a new one without the old device, keeping the same address and funds. See [README.md](README.md) for the design, what is proven and the roadmap (F1 to F5).

It is unaudited and testnet-only. Never point it at mainnet or real funds.

<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes: APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

## Before writing code

- **Safe SDK versions matter.** protocol-kit 8 and relay-kit 6 differ from older docs and examples (for instance, a passkey's `verifierAddress` is mandatory and is a full uint176). Check the installed package sources in `node_modules/@safe-global/` instead of assuming.
- **Read before claiming.** Verify behaviour against the code, the installed packages or the chain. Do not state that something works until it has been checked.

## Rules

1. **One source of truth.** Every version, address, RPC URL and network lives in `src/app/constants.ts`. Never hardcode any of them elsewhere (app, scripts, Hardhat config, tests). Add a new network or contract there first.
2. **Fail loudly.** After changing constants, run `npm run check:constants`. It compares them with the official Safe registries, checks code on-chain and exercises the P256VERIFY precompile. A check that cannot run must report the failure, never a silent pass.
3. **Secrets stay local.** `.env.local` holds API keys and, optionally, a deployer key. It is git-ignored; never print, copy or commit its values. `.env.local.example` documents the variables with placeholders only.
4. **Verify with a production build.** Use `npm run build && npm run start`, not the dev server, before reporting a change as working.
5. **Testnet only.** Ethereum Sepolia, as listed in `constants.ts`.
6. **Writing style.** Code, comments and docs in English. Do not use the em-dash character; use a comma, a colon or parentheses. No absolute local paths in committed files.
7. **Git.** Do not commit, push, create branches or open pull requests unless the maintainer asks for it explicitly. Propose a commit message instead.

## Checks before handing over

```bash
npx tsc --noEmit -p tsconfig.json          # app
npx tsc --noEmit -p tsconfig.hardhat.json  # scripts + Hardhat config
npx eslint src scripts
npx hardhat compile
npm run check:constants
npm run build
```

The end-to-end flow (steps 1 to 6 in the page) needs a real passkey and a browser, so it is run by a person. When something fails on-chain, prefer reproducing it with `eth_call` or a state override over guessing.
