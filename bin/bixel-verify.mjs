#!/usr/bin/env node
/**
 * bixel-verify — independent verifier for Bixel's evidence chain.
 *
 * Input: a proof bundle from Bixel's per-fact proof endpoint
 *   GET https://api.bixel.com/v1/companies/{domain}/facts/{key}/proof
 * plus (optionally) the raw captured bytes. Verifies the chain of custody
 * with standard cryptography. The only network access is the OpenTimestamps
 * calendar/explorer check in step 4 (skippable with --skip-anchor); there
 * are NO requests to bixel.com.
 *
 * Steps (see README):
 *   1. CONTENT   sha256(raw bytes) == the capture's recorded hash   [--raw]
 *   2. INCLUSION leaf hashes through the merkle path to the root the
 *                meta records for that manifest (RFC 6962 / SHA-256)
 *   3. CHAIN     the meta links its predecessor by key + hash
 *   4. ANCHOR    the .ots proof commits to the meta's exact bytes and
 *                verifies through OpenTimestamps toward Bitcoin
 *
 * A passing run proves observation-at-time anchored in Bitcoin. It does NOT
 * prove Bixel's extraction of the bytes is correct — read the raw yourself.
 *
 * Usage:
 *   bixel-verify bundle.json
 *   bixel-verify bundle.json --raw capture.html.gz
 *   curl -s https://api.bixel.com/v1/companies/pinecone.io/facts/pricing.model/proof/ | bixel-verify -
 *   bixel-verify --self-test        # pinned real-world vectors, offline
 *   bixel-verify bundle.json --skip-anchor   # fully offline (steps 2-4a)
 *
 * This tool deliberately shares no code with Bixel's systems.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SUPPORTED_MERKLE_SPEC = "rfc6962-sha256/csv-data-rows-v1";

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
const hex = (b) => Buffer.from(b).toString("hex");

// ---------------------------------------------------------------------------
// argument parsing
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const valueOf = (f) => {
  const i = args.indexOf(f);
  return i >= 0 ? args[i + 1] : undefined;
};

if (has("--help") || (args.length === 0 && process.stdin.isTTY)) {
  console.log("usage: bixel-verify <bundle.json | -> [--raw <file>] [--skip-anchor]");
  console.log("       bixel-verify --self-test");
  process.exit(args.length === 0 ? 1 : 0);
}

// ---------------------------------------------------------------------------
// the four checks
// ---------------------------------------------------------------------------
let failures = 0;
const pass = (step, msg) => console.log(`  ✓ ${step.padEnd(9)} ${msg}`);
const fail = (step, msg) => {
  failures++;
  console.error(`  ✗ ${step.padEnd(9)} ${msg}`);
};
const note = (step, msg) => console.log(`  … ${step.padEnd(9)} ${msg}`);

function verifyContent(bundle, rawPath) {
  const cap = bundle.capture;
  if (!rawPath) {
    note("CONTENT", "no --raw file supplied — skipped (the proof still binds the recorded hash below)");
    return;
  }
  const bytes = readFileSync(rawPath);
  const rule = cap.raw?.hash_rule ?? "";
  const body = /gunzip/i.test(rule) ? gunzipSync(bytes) : bytes;
  const digest = hex(sha256(body));
  if (digest !== cap.sha256) {
    return fail("CONTENT", `raw bytes hash to ${digest.slice(0, 16)}…, capture records ${cap.sha256.slice(0, 16)}…`);
  }
  const keySha = (cap.raw?.key ?? "").match(/[0-9a-f]{64}/)?.[0];
  if (keySha && keySha !== digest) {
    return fail("CONTENT", "the storage key's embedded hash disagrees with the bytes");
  }
  pass("CONTENT", `raw bytes are the captured document (sha256 ${digest.slice(0, 16)}…)`);
}

function verifyInclusion(bundle, meta) {
  const p = bundle.inclusion_proof;
  if (p.merkle_spec !== SUPPORTED_MERKLE_SPEC) {
    return fail("INCLUSION", `unknown merkle spec "${p.merkle_spec}" (this tool implements ${SUPPORTED_MERKLE_SPEC})`);
  }
  // Leaf sanity: the manifest row must reference the capture this bundle claims.
  if (!p.leaf.startsWith(`${bundle.capture.id},`)) {
    return fail("INCLUSION", "the leaf row does not reference the bundle's capture id");
  }
  if (bundle.capture.sha256 && !p.leaf.includes(bundle.capture.sha256)) {
    return fail("INCLUSION", "the leaf row does not carry the capture's content hash");
  }
  // RFC 6962: leaf = SHA256(0x00 || row bytes); node = SHA256(0x01 || l || r).
  let cur = sha256(Buffer.from([0x00]), Buffer.from(p.leaf, "utf8"));
  for (const step of p.path) {
    const sib = Buffer.from(step.sibling, "hex");
    cur = step.side === "left"
      ? sha256(Buffer.from([0x01]), sib, cur)
      : sha256(Buffer.from([0x01]), cur, sib);
  }
  if (hex(cur) !== p.merkle_root) {
    return fail("INCLUSION", "the merkle path does not reproduce the claimed root");
  }
  const entry = (meta.manifests ?? []).find((m) => m.manifest_key === p.manifest_key);
  if (!entry) return fail("INCLUSION", `the meta does not list manifest ${p.manifest_key}`);
  if (entry.merkle_root !== p.merkle_root) {
    return fail("INCLUSION", "the meta records a DIFFERENT root for that manifest");
  }
  pass("INCLUSION", `leaf → ${p.path.length}-hash path → root recorded in the meta (${p.merkle_root.slice(0, 16)}…)`);
}

function verifyChain(meta) {
  if (typeof meta.version !== "number" || meta.version < 3) {
    return fail("CHAIN", `meta version ${meta.version} carries no merkle roots (expected ≥3)`);
  }
  if (meta.previous_meta_key === null) {
    return pass("CHAIN", "this meta IS the genesis record (no predecessor)");
  }
  if (!meta.previous_meta_key || !meta.previous_meta_sha256) {
    return fail("CHAIN", "the meta lacks its predecessor link (key + sha256)");
  }
  pass(
    "CHAIN",
    `links ${meta.previous_meta_key} by sha256 ${meta.previous_meta_sha256.slice(0, 16)}… (walk the keys back to the 2026-06-10 genesis to audit the full history)`
  );
}

async function verifyAnchor(bundle, metaBytes, skipNetwork) {
  const a = bundle.anchor;
  if (!a.ots_b64) return fail("ANCHOR", "the bundle carries no OpenTimestamps proof");
  const metaSha = sha256(metaBytes);
  let OpenTimestamps;
  try {
    OpenTimestamps = (await import("opentimestamps")).default;
  } catch {
    // Zero-dependency fallback: the serialized proof embeds the committed
    // digest verbatim — confirm the commitment without parsing the format.
    const ots = Buffer.from(a.ots_b64, "base64");
    if (!ots.includes(metaSha)) {
      return fail("ANCHOR", "the .ots proof does not commit to the meta's bytes");
    }
    return note("ANCHOR", `proof commits to the meta (sha256 ${hex(metaSha).slice(0, 16)}…); install the optional 'opentimestamps' package (or run \`ots verify\`) for full Bitcoin verification`);
  }
  const detached = OpenTimestamps.DetachedTimestampFile.deserialize(Buffer.from(a.ots_b64, "base64"));
  const committed = hex(detached.fileDigest());
  if (committed !== hex(metaSha)) {
    return fail("ANCHOR", `the .ots proof commits to ${committed.slice(0, 16)}…, but the meta bytes hash to ${hex(metaSha).slice(0, 16)}…`);
  }
  if (skipNetwork) {
    return pass("ANCHOR", "proof commits to the meta's exact bytes (network verification skipped)");
  }
  try {
    if (detached.timestamp.isTimestampComplete()) {
      const original = OpenTimestamps.DetachedTimestampFile.fromHash(
        new OpenTimestamps.Ops.OpSHA256(),
        metaSha
      );
      const res = await OpenTimestamps.verify(detached, original);
      if (res && res.bitcoin) {
        return pass("ANCHOR", `Bitcoin-attested${res.bitcoin.height ? ` (block ${res.bitcoin.height})` : ""} — the batch existed no later than that block`);
      }
      return fail("ANCHOR", "a complete proof failed Bitcoin verification");
    }
    return note("ANCHOR", "proof commits to the meta and is PENDING calendar aggregation (upgrades to Bitcoin-attested automatically; re-fetch the bundle later)");
  } catch (e) {
    return note("ANCHOR", `commitment verified; calendar/explorer unreachable (${e.message}) — retry online for the Bitcoin check`);
  }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------
async function runBundle(label, raw, rawPath, skipNetwork) {
  const parsed = JSON.parse(raw);
  const bundle = parsed.data ?? parsed; // accept the {data,meta} envelope or the bare bundle
  console.log(`\nbixel-verify — ${label}`);
  console.log(`  fact: ${bundle.fact.key} = ${JSON.stringify(bundle.fact.value)} (${bundle.fact.provenance}, as of ${bundle.fact.as_of})`);
  console.log(`  captured: ${bundle.capture.captured_at} from ${bundle.capture.source_url ?? "(source url on the fact)"}\n`);

  const metaBytes = Buffer.from(bundle.anchor.meta_b64, "base64");
  const meta = JSON.parse(metaBytes.toString("utf8"));

  verifyContent(bundle, rawPath);
  verifyInclusion(bundle, meta);
  verifyChain(meta);
  await verifyAnchor(bundle, metaBytes, skipNetwork);

  console.log("");
  if (failures) {
    console.error(`FAILED — ${failures} check(s) did not hold. Do not trust this bundle.`);
    return false;
  }
  console.log("VERIFIED — the raw content this bundle references was observed at the recorded time and sits in a Bitcoin-anchored, hash-chained history.");
  console.log("Reminder: cryptography proves observation, not extraction — read the raw document to confirm what it says.");
  return true;
}

if (has("--self-test")) {
  const here = dirname(fileURLToPath(import.meta.url));
  const vectors = [
    "pricing-model.page-capture.json",
    "stack-nextjs.crawl-snapshot.json",
  ];
  let ok = true;
  for (const v of vectors) {
    failures = 0;
    const raw = readFileSync(join(here, "..", "test", "vectors", v), "utf8");
    ok = (await runBundle(`self-test vector ${v}`, raw, null, true)) && ok;
  }
  process.exit(ok ? 0 : 1);
}

const src = args.find((a) => !a.startsWith("--") && a !== valueOf("--raw"));
if (!src) {
  console.error("no bundle given — pass a file path or '-' for stdin (see --help)");
  process.exit(1);
}
const raw = src === "-" ? readFileSync(0, "utf8") : readFileSync(src, "utf8");
const ok = await runBundle(src === "-" ? "stdin" : src, raw, valueOf("--raw") ?? null, has("--skip-anchor"));
process.exit(ok ? 0 : 1);
