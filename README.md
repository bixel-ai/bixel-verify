# bixel-verify

Independent verifier for [Bixel](https://bixel.com)'s evidence chain. Given a
fact's proof bundle and the raw captured bytes, `bixel-verify` checks the
whole chain of custody with standard cryptography, offline, with zero
requests to bixel.com. You should not have to trust Bixel to check Bixel.

> **Status: working.** The proof endpoint is live and this CLI verifies
> its bundles. Zero runtime dependencies for steps 1–3; step 4's full
> Bitcoin verification uses the standard `opentimestamps` package
> (optional — without it the tool still confirms the proof's commitment
> and tells you how to finish the check).

## Usage

```
# verify a bundle straight from the API
curl -s https://api.bixel.com/v1/companies/pinecone.io/facts/pricing.model/proof/ \
  | npx bixel-verify -

# with the raw captured bytes (completes step 1)
npx bixel-verify bundle.json --raw capture.html.gz

# fully offline (skips the OpenTimestamps network check)
npx bixel-verify bundle.json --skip-anchor

# pinned real-world vectors, offline
npx bixel-verify --self-test
```

Exit code 0 = every executed check held. The output labels each step and
ends with the exact claim the proof supports — nothing more.

## Getting a proof bundle

```
GET https://api.bixel.com/v1/companies/{domain}/facts/{key}/proof
```

Open tier, no key. Example:

```
curl https://api.bixel.com/v1/companies/pinecone.io/facts/pricing.model/proof/
```

The bundle carries the fact, its capture reference (content-addressed
SHA-256), the merkle inclusion path, and the anchoring meta record plus its
OpenTimestamps proof (both base64-embedded), so steps 2–4 below verify
offline from the bundle alone. Facts derived from live network signals with
no stored capture behind them answer `proof_not_available` instead of
pretending.

## What Bixel publishes

Bixel reads publicly accessible company web pages ([how and why](https://bixel.com/bot))
and derives structured, dated, provenance-tagged facts from the captured
HTML. The trust layer underneath:

- **Content-addressed raw captures.** Every captured page is stored under a
  key that IS its SHA-256. Identical content dedups; any object can be
  re-hashed and checked against its own name.
- **Hash-chained manifests.** Each export lists every capture (id, sha256,
  URL, timestamp) and writes a meta record carrying the manifest hashes plus
  the previous meta's key and hash. Rewriting any historical record breaks
  every later link. Each manifest entry also carries a merkle root over its
  rows (construction named in the meta; RFC 6962 with SHA-256), so proving
  one capture's inclusion takes a short hash path instead of the whole
  manifest. Two constructions exist:
  - `rfc6962-sha256/csv-data-rows-v1` (bundles before 2026-07-14): leaves
    are the manifest CSV's data rows in file order; path length ~log2(rows).
  - `rfc6962-sha256/csv-data-rows-v2` (current): the same tree, but the
    leaf set is padded with copies of the literal string `bixel:pad:v2`
    (never a data row — data rows contain commas) to the smallest power of
    two >= max(row count, 16384) before the tree is built. Every inclusion
    path is the same constant length, so a proof reveals nothing about
    corpus size. Path verification is identical for both constructions.
- **OpenTimestamps proofs anchored in the Bitcoin blockchain.** Each meta's
  hash is committed through the OpenTimestamps calendar network into a
  Bitcoin block. Proof-of-work makes the commitment practically impossible
  to backdate or rewrite. (No cryptocurrency is held or traded; Bitcoin is
  used as a public notary only.)

## What a verification run checks

Input: a proof bundle (from the endpoint above) and the raw bytes.

1. **Content.** SHA-256 of the raw bytes equals the capture's recorded
   hash. You now hold the exact document Bixel captured.
2. **Inclusion.** The capture's manifest row hashes through its merkle
   path to the root recorded in the meta. The capture is provably part of
   that batch.
3. **Chain.** The meta links to its predecessor by key and hash; the walk
   terminates at the genesis record. The batch sits in one append-only
   history.
4. **Anchor.** The meta's hash verifies through its OpenTimestamps proof
   to a Bitcoin block header. The batch, and therefore the exact bytes,
   existed no later than that block's time.

Every step is standard, independently reimplementable cryptography. This
tool deliberately shares no code with Bixel's private systems.

## What a proof does and does not attest

A passing verification proves: **these exact bytes were observed by Bixel
and committed to a Bitcoin-anchored, hash-chained record no later than a
specific block time.**

It does **not** prove that Bixel's structured extraction of those bytes is
correct. Facts are machine-derived readings of the captured page; the raw
bytes travel with the proof precisely so you can read the page yourself.
The cryptography establishes what existed and when; your own eyes establish
what it says. Claims beyond that boundary are overclaims, and this tool
will never make them.

## License

[Apache-2.0](LICENSE)
