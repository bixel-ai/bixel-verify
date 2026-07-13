# bixel-verify

Independent verifier for [Bixel](https://bixel.com)'s evidence chain. Given a
fact's proof bundle and the raw captured bytes, `bixel-verify` checks the
whole chain of custody with standard cryptography, offline, with zero
requests to bixel.com. You should not have to trust Bixel to check Bixel.

> **Status: pre-release.** The verifier ships alongside Bixel's per-fact
> proof endpoint. This repository is its permanent home; the specification
> below is the contract the tool is being built against, published first so
> it can be reviewed before code exists to defend it.

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
  every later link.
- **OpenTimestamps proofs anchored in the Bitcoin blockchain.** Each meta's
  hash is committed through the OpenTimestamps calendar network into a
  Bitcoin block. Proof-of-work makes the commitment practically impossible
  to backdate or rewrite. (No cryptocurrency is held or traded; Bitcoin is
  used as a public notary only.)

## What a verification run checks

Input: a proof bundle (from Bixel's per-fact proof endpoint) and the raw bytes.

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
