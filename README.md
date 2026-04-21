# SBOM License Policy with Conforma

This repository tells the story of writing a [Conforma](https://github.com/conforma/cli) policy
rule that verifies SBOM license compliance. The git history is intentionally structured to show how
the policy evolves over time. Start from the first commit and walk forward. Each commit message
explains the motivation behind the change.

## Prerequisites

- [Conforma CLI](https://github.com/conforma/cli) (`ec`) installed
- [cosign](https://github.com/sigstore/cosign) installed (for downloading SBOMs)

## Usage

All commands should be run from the root of this repository. The examples below use this image:

```bash
IMAGE='registry.access.redhat.com/hi/nodejs@sha256:800a2372b211b98caa6b390b40224854022c8a29c8e81ffc2a090c2e4156d852'
```

### Validate a local SBOM

Download an SBOM for the image:

```bash
cosign download sbom $IMAGE > sbom.json
```

Run the policy against the local SBOM file (any SPDX 2.3 SBOM will work):

```bash
ec validate input --file sbom.json --policy policy.yaml
```

### Validate an image directly

The same policy can also be run directly against an image:

```bash
ec validate image --policy policy.yaml \
  --public-key 'https://security.access.redhat.com/data/63405576.txt' \
  --ignore-rekor \
  --image $IMAGE
```

If using a different `$IMAGE`, update `--public-key` accordingly.

Support for `ec validate input` is introduced first in the git history. `ec validate image` is added
later as an additive change, resulting in a single policy rule that works with either command.
