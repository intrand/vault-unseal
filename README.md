## :grey_question: Why

Depending on your use-case for Vault, you may or may not have opted for Vault
Enterprise. If you have not, auto-unseal functionality for on-prem is currently
only in enterprise (for cloud, it is now in the OSS version). If what you are
storing in vault isn't sensitive enough to require human intervention, you may
want to roll your own unseal functionality. The problem with this is it is very
hard to do safely.

So, what do we need to solve? we want to auto-unseal a vault, by providing the
necessary unseal tokens when we find vault is sealed. We also want to make sure
we're sending notifications when this happens, so if vault was unsealed
unintentionally (not patching, upgrades, etc), possibly related to crashing or
malicious intent, a human can investigate at a later time (**not** 3am in the
morning).

## :heavy_check_mark: Solution

The goal for this project is to find the best way to unseal vault in a way that
doesn't compromise too much security (a good balance between security and ease of
use/uptime), without the requirement of Vault Enterprise, or having to move to a
cloud platform.

We do this by running multiple instances of vault-unseal (you could run one
on each node in the cluster). Each instance of vault-unseal is given a subset
of the unseal tokens. You want to give each node **just enough** tokens, that
when paired with another vault-unseal node, they can work together to unseal the
vault. What we want to avoid is giving a single vault-unseal instance enough
tokens to unseal (to prevent a compromise leading to enough tokens being exposed
that could unseal the vault). Let's use the following example:

![vault-unseal example diagram](https://cdn.liam.sh/share/2022/08/I8Qc1RCBMd.png)

Explained further:

- `cluster-1` consists of 3 nodes:
  - `node-1`
  - `node-2`
  - `node-3`
- `cluster-1` is configured with 5 unseal tokens (tokens `A`, `B`, `C`, `D`, `E`), but
     only 3 are required to unseal a given vault node.
- given there are 3 nodes, 3 tokens being required:
  - vault-unseal on `node-1` gets tokens `A` and `B`.
  - vault-unseal on `node-2` gets tokens `B` and `C`.
  - vault-unseal on `node-3` gets tokens `A` and `C`.

With the above configuration:

- Given each vault-unseal node, each node has two tokens.
- Given the tokens provided to vault-unseal, each token (`A`, `B`, and `C`), there
   are two instances of that token across nodes in the cluster.
- If `node-1` is completely hard-offline, nodes `node-2` and `node-3` should have
   all three tokens, so if the other two nodes reboot, as long as vault-unseal starts
   up on those nodes, vault-unseal will be able to unseal both.
- If `node-2` becomes compromised, and the tokens are read from the config
   file, this will not be enough tokens to unseal the vault.
- vault-unseal runs as root, with root permissions.

## :computer: Installation

Check out the [releases](https://github.com/lrstanley/vault-unseal/releases)
page for prebuilt versions.


## :balance_scale: License

```
MIT License

Copyright (c) 2018 Liam Stanley <me@liamstanley.io>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

_Also located [here](LICENSE)_
