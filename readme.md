# 🌍 **Interplanetary Network (IPN) -- Milestone 1** 👽

[![made-with-javascript](https://img.shields.io/badge/Made%20with-JavaScript-1f425f.svg)](https://www.javascript.com)
[![GitHub branches](https://badgen.net/github/branches/Naereen/Strapdown.js)](https://github.com/fluffelpuff/ipncore/)
[![GitHub commits](https://badgen.net/github/commits/Naereen/Strapdown.js)](https://github.com/fluffelpuff/ipncore/commit/)
[![GitHub forks](https://img.shields.io/github/forks/Naereen/StrapDown.js.svg?style=social&label=Fork&maxAge=2592000)](https://github.com/fluffelpuff/ipncore/network/)

[![GitHub license](https://badgen.net/github/license/Naereen/Strapdown.js)](https://github.com/Naereen/StrapDown.js/blob/master/LICENSE)
[![Twitter](https://badgen.net/badge/icon/twitter?icon=twitter&label)](https://twitter.com/fluffelpuffcode)



Select language: EN | [DE](./README_eu_DE.md)

The Interplanetray Network is an open-source, decentralized P2P network that aims to enable a simple connection between 2 or more devices. It doesn't matter whether the device is in Tor, in i2p or in the "normal" Internet. Anyone can create an ed25519 ([EdDSA](https://en.wikipedia.org/wiki/EdDSA) / [curve25519](https://en.wikipedia.org/wiki/Curve25519)) key and use the public key as an address within the IPN to establish a P2P connection. If a direct connection at the IP level is possible, the IPN core software automatically connects to the opposite peer.


## 👍 **The following functions are supported:**
- [Decentralized routing protocol (Artemis Protocol | INIP0001)](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0001_de.mediawiki)
- [Bootnode support and hardcoded swarm nodes to initialize the network (INIP0003)](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0003_de.mediawiki)


## 🌍 **Supported network protocols:**
- [Websocket (WS/WSS) (INIP0002)](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0002_de.mediawiki)


## 🔐 **Support cryptographic methods:**
- [ED25519 / Curve25519 (INIP0004)](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0004_de.mediawiki)
- [Chacha20-Poly1305 (INIP0004)](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0004_de.mediawiki)


## 🚀🍾 **Communities:** 
* [Interplanetary Network (IPN) Twitter](https://twitter.com/fluffelpuffcode)


## 📚 **Available libraries / API's:**
| Language                                                      | State               | Improvement Proposal                                                                              | Full Library |
| ---                                                           | ---                 | ---                                                                                               | ---          |
| [NodeJs / Javascript](https://github.com/fluffelpuff/ipncore) | 👩‍💻 In progress      |     [INIP0016](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0016_de.mediawiki)     |     ✅ Yes    |
| C / C++                                                       | 🚫 Work not started |     [INIP0016](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0016_de.mediawiki)     |     ❌ No     |
| [Python](https://github.com/fluffelpuff/ipnpylib)             | 👩‍💻 In progress      |     [INIP0016](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0016_de.mediawiki)     |     ❌ No     |
| Rust                                                          | 🚫 Work not started |     [INIP0016](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0016_de.mediawiki)     |     ❌ No     |
| C#                                                            | 🚫 Work not started |     [INIP0016](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0016_de.mediawiki)     |     ❌ No     |


## 💲 **Support me:**
- **BTC**: bc1pt4jfvgsylagskgcex9rwefufhzsv2qanwk9f77ullaft0hd4jy0s4870jh
- **ETH**: 0xF0b7D4B2c21F4FE3645dBB312B8C2e08220B7f0d


## ✅ **To do list:**
- [ ] Power Routing over Distributed hash table DHT
- [ ] Commandline Console for IPN-Core Service
- [ ] [DNS Node seeding (INIP0003)](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0003_de.mediawiki)
- [ ] [DDoS Protection (INIP0013)](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0013_de.mediawiki)
- [ ] [Crypto algorithms (INIP0004):](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0004_de.mediawiki)
  - [X] [ED25519 / Curve25519 (Sodium)](https://github.com/paixaop/node-sodium#readme)
  - [ ] [FROST-Ed25519](https://docs.rs/frost-dalek/latest/frost_dalek/)
  - [ ] [AES256-Bit](https://github.com/brix/crypto-js)
- [ ] Network protocols:
  - [x] [Websocket](https://en.wikipedia.org/wiki/WebSocket) | [INIP0002](https://github.com/fluffelpuff/ipncore/blob/main/inips/inip_0002_de.mediawiki)
  - [ ] [QUIC](https://en.wikipedia.org/wiki/QUIC)
  - [ ] [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
  - [ ] [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
  - [ ] [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)
  - [ ] [TOR](https://en.wikipedia.org/wiki/Tor_(network))
  - [ ] [i2p](https://en.wikipedia.org/wiki/I2P)


## ⚖️ **License - Much license:**
IPN Core is released under the terms of the MIT license. See
[COPYING](COPYING) for more information or see
[opensource.org](https://opensource.org/licenses/MIT)