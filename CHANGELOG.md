ChangeLog
=========

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com).

Type of changes

* Added: for new features.
* Changed: for changes in existing functionality.
* Deprecated: for soon-to-be removed features.
* Removed: for now removed features.
* Fixed: for any bug fixes.
* Security: in case of vulnerabilities.

This project adheres to [Semantic Versioning](http://semver.org).

Given a version number MAJOR.MINOR.PATCH
* MAJOR incremented for incompatible API changes
* MINOR incremented for new functionalities
* PATCH incremented for bug fixes

Additional labels for pre-release metadata:
* alpha.x: internal development stage.
* beta.x: shipped version under testing.
* rc.x: stable release candidate.


0.2.9 unreleased
----------------
...

0.2.8 05-07-2022
----------------
Changed
* Bulk transaction is paid by the signer

Fixed
* Block time fixed (before was always zero) ### Breaking Change
* Seed update at each block

0.2.7 24-05-2022
------------------
Changed
* BlockchainSettings structure
* Test/Production flag
* Improved `is_callable` host_function
* Improved `p2p` module, introduced reqres layer and reduced gossip messages
* Added message fields:
  * GetTransactionRequest: `destination: Option<String>`
  * GetTransactionResponse: `origin: Option<String>`
  * GetBlockRequest: `destination: Option<String>`
  * GetBlockResponse: `origin: Option<String>`

Added
* `secure_call` host function
* `remove_asset` host function
* `get_block_time` host function (returns the next block timestamp )
* Call to Service `contract_updatable`
* NFA Non-Fungible Account
* Added size limit on transaction that can be executed
* Fuel consumption
* is_callable direct wasm call
* Aligner module
* Message::Ack for reqres interaction

Removed
* Synchronizer removed, now replaced by aligner


0.2.6 - 08-02-2022
------------------
Changed
* Removed wasm loader from closure

0.2.5 - 02-02-2022
------------------

Added
* Drand implementation
* get_account_contract host function
* is_callable host function
* Offline mode for p2p module (prevent it from start)

0.2.4 - release skipped
------------------

Changed
* Transaction schema
* Signed blocks
* Introduction of fuel management structures

Added
* Bulk transaction
* Bootstrap from wasm or wasm+txs
* Config from bootstrap
* Network name from bootstrap hash



0.2.3 - 25-11-2021
------------------

Changed

* Upgrade to Rust 2021
* Bump "wasmtime" from v0.30 to v0.31.

Added

* Added smartcontract events to tx receipt
* Added smartcontracts events subscription
* Added sha256 host function
* Added TPM2 signature
* Added Node Monitor support


0.2.2 - 05-11-2021
------------------

Changed

* User can choose p2p listening port. Previously the port was forced to random.
* Always generate random ed25519 p2p keypair.

Added

* ECDSA digital signature backend can now optionally exploit TPM v2 hardware.


0.2.1 - 04-11-2021
------------------

Added

* Support for ECDSA secp256r1 curve for transaction digital signature.
* Kademlia peer discovery mechanism.

Changed

* Exonum merkledb project has been forked to replace the original version.
  The new merkledb is a more lightweight, flexible and portable (see fixed issue
  below)
* Bump "wasmtime" from v0.29 to v0.30.

Fixed

* Binary portability issues due to an issue in exonum-merkledb dependencies.
  In particular the project was forcing max optimizations to libsodium build.
  This was causing the inclusion of non-portable cpu instructions within the
  binary.


0.2.0 - 30-09-2021
------------------

Added

* Ed25519 keypair support. Nodes now are capable to use the same key for both
  transaction submission and p2p communication.
* AGPL v3 LICENSE file.


0.1.6 - 20-09-2021
------------------

Fixed

* Account assets order shall be deterministic for a deterministic global state
  hash. Replaced the assets `HashMap` with a `BTreeMap`.


0.1.5 - 03-09-2021
------------------

Added

* Blockchain bridge service. A convenient asynchronous tcp/ip interface to
  send/receive any type of blockchain message.
  This service allows the user to "hot-plug" new specialized blockchain
  services: for example a performance tracer or an account status indexer.

Changed

* Stabilized message pack data serialization to anonymous format.
  The map keys are dropped during serialization.


0.1.4 - 21-08-2021
------------------

Added

* Nodes reliable synchronization. The procedure is "lazy" and generally
  triggered when a node sees a block that doesn't have yet. An exception is
  performed at boot time, in this case the node asks in the wild for the last
  available block.
* Defined a message format for blockchain interactions from external components.
  The messages allows both solicited (direct requests) and unsolicited (internal
  events pubsub) exchange of blockchain data structures such as transactions,
  receipts, blocks and accounts.
* New "verify" WM host function available for smart contracts development.
  The function allows to verify ecdsa-p384 digital signatures without adding
  any additional crate dependency to the contract sources.

Changed

* Bump "wasmtime" from v0.28 to v0.29.


0.1.3 - 30-07-2021
------------------

Added

* Subscription to blockchain events using a pub/sub architecture.
  Events are sent to subscribers using internal channels.
* CLI application is now capable to submit a transactions batch specified within
  a configuration file. This feature allows to easily set up a node that is
  still in the "bootstrap" phase by using a set of well known transactions.
* CLI arbitrary transaction building capability.
* CLI now can be configured to use: http, stdio, or file channels.

Changed

* Removed all but one transactions submission from node boot sequence. The
  blockchain node now boots in vanilla state. The node wasm loader is set to
  the "bootstrap-loader" until the node has not produced the genesis block.


0.1.2 - 15-06-2021
------------------

Added

* Digital signature verification for transactions without explicitly named
  fields (i.e. message pack compact representation).
* Internal pub/sub mechanism to internally propagate blockchain events.
* Forward transactions using p2p service via internal pub/sub mechanism.
* Using "libp2p" v0.39 as the p2p service backend.

Changed

* Fully asynchronous architecture.
* Node loads contract from the blockchain. Filesystem registry is now only used
  to optionally register new contracts during startup using transactions targeting
  the service contract.
* WmLocal machine loads wasm binaries using a user callback provided at
  initialization time. Previous implementation was loading the contracts
  code from the filesystem.
* WM and DB are now strictly owned by the blockchain service. REST service
  submits requests to the blockchain service via message passing using
  asynchronous channels.
* Switching from "rocket" to "tide" HTTP server. Reasons: async-std, less
  dependencies and stable Rust channel.
* Switching the CLI http client from "reqwest" to "ureq".


0.1.1 - 28-06-2021
------------------

Added

* Smart contracts composability: capability to invoke smart contract methods
  from other smart contract methods.
* Definition of TRINCI Assets Interface (TAI) with locking capability.
* Basic asset smart contract using TAI interface.
* Flexible asset types controlled entirely from the smart contract.
* Time oracle smart contract.
* Service smart contract to manage global blockchain data.
* Default smart contract modified to allow arbitrary user data management.

Changed

* Use multihash format to keep a door open to future algorithms upgrades.
* Default hash algorithm set to Sha256.
* Default `Hash` set to zero length `Identity`.
* Bump "wasmtime" from v0.27 to v0.28.


0.1.0 - 22-05-2021
------------------

Added

* Implementation of core types: transaction, receipt, block, account.
* Unconfirmed transactions queue and block service for new blocks generation.
* Persistence of core structure using "rocksdb" with "exonum-merkledb" v1.0.0.
* REST web service for new transactions submission and read access to core
  structures using "rocket" v0.4.10.
* Sandboxed execution of arbitrary smart contracts using "wasmtime" v0.27.0.
* Project-specific error type with capability to propagate subsystems errors.
* Support for ecdsa secp384r1 digital signature using "ring" v0.16.20.
* Account id generation as a function of ecdsa public key.
* Rust smart contracts sdk for third-party developers.
