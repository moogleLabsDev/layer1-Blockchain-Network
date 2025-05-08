# Layer1 Blockchain

A custom Layer 1 blockchain implementation designed to explore and demonstrate the fundamental components of a decentralized ledger system. This project includes core features such as peer-to-peer networking, consensus, block validation, and transaction execution.

## 🚀 Overview

This project serves as an educational and experimental base for understanding how a blockchain network functions at the protocol level. It is not based on any existing blockchain framework like Ethereum or Bitcoin but is built from scratch to illustrate key concepts.

## 🧱 Features

- Custom consensus mechanism (e.g., QBFT, PoA, or your own)
- Peer-to-peer (P2P) networking layer
- Transaction pool and validation
- Block creation and validation
- Persistent state storage (LevelDB or RocksDB)
- Genesis block configuration
- Basic CLI node management

## ⚙️ Architecture

The blockchain includes the following core components:

- **Node Layer** – Handles networking and peer discovery.
- **Consensus Layer** – Implements the consensus algorithm.
- **Ledger Layer** – Manages blocks and transactions.
- **Storage Layer** – Stores blockchain data and state.
- **RPC/CLI Interface** – For interacting with the node.

## 📦 Folder Structure

```bash
.
├── cmd/                    # CLI or node startup code
├── core/                   # Core blockchain logic
│   ├── block/              # Block structure and validation
│   ├── consensus/          # Consensus algorithm implementation
│   ├── p2p/                # Networking layer
│   └── storage/            # Persistent data storage
├── scripts/                # Setup, test, and utility scripts
├── genesis.json            # Genesis configuration
└── README.md               # This file
