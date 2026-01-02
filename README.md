# DooD CLI

**A secure, self-hostable, end-to-end encrypted messaging client**

DooD CLI is part of the larger **DooD Project** — an initiative to create a truly secure-by-design messaging platform that puts privacy and user control first. Unlike centralized messaging services, DooD is built from the ground up to be self-hosted, giving individuals and organizations complete control over their communication infrastructure.

---

## 🎯 Project Goals

The DooD Project aims to provide:

- **True End-to-End Encryption**: Messages are encrypted on your device and can only be decrypted by the intended recipient
- **Self-Hosting First**: Run your own server cluster without relying on third-party infrastructure
- **Privacy by Design**: No phone numbers, no email addresses, no metadata collection
- **Open Source**: Fully transparent implementation that anyone can audit and verify
- **Decentralization**: Anyone can host their own DooD server and create their own private network

---

## ✨ Features

### 🔐 Signal Protocol Implementation

DooD CLI implements the industry-standard Signal Protocol for maximum security:

- **X3DH (Extended Triple Diffie-Hellman)**: Secure key agreement protocol for establishing encrypted sessions
- **Double Ratchet Algorithm**: Forward secrecy and break-in recovery for ongoing conversations
- **Prekey Bundles**: Asynchronous messaging support — send messages even when recipients are offline

### 🔑 Passwordless Authentication

- **Challenge-Response Authentication**: No passwords to remember, leak, or crack
- **Cryptographic Identity**: Your identity is your public key
- **Secure by Default**: Authentication is built on the same cryptographic primitives as message encryption

### 💬 Core Messaging Features

- **One-on-One Conversations**: Secure direct messaging between users
- **Message History**: Local encrypted storage of conversation history
- **Interactive Chat Mode**: Real-time conversation interface
- **Conversation Management**: View all your chats with unread message indicators
- **Key Export/Import**: Backup and restore your encryption keys across devices

### 🏠 Self-Hosting Ready

- **Connect to Any Server**: Point the CLI to your own DooD API server
- **No Vendor Lock-in**: Your data stays on infrastructure you control
- **Network Isolation**: Create private messaging networks for organizations or communities

---

## ⚠️ Current Limitations

DooD CLI is a **work in progress** and currently has some limitations:

- **Single Device per Account**: Multi-device support is not yet implemented
- **Text Messages Only**: No support for images, videos, audio, or file attachments yet
- **No Group Chats**: Only one-on-one conversations are supported
- **Command-Line Only**: No graphical user interface (GUI)
- **Manual Message Fetching**: Real-time push notifications not yet implemented

**Known Issues**: As an early-stage project, you may encounter bugs and unexpected behavior. We appreciate your patience and feedback!

---

## 📦 Installation

### Prerequisites

- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning repositories
- **DooD API Server**: You'll need access to a DooD server (see below)

### Step 1: Clone the Encryption Library

DooD CLI depends on our custom encryption library. Clone it first:

```bash
git clone git@github.com:MahbodGhadiri/DooD-encryption-lib.git
```

### Step 2: Clone DooD CLI

```bash
git clone git@github.com:YOUR_USERNAME/DooD-CLI.git
cd DooD-CLI
```

### Step 3: Update Dependency Path

Make sure the `Cargo.toml` points to the correct path for the encryption library:

```toml
[dependencies]
DooD_encryption_lib = { path = "../DooD-encryption-lib" }
```

Adjust the path if you cloned the library to a different location.

### Step 4: Build the Project

```bash
cargo build --release
```

The compiled binary will be available at `target/release/dood-cli` (or `dood-cli.exe` on Windows).

### Step 5: Set Up a Server

**Note**: The DooD API server is not yet publicly available. For now, use this placeholder:

```
# Coming soon: Instructions for self-hosting DooD API
# Repository: [Will be available at github.com/YOUR_USERNAME/DooD-API]
```

---

## 🚀 Usage

### Initial Setup

1. **Configure Server URL**:

   ```bash
   ./dood-cli set-server --url https://your-dood-server.com
   ```

2. **Register a New Account**:

   ```bash
   ./dood-cli register --username your_username
   ```

3. **Login** (on subsequent uses):
   ```bash
   ./dood-cli login --username your_username
   ```

### Messaging

**Send a Message**:

```bash
./dood-cli send --to recipient_username --message "Hello, secure world!"
```

**Fetch New Messages**:

```bash
./dood-cli fetch
```

**View Conversations**:

```bash
./dood-cli chats
```

**View Message History**:

```bash
./dood-cli history --username recipient_username
```

**Interactive Chat Mode**:

```bash
./dood-cli chat --username recipient_username
```

In interactive mode:

- Type your message and press Enter to send
- Type `/fetch` to check for new messages
- Type `/quit` or `/exit` to leave the chat

### Account Management

**View Account Info**:

```bash
./dood-cli account
```

**Export Keys** (for backup):

```bash
./dood-cli export-keys --output my-keys-backup.json
```

⚠️ **Keep this file secure!** Anyone with access can read your messages.

**Import Keys** (restore from backup):

```bash
./dood-cli import-keys --input my-keys-backup.json
```

**Logout**:

```bash
./dood-cli logout
```

---

## 🛠️ Technology Stack

- **Rust**: Memory-safe systems programming language
- **X25519**: Elliptic curve Diffie-Hellman key exchange
- **ChaCha20-Poly1305**: Authenticated encryption
- **Ed25519**: Digital signatures
- **SQLite**: Local encrypted message storage
- **Reqwest**: HTTP client for server communication

---

## 🗺️ Roadmap

Future features I'm working on:

- [ ] Multi-device support
- [ ] File and multimedia sharing
- [ ] Group messaging
- [ ] Real-time message delivery (WebSocket/push notifications)
- [ ] Contact management
- [ ] Read receipts
- [ ] Desktop and mobile GUI clients
- [ ] Federation between different DooD servers

---

## 📄 License

[Add your license here - MIT, GPL, Apache 2.0, etc.]

---

## 🔗 Related Projects

- **DooD Encryption Library**: [github.com/MahbodGhadiri/DooD-encryption-lib](https://github.com/MahbodGhadiri/DooD-encryption-lib)
- **DooD API Server**: [Coming soon - Self-hostable server implementation]

---

## ⚡ Quick Start Example

```bash
# 1. Set up your server
./dood-cli set-server --url https://dood.example.com

# 2. Register
./dood-cli register --username alice

# 3. Start chatting
./dood-cli chat --username bob
```

---

## 🔒 Security Notice

While DooD implements industry-standard cryptographic protocols, this is an early-stage project that **has not undergone professional security auditing**. Use at your own risk, especially for sensitive communications.

If you discover a security vulnerability, please report it responsibly by contacting [m.ghadirisani2013@gmail.com].

---
