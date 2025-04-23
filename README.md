# LIP – LLM Intent Protocol

**LIP (LLM Intent Protocol)** is a semantic, 4-dimensional protocol for AI-to-AI communication and authentication based on **intention** rather than static credentials.

This project defines:
- A universal JSON schema for LIP intents (`schemas/lip-4d-v0.2.json`)
- A full protocol specification (`lip-spec.md`)
- Example LIP intent documents
- A simple Python reference agent for generating and validating LIP intents

## 🌐 What is LIP?

LIP lets autonomous agents (LLMs, gateways, services) communicate in a shared language of:

| Dimension | Name    | Description |
|----------|---------|-------------|
| 1️⃣       | Chronos | Time: When the intent happens and how it fits a timeline |
| 2️⃣       | Logos   | Cognition: Why the agent acts, and how it reasons |
| 3️⃣       | Topos   | Context: Where the agent is and what domain it belongs to |
| 4️⃣       | Physis  | Evolution: How the intent adapts, mutates, retries, or decays |

## 📜 License

Apache 2.0 – © 2025 Angelo Ovidi
