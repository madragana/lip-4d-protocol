# LIP-4D Specification (v0.2)

## Overview
The **LLM Intent Protocol (LIP)** aka LIP-4D is a 4-dimensional semantic language designed for AI-to-AI interaction based on expressed **intent**, rather than static credentials. It is optimized for environments where LLM agents, gateways, or autonomous services must communicate and authenticate based on purpose, context, reasoning, and evolution.

---

## Protocol Version
```json
"lip_version": "0.2"
```

---

## Dimensions

### 1️⃣ Time – Chronos
Encodes when the intent was created, how long it remains valid, and how it fits into a timeline of events.

```json
"time": {
  "timestamp": "2025-04-22T18:00:00Z",
  "expires": "2025-04-22T18:05:00Z",
  "intent_age": "PT1M",
  "timeline": {
    "prior_events": ["login", "checkout"],
    "current_event": "view_profile",
    "expected_next": "update_address"
  }
}
```

### 2️⃣ Cognition – Logos
Encodes the reasoning, decision basis, and explainability trace of the intent.

```json
"cognition": {
  "explanation": "User clicked on profile icon after successful checkout.",
  "confidence": 0.92,
  "decision_basis": ["checkout complete", "user role: buyer"],
  "reasoning_graph": {
    "nodes": [
      { "id": "n1", "fact": "User logged in" },
      { "id": "n2", "fact": "User purchased product" }
    ],
    "edges": [
      { "from": "n1", "to": "n2", "type": "causes" }
    ],
    "conclusion": "Intent to manage account info is valid"
  },
  "validation_mode": "reasoning_trace"
}
```

### 3️⃣ Context – Topos
Encodes the origin, relationships, and operational scope of the agent issuing the intent.

```json
"context": {
  "agent_location": {
    "network_domain": "app.example.com",
    "ip": "10.0.0.42",
    "geo": "Edinburgh, UK",
    "cluster_zone": "eu-west-1"
  },
  "session": {
    "session_id": "sess-12345",
    "created_at": "2025-04-22T17:05:00Z",
    "user_agent": "ProfileApp/3.1"
  },
  "agent_relationships": [
    { "type": "child-of", "target": "frontend_gateway" }
  ],
  "scope_domain": {
    "resource": "user_profile",
    "visibility": "private",
    "tenant": "demo_tenant"
  },
  "operational_context": {
    "mode": "production",
    "environment": "k8s",
    "risk_level": "medium"
  }
}
```

### 4️⃣ Evolution – Physis
Encodes how the intent mutates, retries, learns, and expires.

```json
"evolution": {
  "intent_id": "intent-0072",
  "parent_intent": "intent-0069",
  "mutation": {
    "type": "urgency_upgrade",
    "cause": "user returned after timeout",
    "time": "2025-04-22T18:04:00Z"
  },
  "retry_count": 2,
  "learning": {
    "insights": ["Session expired previously"],
    "adapted_parameters": {
      "confidence": 0.94,
      "urgency": "high"
    }
  },
  "decay_policy": {
    "decay_start": "2025-04-22T18:10:00Z",
    "soft_expiry": "2025-04-22T18:15:00Z",
    "hard_expiry": "2025-04-22T18:20:00Z",
    "on_decay": "reduce_confidence"
  }
}
```

---

## Core Fields

```json
"intent": "string",
"actor": {
  "agent_name": "string",
  "capabilities": [ "string" ],
  "reputation": {
    "score": 0.0–1.0,
    "last_verified": "ISO-8601"
  }
}
```

---

## Use Cases
- Secure AI gateway-to-gateway intent handshakes
- Autonomous agent delegation based on purpose
- Intent tracing, explanation, and rollback
- Intent-based access control (IBAC) instead of role-based or token-based

---

## Future Extensions
- Ethical filters
- Federated trust scores
- Graph serialization format (e.g., JSON-LD / RDF)
- AI-native signatures (e.g., zero-knowledge proof of reasoning)

---

## License
Proposed: Apache 2.0

## Maintainer
@angelo-ovidi (initial creator)
