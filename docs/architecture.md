# PacketAlchemy Nexus Architecture

## Overview

PacketAlchemy Nexus is an edge engineering platform built on Cloudflare Workers.

### Core Components

- DNS
- Cloudflare Edge
- Workers
- Security Layer
- Origin Services

---

## High-Level Flow

Client → DNS → Cloudflare Edge → Worker → Origin

┌──────────────┐
│    Client    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│     DNS      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Cloudflare   │
│    Edge      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Worker     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Origin     │
└──────────────┘
