# API Keys Setup Guide

This guide explains how to obtain free API keys for the premium sources.

## VirusTotal

**Free tier:** 4 requests/minute, 500/day

1. Go to https://www.virustotal.com/gui/join-us
2. Create a free account
3. Go to your profile → API Key
4. Copy your API key

```bash
export VIRUSTOTAL_API_KEY="your-key-here"
```

## URLScan.io

**Free tier:** 5,000 requests/day, 100 private scans/day

1. Go to https://urlscan.io/user/signup
2. Create a free account
3. Go to Settings & API → Create new API key
4. Copy your API key

```bash
export URLSCAN_API_KEY="your-key-here"
```

## Google Safe Browsing

**Free tier:** 10,000 requests/day

1. Go to https://console.cloud.google.com/
2. Create a new project (or use existing)
3. Enable "Safe Browsing API" in APIs & Services
4. Go to Credentials → Create Credentials → API Key
5. (Optional) Restrict the key to Safe Browsing API only

```bash
export GOOGLE_SAFEBROWSING_API_KEY="your-key-here"
```

## AbuseIPDB

**Free tier:** 1,000 requests/day

1. Go to https://www.abuseipdb.com/register
2. Create a free account
3. Go to your account → API tab
4. Create an API key

```bash
export ABUSEIPDB_API_KEY="your-key-here"
```

## Setting Environment Variables

### Temporary (current session)

```bash
export VIRUSTOTAL_API_KEY="..."
export URLSCAN_API_KEY="..."
export GOOGLE_SAFEBROWSING_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
```

### Permanent (add to ~/.bashrc or ~/.zshrc)

```bash
echo 'export VIRUSTOTAL_API_KEY="..."' >> ~/.bashrc
echo 'export URLSCAN_API_KEY="..."' >> ~/.bashrc
# etc.
source ~/.bashrc
```

### Using a .env file

Create a `.env` file:

```
VIRUSTOTAL_API_KEY=your-key
URLSCAN_API_KEY=your-key
GOOGLE_SAFEBROWSING_API_KEY=your-key
ABUSEIPDB_API_KEY=your-key
```

Load with:

```bash
export $(cat .env | xargs)
```

Or use python-dotenv in Python scripts.

## IPQualityScore

**Free tier:** 5,000 requests/month

1. Go to https://www.ipqualityscore.com/create-account
2. Create a free account
3. Go to Dashboard → API Key
4. Copy your API key

```bash
export IPQUALITYSCORE_API_KEY="your-key-here"
```

## ThreatFox (abuse.ch)

**Free tier:** Unlimited (requires registration)

1. Go to https://auth.abuse.ch/
2. Register for a free account
3. Get your Auth-Key from the dashboard
4. Use it for ThreatFox, MalwareBazaar, and other abuse.ch services

```bash
export THREATFOX_API_KEY="your-key-here"
```

## AlienVault OTX (Optional)

**Free tier:** Works without key, but key gives higher rate limits

1. Go to https://otx.alienvault.com/
2. Create a free account
3. Go to Settings → API Integration
4. Copy your OTX API Key

```bash
export OTX_API_KEY="your-key-here"
```

## Free Sources (No API Key Needed)

These sources work without any API key:

- **URLhaus** - Malware URL database by abuse.ch
- **OpenPhish** - Phishing URL feed
- **DNSBL** - DNS-based blocklists (Spamhaus, SURBL)
- **AlienVault OTX** - Community threat intel (key optional for higher limits)

The skill will automatically use these sources even without any API keys configured.
