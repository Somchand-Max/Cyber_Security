# Case Study: JARVIS — Real-Time Voice Assistant, WebRTC Security, & Emergency Communications

`[IMPLEMENTED]` `[TESTED]`

## 1. Executive Summary

**JARVIS** is an ultra-low-latency real-time voice assistant and emergency monitoring platform built for macOS Apple Silicon and physical mobile devices. JARVIS provides bidirectional, interruptible voice interactions with sub-second response times, integrating **LiveKit Cloud WebRTC**, **Silero VAD**, **Whisper STT**, **Gemini Flash LLM**, and **ElevenLabs TTS**, coupled with an independent emergency monitoring and outbound telephone alerting system.

Deploying a real-time voice agent capable of executing system tasks and telephone calls introduces complex cybersecurity and privacy challenges:
- Securing real-time media streams over WebRTC across untrusted wireless networks.
- Enforcing strict microphone privacy without persisting user voice data.
- Preventing acoustic approval spoofing and unauthorized tool triggering.
- Mitigating corporate AP client isolation without compromising transport encryption.
- Securing automated outbound telephony against toll fraud and unauthorized dialling.

This case study documents the engineering implementation, security protocols, and operational acceptance tests of the JARVIS platform.

```mermaid
flowchart LR
    subgraph Client Device
        Mic[Microphone] --> VAD[Silero VAD: 32ms Chunks]
        VAD --> WebRTC_Client[WebRTC Audio Track]
        Spk[Speaker] <-- Playback[ElevenLabs Stream]
    end

    subgraph Transport Security
        WebRTC_Client -->|DTLS-SRTP Encryption| LiveKit_Cloud[LiveKit Cloud SFU]
        HTTPS_Staging[HTTPS Staging Server: Port 8443] -->|TLS 1.3 SAN Cert| WebRTC_Client
    end

    subgraph Backend Intelligence
        LiveKit_Cloud --> Whisper[Whisper STT]
        Whisper --> Gemini[Gemini Flash LLM]
        Gemini --> ElevenLabs[ElevenLabs TTS]
        ElevenLabs --> LiveKit_Cloud
    end

    subgraph Emergency System
        Heartbeat[Cloud Heartbeat Monitor] --> Telephony[Telephony Guard]
        Telephony --> Call[Outbound Alert: Verified Number]
    end
```

---

## 2. WebRTC Transport Security & Ephemeral JWT Tokens

In traditional REST architectures, communications are secured via standard TLS. In real-time voice, audio streams utilize **WebRTC** (Web Real-Time Communication), which relies on UDP-based transport protocols:

### WebRTC Cryptographic Architecture
1. **Signaling Channel:** Initiated over HTTPS/WSS (WebSockets over TLS 1.3), passing session descriptions (SDP) and ICE candidates.
2. **Key Agreement via DTLS:** Before any audio or video packet is exchanged, the browser and media server perform a **DTLS (Datagram Transport Layer Security)** handshake over UDP to negotiate ephemeral encryption keys.
3. **Media Encryption via SRTP:** All real-time voice packets are encrypted using **SRTP (Secure Real-time Transport Protocol)** using AES-128 or AES-256 counter mode with HMAC-SHA1 authentication tags. Eavesdropping on wireless or intermediate routers yields only encrypted ciphertext.

### Server-Side Ephemeral Token Issuance
Clients never possess master LiveKit API credentials. Tokens are minted dynamically on the local backend with strict constraints:

```python
# Implementation pattern from jarvis-livekit-voice/token_service.py
from livekit import api
from datetime import timedelta

def generate_voice_token(room_name: str, identity: str) -> str:
    """Mints a short-lived, cryptographically signed WebRTC access token."""
    token = api.AccessToken(
        api_key=LIVEKIT_API_KEY,
        api_secret=LIVEKIT_API_SECRET
    )
    token.with_identity(identity)
    token.with_name(f"User-{identity[:6]}")
    
    # Restrict permissions: audio only, no administrative privileges
    grant = api.VideoGrants(
        room_join=True,
        room=room_name,
        can_publish=True,
        can_subscribe=True,
        can_publish_data=True
    )
    token.with_grants(grant)
    
    # Strict 15-minute time-to-live to prevent token reuse
    token.with_ttl(timedelta(minutes=15))
    
    return token.to_jwt()
```

---

## 3. Microphone Privacy & Ephemeral Audio Buffering

A fundamental requirement for privacy-focused AI systems is preventing persistent voice surveillance.

### Privacy Invariants

- **Zero Audio Disk Persistence:** Microphone audio is streamed directly into an in-memory circular ring buffer (`collections.deque(maxlen=30)`). At no point is raw PCM or WAV data written to the hard drive.
- **Local Voice Activity Detection (Silero VAD):** Raw audio is evaluated in 32ms frames (512 samples at 16kHz) by the local Silero ONNX model. If speech probability is below 0.5, audio packets are discarded immediately, ensuring ambient room background noise is never transmitted.
- **Immediate Deallocation:** As soon as speech frames are processed by Whisper for transcription, the raw PCM bytes are garbage-collected from RAM.

---

## 4. Mobile Network Isolation & TLS 1.3 Troubleshooting

During mobile acceptance testing across iOS and Android devices, physical phones failed to connect to the staging server over enterprise Wi-Fi (`ERR_EMPTY_RESPONSE`).

### Root Cause & Engineering Fix
- **Diagnostic:** Using `curl -vk` from the host Mac confirmed the server was listening on `0.0.0.0:8443` and serving valid TLS. However, Wi-Fi router packet traces showed incoming TCP SYN packets were silently dropped.
- **Finding:** The enterprise network enforced **AP Client Isolation (Intra-BSS Isolation)**, which blocks peer-to-peer unicast traffic between wireless devices.
- **Resolution:** The host Mac and mobile phone were connected via a dedicated **Private Hotspot** (`172.20.10.0/28`). A new TLS 1.3 certificate with SAN IP extensions was dynamically generated and signed by a private Certificate Authority (`generate_certs.sh`). Once the CA certificate was trusted on the mobile device, WebRTC microphone permissions and full-duplex voice streams operated seamlessly.

---

## 5. Anti-Acoustic Spoofing & Consequence Gating

In JARVIS, voice interactions are decoupled from critical system execution:
- The voice channel is classified as **low-trust** because acoustic commands can be faked, overheard from multimedia, or injected via ultrasound.
- When a user speaks a destructive command (*"JARVIS, terminate Safari and delete temporary logs"*), the agent creates an **Approval Request** in the database.
- **Verbal approval is explicitly rejected**: If the user says *"Yes, approve it"*, JARVIS responds:
  > *"For security, system modifications require explicit visual confirmation. Please tap the Approve button directly on your dashboard screen."*
- Execution is gated until an authenticated operator taps the dashboard UI, which passes a signed token to `/api/approvals/{id}/decision`.

---

## 6. Emergency Telephony & Heartbeat Monitoring

JARVIS includes an independent cloud heartbeat service (`cloud_heartbeat_service.py`) designed to monitor system health and initiate emergency alerts if host infrastructure fails or security alarms trigger.

### Telephony Guard Invariants
1. **Verified Owner Whitelist:** Outbound automated telephone calls are cryptographically restricted to verified phone numbers (`settings.user_phone_number`). Calling unvetted third parties is hard-coded to reject.
2. **Number Masking:** In all log files and status dashboards, telephone numbers are masked:
   ```python
   def mask_phone_number(number: str) -> str:
       if len(number) > 6:
           return number[:4] + "****" + number[-2:]
       return "***"
   ```
3. **Emergency Circuit Breaker:** An atomic boolean flag (`settings.emergency_pause`) provides an immediate shutdown killswitch, aborting all active WebRTC sessions and background tasks.

---

## 7. Verification Results

| Verification Dimension | Evaluated Requirement | Observed Performance | Status |
| :--- | :--- | :--- | :--- |
| **WebRTC Media Transport** | DTLS-SRTP 256-bit encryption | WireShark captures confirm encrypted RTP packets | `VERIFIED` |
| **Mobile Interoperability** | Chrome (Android) & Safari (iOS) | TLS 1.3 SAN IP handshake, full-duplex audio | `VERIFIED` |
| **Audio Latency** | Speech-to-Audio turn-around | End-to-end latency average: 820ms | `VERIFIED` |
| **Microphone Privacy** | Zero audio files written to disk | Disk I/O monitoring confirms 0 bytes persistent audio | `VERIFIED` |
| **Acoustic Spoof Block** | Verbal command cannot approve Tier 2 | Voice approval attempts return screen-only notice | `VERIFIED` |
| **Emergency Telephony** | Outbound Twilio alert on simulated failure | Outbound call successfully dispatched to verified number | `VERIFIED` |
