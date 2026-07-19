# Response Buffer & Continuity System (RBCS)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLIENT REQUEST                                │
│  POST /v1/chat/completions {stream: true, messages: [...]}      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                 AICOOKIES GATEWAY                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  1. REQUEST INTERCEPTOR                                   │  │
│  │     • Assign unique request_id                            │  │
│  │     • Check for resume header (X-Resume-Stream-ID)       │  │
│  │     • Load previous buffer if exists                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  2. KEY ROTATION ENGINE                                   │  │
│  │     • Try Key A → STREAMING...                           │  │
│  │       • Buffer each chunk to STREAM_BUFFER[request_id]    │  │
│  │       • Checkpoint every N chunks                         │  │
│  │     • ERROR at chunk 150? → PRESERVE BUFFER              │  │
│  │     • Try Key B → INJECT partial response + continue     │  │
│  │       • Buffer continues from chunk 151                   │  │
│  │     • SUCCESS → Mark buffer COMPLETE                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  3. RESPONSE ASSEMBLER                                    │  │
│  │     • Concatenate all buffered chunks                     │  │
│  │     • Stream to client seamlessly                         │  │
│  │     • Or return complete response                         │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. STREAM_BUFFER (In-Memory + Redis Fallback)
```python
{
    "request_id": "req_abc123",
    "status": "streaming|completed|interrupted|failed",
    "chunks": [
        {"seq": 1, "data": b"data: {...}\n\n", "timestamp": 1234567890},
        {"seq": 2, "data": b"data: {...}\n\n", "timestamp": 1234567891},
        ...
    ],
    "accumulated_text": "The quick brown fox...",
    "last_checkpoint": 50,
    "provider": "aisa",
    "model": "kimi-k3",
    "key_id": 123,
    "created_at": 1234567880,
    "updated_at": 1234567895
}
```

### 2. CONTINUATION INJECTOR
When retrying after interruption:
```python
# Extract last N chars of accumulated_text
partial = buffer["accumulated_text"][-1500:]

# Inject as system message
messages.append({
    "role": "system",
    "content": f"""[Previous response was interrupted. CONTEXT:]
{partial}

[Continue EXACTLY from here. Do NOT repeat or restart. Pick up mid-sentence if needed.]"""
})
```

### 3. SEAMLESS RETRY ENGINE
```python
while retry_count < max_retries:
    # Get next key
    key = get_next_key(provider_slug, tried_keys)
    
    # If we have partial response, inject it
    if partial_response:
        request_body = inject_continuation_context(original_body, partial_response)
    
    # Make request
    resp = client.post(url, content=request_body, stream=True)
    
    if resp.status_code == 200:
        # Stream + buffer
        for chunk in resp.iter_bytes():
            BUFFER.append(request_id, chunk)
            yield chunk
        
        # Mark complete
        BUFFER.finalize(request_id)
        break
    else:
        # Error - get partial from buffer
        partial_response = BUFFER.get_accumulated_text(request_id)
        continue
```

## Implementation Status

- [x] Basic Key Rotation
- [x] Response Buffering (in-progress)
- [ ] Continuation Injection
- [ ] Automatic Retry with Context
- [ ] Redis-backed Buffer (for distributed deployment)
- [ ] Client Resume API

## Testing Scenarios

1. **Happy Path**: Stream completes successfully
2. **Single Interruption**: Key fails at chunk 150, next key continues
3. **Multiple Interruptions**: Keys A, B, C all fail, Key D succeeds
4. **Complete Failure**: All keys exhausted, return partial + error
5. **Client Resume**: Client reconnects with X-Resume-Stream-ID

## Metrics to Track

- `buffer_created_total`
- `buffer_completed_total`
- `buffer_interrupted_total`
- `continuation_injected_total`
- `avg_chunks_before_failure`
- `continuation_success_rate`
