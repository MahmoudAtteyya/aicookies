# Streaming Context Continuity System (SCCS)

## Problem Analysis

### Current Behavior (BROKEN)
```
Client Request → aicookies → Provider Key A
                           ↓ [streaming tokens...]
                       [after 500 tokens] → Key A exhausted
                           ↓
                       [ERROR: stop_stream]
                           ↓
                       Client receives: "Here is my response about... [CUT]"
```

### Desired Behavior (FIXED)
```
Client Request → aicookies → Provider Key A
                           ↓ [buffering tokens...]
                       [after 500 tokens] → Key A exhausted
                           ↓
                       [Checkpointer saves: partial_response (500 tokens)]
                           ↓
                       Retry with Key B + inject partial as context
                           ↓
                       Key B continues from token 501
                           ↓
                       Client receives seamless: "Here is my response about X. [continuation...] The answer is..."
```

---

## Technical Implementation

### Phase 1: Response Buffer (In-Memory)

```python
import uuid
import threading
from collections import defaultdict

# Stream buffer with request tracking
STREAM_BUFFERS = {}  # {stream_id: {"tokens": [], "last_checkpoint": N, "created_at": ts, "metadata": {}}}
STREAM_LOCK = threading.Lock()

def create_stream_buffer(request_id: str, metadata: dict) -> str:
    """Create a buffer for streaming response."""
    stream_id = f"stream_{request_id}_{uuid.uuid4().hex[:8]}"
    with STREAM_LOCK:
        STREAM_BUFFERS[stream_id] = {
            "tokens": [],
            "accumulated_text": "",
            "last_checkpoint": 0,
            "created_at": time.time(),
            "metadata": metadata,
            "status": "streaming"
        }
    return stream_id

def append_token(stream_id: str, token: bytes):
    """Append a token to buffer. Called on every chunk from provider."""
    with STREAM_LOCK:
        if stream_id in STREAM_BUFFERS:
            STREAM_BUFFERS[stream_id]["tokens"].append(token)
            # Accumulate text representation (for context injection)
            try:
                decoded = token.decode('utf-8')
                STREAM_BUFFERS[stream_id]["accumulated_text"] += decoded
            except:
                pass

def get_buffer_state(stream_id: str) -> dict:
    """Get current buffer state for checkpoint/restore."""
    with STREAM_LOCK:
        if stream_id in STREAM_BUFFERS:
            return {
                "token_count": len(STREAM_BUFFERS[stream_id]["tokens"]),
                "accumulated_text": STREAM_BUFFERS[stream_id]["accumulated_text"],
                "last_checkpoint": STREAM_BUFFERS[stream_id]["last_checkpoint"]
            }
    return None

def checkpoint_stream(stream_id: str, position: int):
    """Mark checkpoint position for possible recovery."""
    with STREAM_LOCK:
        if stream_id in STREAM_BUFFERS:
            STREAM_BUFFERS[stream_id]["last_checkpoint"] = position

def finalize_stream(stream_id: str):
    """Mark stream as complete, keep for reference (TTL: 5 min)."""
    with STREAM_LOCK:
        if stream_id in STREAM_BUFFERS:
            STREAM_BUFFERS[stream_id]["status"] = "completed"
            STREAM_BUFFERS[stream_id]["completed_at"] = time.time()
```

### Phase 2: Streaming Generator with Buffer

```python
from flask import stream_with_context, Response
import httpx

def buffered_stream_generator(resp, stream_id: str, checkpoint_interval: int = 100):
    """
    Generator that:
    1. Buffers all tokens
    2. Creates checkpoints every N tokens
    3. Yields to client immediately (no latency added)
    """
    token_count = 0
    try:
        for chunk in resp.iter_bytes(8192):
            # Buffer it
            append_token(stream_id, chunk)
            token_count += 1
            
            # Checkpoint periodically
            if token_count % checkpoint_interval == 0:
                checkpoint_stream(stream_id, token_count)
                app.logger.debug(f"[stream] Checkpoint at token {token_count}")
            
            # Yield to client
            yield chunk
    except Exception as e:
        # Stream interrupted — buffer state preserved for recovery
        app.logger.warning(f"[stream] Interrupted at token {token_count}: {e}")
        checkpoint_stream(stream_id, token_count)
        raise  # Re-raise for retry logic
```

### Phase 3: Context Injection for Continuation

```python
def inject_continuation_context(original_body: bytes, partial_response: str, model: str) -> bytes:
    """
    Modify request to include partial response as context.
    
    Strategy:
    - For chat models: Add as system message "Continue from: ..."
    - For completion models: Append to prompt
    """
    try:
        data = json.loads(original_body)
        
        continuation_prompt = f"""[Previous response was interrupted. Continue seamlessly from here:]

{partial_response[-2000:]}

[Continue the response naturally without repeating or apologizing. Pick up exactly where the text cuts off.]"""
        
        # Chat completions format
        if "messages" in data:
            # Add continuation as system message
            data["messages"].append({
                "role": "system",
                "content": continuation_prompt
            })
        else:
            # Completion format
            data["prompt"] = data.get("prompt", "") + "\n\n" + continuation_prompt
        
        return json.dumps(data).encode()
    except:
        return original_body
```

### Phase 4: Retry Logic with Buffer Restore

```python
def proxy_to_provider_with_buffering(provider_slug, real_model, model_slug):
    """
    Enhanced proxy with streaming buffer + context continuity.
    """
    request_id = str(uuid.uuid4())
    stream_id = None
    partial_response = None
    
    # ... (try keys in rotation)
    
    for key_info in untried_keys:
        try:
            # Determine if this is a continuation
            body_data = request.get_data()
            if partial_response:
                # Inject partial response as context
                body_data = inject_continuation_context(body_data, partial_response, real_model)
                app.logger.info(f"[proxy] Continuation request with {len(partial_response)} chars context")
            
            # Create buffer for this attempt
            stream_id = create_stream_buffer(request_id, {
                "provider": provider_slug,
                "model": model_slug,
                "key_id": key_id
            })
            
            # Make request
            with httpx.Client(timeout=180.0) as client:
                resp = client.post(url, content=body_data, headers=headers)
                
                if is_streaming:
                    # Buffered streaming
                    def generate():
                        yield from buffered_stream_generator(resp, stream_id)
                    
                    return Response(
                        stream_with_context(generate()),
                        status=resp.status_code,
                        headers={
                            "Content-Type": "text/event-stream",
                            "X-Stream-ID": stream_id,
                            "X-Buffer-Enabled": "true"
                        }
                    )
        
        except Exception as e:
            # Get partial response from buffer
            buffer_state = get_buffer_state(stream_id)
            if buffer_state and buffer_state["accumulated_text"]:
                partial_response = buffer_state["accumulated_text"]
                app.logger.warning(f"[proxy] Stream interrupted, have {len(partial_response)} chars to continue")
            
            # Try next key with context
            continue
    
    # All keys exhausted
    if partial_response:
        # At least return what we got
        app.logger.warning(f"[proxy] Returning partial response: {len(partial_response)} chars")
        return Response(
            partial_response,
            status=200,
            headers={"X-Partial-Response": "true", "X-Complete": "false"}
        )
    
    return format_error_response("ALL_KEYS_EXHAUSTED", ...)
```

---

## Integration Points

### Where to modify in app.py:

1. **Lines 1298-1306** (streaming return):
   ```python
   # OLD:
   if is_streaming:
       def generate():
           for chunk in resp.iter_bytes(8192):
               yield chunk
       return Response(...)
   
   # NEW:
   if is_streaming:
       stream_id = create_stream_buffer(request_id, {...})
       def generate():
           yield from buffered_stream_generator(resp, stream_id)
       return Response(...)
   ```

2. **Add buffer management functions** at line ~768 (near KeyCache)

3. **Modify exception handling** (lines 1319+) to:
   - Extract partial response from buffer
   - Pass to next key iteration

---

## Performance Considerations

### Memory Usage
- Each stream buffer: ~10-50KB per active request
- TTL cleanup every 5 minutes for completed streams
- Max 100 concurrent streams = 5MB RAM

### Latency Impact
- Buffer append: < 1ms per chunk (negligible)
- No additional network latency (tokens still stream to client immediately)
- Context injection adds ~50ms for new key request

### Token Tracking
- Approximate character-based tracking (not exact tokens)
- Could integrate tiktoken for accurate token counting if needed

---

## Alternative: Redis-backed (for distributed deployment)

```python
import redis
r = redis.Redis(host='localhost', port=6379, db=0)

def create_stream_buffer(stream_id: str, metadata: dict):
    r.hset(f"stream:{stream_id}", mapping={
        "tokens": "",
        "created_at": time.time(),
        "metadata": json.dumps(metadata)
    })
    r.expire(f"stream:{stream_id}", 300)  # 5 min TTL

def append_token(stream_id: str, token: bytes):
    r.rpush(f"stream:{stream_id}:tokens", token)
```

---

## Testing Strategy

### Unit Tests
```python
def test_buffer_append():
    stream_id = create_stream_buffer("test", {})
    append_token(stream_id, b"Hello ")
    append_token(stream_id, b"World")
    state = get_buffer_state(stream_id)
    assert "Hello World" in state["accumulated_text"]
```

### Integration Tests
1. Start stream with Key A
2. Kill connection at token 100
3. Verify Key B receives context
4. Verify client sees seamless response

---

## Limitations & Edge Cases

1. **Semantic coherence**: Continuation might not perfectly match original tone
2. **Provider context window**: Some models reject large context
3. **Non-streaming requests**: Simpler — just retry with new key, no buffering needed
4. **Long responses**: Buffer can grow large (need streaming to disk for very long responses)

---

## Recommended Implementation Order

1. ✅ Add buffer functions (lines 768-850)
2. ⏳ Modify streaming generator (lines 1298-1306)
3. ⏳ Add context injection logic
4. ⏳ Test with aisa provider (your use case)
5. ⏳ Deploy and monitor

---

## Expected Outcome

When aisa key exhausts mid-stream:
- **Before**: `[interrupted]` → Client sees partial response, next request starts fresh
- **After**: `[interrupted]` → Buffer saves context → Key B continues → Client sees seamless response

Credits usage: **Minimal overhead** — only buffers active streams, cleans up after completion.
