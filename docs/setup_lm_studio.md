# Setup LM Studio

This lab targets LM Studio running locally with an OpenAI-compatible API server.

## 1. Install LM Studio

Install LM Studio from:

https://lmstudio.ai/

Use the official installer for your operating system.

## 2. Download a DeepSeek R1 Distill Qwen GGUF Q4 Model

In LM Studio, open the model discovery/search area and search for:

```text
DeepSeek R1 Distill Qwen GGUF Q4
```

Select a Q4 quantized GGUF variant that fits your machine. Common Q4 variants may include names such as `Q4_K_M`, but exact filenames and publishers can change. Prefer a reputable model publisher and verify the license before use.

## 3. Load the Model

Load the downloaded model in LM Studio. Note the model identifier shown by LM Studio, because the API request must use that identifier.

Update `.env` if needed:

```bash
LM_STUDIO_MODEL=your-loaded-model-identifier
```

## 4. Start the Local Server

In LM Studio, start the local developer server. Configure it to listen on:

```text
localhost:1234
```

This lab expects the OpenAI-compatible base URL:

```text
http://localhost:1234/v1
```

LM Studio documents OpenAI-compatible endpoints including `POST /v1/chat/completions` and the `base_url` setting here:

https://lmstudio.ai/docs/developer/openai-compat

## 5. Confirm the Server Is Running

From a terminal:

```bash
curl http://localhost:1234/v1/models
```

You should receive a JSON response listing local models. If this fails, confirm the model is loaded and the LM Studio server is running on port `1234`.

Then start the lab API:

```bash
uvicorn app.main:app --reload
```

Test the local secure endpoint:

```bash
curl -s http://localhost:8000/chat/local-secure \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Summarize refund policy safely."}'
```
