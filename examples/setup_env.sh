#!/bin/bash
# Memgar Environment Setup
# Source this file: source setup_env.sh

# ============================================
# LLM Provider Configuration
# ============================================

# Option 1: Let Memgar auto-detect (recommended)
# Just set the API key for your preferred provider

# Option 2: Explicitly set provider and model
# export MEMGAR_LLM_PROVIDER=groq
# export MEMGAR_LLM_MODEL=llama-3.1-8b-instant

# ============================================
# Provider API Keys (set the ones you have)
# ============================================

# OpenAI
# export OPENAI_API_KEY=sk-xxxxx

# Anthropic
# export ANTHROPIC_API_KEY=sk-ant-xxxxx

# Groq (fast inference, free tier available)
# export GROQ_API_KEY=gsk_xxxxx

# Google
# export GOOGLE_API_KEY=AIza-xxxxx

# Mistral
# export MISTRAL_API_KEY=xxxxx

# Together AI
# export TOGETHER_API_KEY=xxxxx

# Cohere
# export COHERE_API_KEY=xxxxx

# OpenRouter (multi-model gateway)
# export OPENROUTER_API_KEY=sk-or-xxxxx

# Azure OpenAI
# export AZURE_OPENAI_API_KEY=xxxxx
# export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com

# Custom OpenAI-compatible API
# export OPENAI_COMPATIBLE_API_KEY=xxxxx
# export OPENAI_COMPATIBLE_BASE_URL=https://api.example.com/v1

# ============================================
# Analysis Settings
# ============================================

# Enable strict mode (more aggressive detection)
# export MEMGAR_STRICT_MODE=true

# Enable LLM-based analysis (requires API key)
# export MEMGAR_USE_LLM=true

# Sliding window for long content
# export MEMGAR_SLIDING_WINDOW=true
# export MEMGAR_WINDOW_SIZE=1000

# ============================================
# Performance Settings
# ============================================

# Response caching
# export MEMGAR_CACHE_ENABLED=true
# export MEMGAR_CACHE_TTL=7200

# Request settings
# export MEMGAR_LLM_TIMEOUT=30
# export MEMGAR_LLM_MAX_RETRIES=2

# Enable/disable provider fallback
# export MEMGAR_LLM_FALLBACK=true

# ============================================
# Logging
# ============================================

# Log level: DEBUG, INFO, WARNING, ERROR
# export MEMGAR_LOG_LEVEL=INFO

echo "Memgar environment configured!"
