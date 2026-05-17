# LangChain integration

Memgar wraps LangChain's memory and retriever interfaces so every write and
chunk gets analyzed before reaching the model.

## Memory firewall

```python
from langchain.memory import ConversationBufferMemory
from memgar.integrations.langchain_memory import MemgarMemory

base_memory = ConversationBufferMemory()
guarded = MemgarMemory(
    base=base_memory,
    on_block="quarantine",   # or "drop", "raise"
)

# Now any save_context / load_memory_variables goes through memgar
chain = LLMChain(memory=guarded, prompt=..., llm=...)
```

When memgar flags an incoming write as `block`:

- `on_block="quarantine"` — write is stored in a quarantine buffer and not
  returned to the chain
- `on_block="drop"` — write is silently dropped (logged)
- `on_block="raise"` — raises `MemgarBlockedError`

## Retrieval guard

```python
from memgar.integrations.langchain_retriever import MemgarRetriever

retriever = MemgarRetriever(
    base=my_chroma_retriever,
    drop_blocked=True,
)

# Chunks flagged by memgar are removed before reaching the LLM prompt
docs = retriever.invoke("How do I reset my password?")
```

## Full example

```python
import os
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain_openai import ChatOpenAI
from memgar.integrations.langchain_memory import MemgarMemory

llm = ChatOpenAI(model="gpt-4o-mini", api_key=os.environ["OPENAI_API_KEY"])
mem = MemgarMemory(base=ConversationBufferMemory())
chain = LLMChain(llm=llm, memory=mem, prompt=my_prompt)

response = chain.invoke({"input": user_message})
# If user_message contains a memory-poisoning attempt, memgar blocks the
# write into history. The LLM still answers but its future turns won't be
# poisoned.
```

## See also

The committed example `examples/langchain_memory.py` is a runnable end-to-end
demo covering both memory and retriever guards with a small in-memory store.
