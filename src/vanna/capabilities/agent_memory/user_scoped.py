"""
Per-user agent memory.

Every AgentMemory backend keeps a single memory that is shared by all users
of the agent: questions, tool arguments (such as SQL) and text memories saved
by one user are returned to every other user, and text memories are added to
their system prompts. That is intended when only trusted users can save
memories (register the save tools with ``access_groups=["admin"]``).

When regular users can save memories, wrap the backend in
``UserScopedAgentMemory`` so each user gets a separate memory. Their saved
questions, SQL and notes then stay private and cannot steer other users'
conversations. Admin-curated knowledge can still be shared read-only through
``shared_memory``.
"""

from __future__ import annotations

import hashlib
import threading
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from .base import AgentMemory

if TYPE_CHECKING:
    from vanna.core.tool import ToolContext
    from .models import (
        TextMemory,
        TextMemorySearchResult,
        ToolMemory,
        ToolMemorySearchResult,
    )


class UserScopedAgentMemory(AgentMemory):
    """Give each user a separate memory, with optional shared read-only memory.

    Example::

        memory = UserScopedAgentMemory(
            lambda key: ChromaAgentMemory(
                persist_directory="./chroma_memory",
                collection_name=f"memories_{key}",
            ),
            shared_memory=ChromaAgentMemory(collection_name="shared_memories"),
        )

    Args:
        memory_factory: Called once per user with a storage key (a hash of the
            user ID that is safe to use in collection names and paths) and
            returns that user's memory.
        shared_memory: Optional memory that every user can search but not
            change, for example knowledge curated by admins.
    """

    def __init__(
        self,
        memory_factory: Callable[[str], AgentMemory],
        shared_memory: Optional[AgentMemory] = None,
    ) -> None:
        self._memory_factory = memory_factory
        self._shared_memory = shared_memory
        self._user_memories: Dict[str, AgentMemory] = {}
        self._lock = threading.Lock()

    @staticmethod
    def storage_key(user_id: str) -> str:
        """Return a name-safe key for a user ID."""
        return hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:32]

    def memory_for(self, context: "ToolContext") -> AgentMemory:
        """Return the memory of the user in ``context``, creating it if needed."""
        user_id = getattr(context.user, "id", None)
        if not user_id:
            raise ValueError("UserScopedAgentMemory requires a user with an id")
        key = self.storage_key(str(user_id))
        with self._lock:
            memory = self._user_memories.get(key)
            if memory is None:
                memory = self._memory_factory(key)
                self._user_memories[key] = memory
            return memory

    def _sources(self, context: "ToolContext") -> List[AgentMemory]:
        sources = [self.memory_for(context)]
        if self._shared_memory is not None:
            sources.append(self._shared_memory)
        return sources

    @staticmethod
    def _merge_ranked(results: List[Any], limit: int) -> List[Any]:
        results = sorted(results, key=lambda r: r.similarity_score, reverse=True)
        return [
            result.model_copy(update={"rank": rank})
            for rank, result in enumerate(results[:limit], start=1)
        ]

    @staticmethod
    def _merge_recent(memories: List[Any], limit: int) -> List[Any]:
        return sorted(memories, key=lambda m: m.timestamp or "", reverse=True)[:limit]

    async def save_tool_usage(
        self,
        question: str,
        tool_name: str,
        args: Dict[str, Any],
        context: "ToolContext",
        success: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        await self.memory_for(context).save_tool_usage(
            question=question,
            tool_name=tool_name,
            args=args,
            context=context,
            success=success,
            metadata=metadata,
        )

    async def save_text_memory(
        self, content: str, context: "ToolContext"
    ) -> "TextMemory":
        return await self.memory_for(context).save_text_memory(
            content=content, context=context
        )

    async def search_similar_usage(
        self,
        question: str,
        context: "ToolContext",
        *,
        limit: int = 10,
        similarity_threshold: float = 0.7,
        tool_name_filter: Optional[str] = None,
    ) -> List["ToolMemorySearchResult"]:
        results: List["ToolMemorySearchResult"] = []
        for memory in self._sources(context):
            results.extend(
                await memory.search_similar_usage(
                    question,
                    context,
                    limit=limit,
                    similarity_threshold=similarity_threshold,
                    tool_name_filter=tool_name_filter,
                )
            )
        return self._merge_ranked(results, limit)

    async def search_text_memories(
        self,
        query: str,
        context: "ToolContext",
        *,
        limit: int = 10,
        similarity_threshold: float = 0.7,
    ) -> List["TextMemorySearchResult"]:
        results: List["TextMemorySearchResult"] = []
        for memory in self._sources(context):
            results.extend(
                await memory.search_text_memories(
                    query,
                    context,
                    limit=limit,
                    similarity_threshold=similarity_threshold,
                )
            )
        return self._merge_ranked(results, limit)

    async def get_recent_memories(
        self, context: "ToolContext", limit: int = 10
    ) -> List["ToolMemory"]:
        memories: List["ToolMemory"] = []
        for memory in self._sources(context):
            memories.extend(await memory.get_recent_memories(context, limit=limit))
        return self._merge_recent(memories, limit)

    async def get_recent_text_memories(
        self, context: "ToolContext", limit: int = 10
    ) -> List["TextMemory"]:
        memories: List["TextMemory"] = []
        for memory in self._sources(context):
            memories.extend(await memory.get_recent_text_memories(context, limit=limit))
        return self._merge_recent(memories, limit)

    # Deleting only ever touches the user's own memory; shared memory is
    # managed directly by whoever owns it.

    async def delete_by_id(self, context: "ToolContext", memory_id: str) -> bool:
        return await self.memory_for(context).delete_by_id(context, memory_id)

    async def delete_text_memory(self, context: "ToolContext", memory_id: str) -> bool:
        return await self.memory_for(context).delete_text_memory(context, memory_id)

    async def clear_memories(
        self,
        context: "ToolContext",
        tool_name: Optional[str] = None,
        before_date: Optional[str] = None,
    ) -> int:
        return await self.memory_for(context).clear_memories(
            context, tool_name=tool_name, before_date=before_date
        )
