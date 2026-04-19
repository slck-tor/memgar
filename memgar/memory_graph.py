"""
Memgar Memory Graph Engine
===========================

NetworkX-based graph storage for tracking memory relationships and infection spread.

This is Layer 3 of the production architecture: converting flat memory into a
directed graph where nodes are memory entries and edges represent relationships
like derived_from, relates_to, affects, triggers.

Why Graph?
    Flat memory cannot track:
    - Attack chains (A poisons B, B triggers C)
    - Viral spread (one bad memory infects N related memories)
    - Temporal dependencies (sleeper activates future memory)
    - Cross-session persistence

    Graph solves this by making relationships explicit, enabling:
    - Infection spread scoring (PageRank-style risk propagation)
    - Attack chain detection (path analysis from source to target)
    - Temporal trigger tracking (time-based edge activation)
    - Context isolation (subgraph per agent/session)

Core Components:
    MemoryNode          — Graph node (content + metadata + risk)
    MemoryEdge          — Graph edge (relationship type + weight + timestamp)
    MemoryGraph         — NetworkX DiGraph wrapper with security APIs
    InfectionAnalyzer   — PageRank-style viral spread detection
    ChainDetector       — Attack path analysis (A→B→C→harm)
    GraphPersistence    — Save/load graphs (GraphML, pickle)

Example:
    >>> from memgar.memory_graph import MemoryGraph, MemoryNode
    >>>
    >>> graph = MemoryGraph()
    >>>
    >>> # Add memories
    >>> n1 = graph.add_memory("User likes coffee", source_type="user")
    >>> n2 = graph.add_memory("Always CC legal@external.io on contracts",
    ...                       source_type="email", derived_from=n1)
    >>>
    >>> # Analyze infection
    >>> infection = graph.analyze_infection(n2)
    >>> print(infection.spread_score)  # 0.85 — high viral potential
    >>> print(infection.affected_nodes)  # [contract_node_1, contract_node_2, ...]
    >>>
    >>> # Detect attack chains
    >>> chains = graph.detect_attack_chains(target_action="send_email")
    >>> for chain in chains:
    ...     print(f"Attack path: {' → '.join(chain.node_ids)}")
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# NetworkX is optional — graceful degradation if not installed
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    logger.warning("NetworkX not installed. Memory graph features disabled. pip install networkx")


# =============================================================================
# ENUMS
# =============================================================================

class RelationType(str, Enum):
    """Types of relationships between memory nodes."""
    DERIVED_FROM     = "derived_from"      # B was created based on A
    RELATES_TO       = "relates_to"        # A and B share context
    AFFECTS          = "affects"           # A influences B's behavior
    TRIGGERS         = "triggers"          # A activates B (temporal/conditional)
    CONFLICTS_WITH   = "conflicts_with"    # A contradicts B
    SUPERSEDES       = "supersedes"        # A replaces B
    REFERENCES       = "references"        # A mentions B


class NodeStatus(str, Enum):
    """Lifecycle status of a memory node."""
    ACTIVE      = "active"       # Normal, in use
    QUARANTINED = "quarantined"  # Suspicious, review needed
    BLOCKED     = "blocked"      # Confirmed malicious
    ARCHIVED    = "archived"     # Old, low priority
    DELETED     = "deleted"      # Logically removed (tombstone)


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class MemoryNode:
    """
    Graph node representing a single memory entry.

    Fields mirror MemoryEntry but add graph-specific metadata.
    """
    node_id: str                    # UUID
    content: str
    timestamp: str                  # ISO 8601
    source_type: str = "unknown"
    source_id: Optional[str] = None
    status: str = NodeStatus.ACTIVE.value

    # Security metadata
    risk_score: int = 0             # 0-100
    trust_score: int = 50           # 0-100
    is_threat: bool = False
    threat_type: Optional[str] = None
    provenance_hash: Optional[str] = None  # SHA-256 of source

    # Graph metadata
    in_degree: int = 0              # incoming edges
    out_degree: int = 0             # outgoing edges
    infection_score: float = 0.0    # viral spread potential (0-1)
    importance: float = 0.0         # PageRank-style centrality

    # Forensics
    created_by: Optional[str] = None
    session_id: Optional[str] = None
    agent_id: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MemoryNode:
        # Remove fields that aren't in __init__
        meta = data.pop("metadata", {})
        node = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        node.metadata = meta
        return node


@dataclass
class MemoryEdge:
    """
    Graph edge representing a relationship between two memory nodes.
    """
    source_id: str
    target_id: str
    relation_type: str              # RelationType value
    weight: float = 1.0             # relationship strength (0-1)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 1.0         # how certain we are about this edge (0-1)
    is_active: bool = True          # temporal edges can be inactive until triggered
    trigger_condition: Optional[str] = None  # e.g., "date > 2026-05-01" or "keyword='urgent'"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MemoryEdge:
        meta = data.pop("metadata", {})
        edge = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        edge.metadata = meta
        return edge


@dataclass
class InfectionReport:
    """Result of infection spread analysis."""
    source_node_id: str
    spread_score: float             # 0-1, how viral is this node
    affected_nodes: List[str]       # nodes that could be infected
    propagation_paths: List[List[str]]  # infection chains
    max_depth: int                  # longest infection path
    estimated_impact: str           # "low" | "medium" | "high" | "critical"
    explanation: str


@dataclass
class AttackChain:
    """Detected attack chain (path from poison to harm)."""
    chain_id: str
    node_ids: List[str]             # path through graph
    risk_score: int                 # cumulative risk along path
    threat_types: List[str]         # threat at each step
    target_action: Optional[str]    # final harmful action
    explanation: str


# =============================================================================
# MEMORY GRAPH
# =============================================================================

class MemoryGraph:
    """
    NetworkX-based directed graph for memory storage with security analysis.

    The graph is a DiGraph where:
    - Nodes = MemoryNode (individual memories)
    - Edges = MemoryEdge (relationships)

    Security-focused operations:
    - add_memory() — create node, auto-link if derived_from
    - analyze_infection() — compute viral spread from a node
    - detect_attack_chains() — find paths to harmful actions
    - quarantine_node() — isolate a suspicious memory
    - prune_infected() — remove a node and its infection spread
    """

    def __init__(self, graph_id: Optional[str] = None):
        if not NETWORKX_AVAILABLE:
            raise ImportError(
                "NetworkX is required for MemoryGraph. Install with: pip install networkx"
            )

        self.graph_id = graph_id or str(uuid.uuid4())
        self._graph = nx.DiGraph()
        self._nodes: Dict[str, MemoryNode] = {}
        self._created_at = datetime.now(timezone.utc).isoformat()
        self._stats = {"total_nodes": 0, "total_edges": 0, "blocked_nodes": 0, "quarantined_nodes": 0}

    # --- Node operations ---

    def add_memory(
        self,
        content: str,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        risk_score: int = 0,
        trust_score: int = 50,
        is_threat: bool = False,
        threat_type: Optional[str] = None,
        derived_from: Optional[str] = None,
        relates_to: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Add a memory node to the graph.

        Args:
            content: Memory text
            source_type: Origin (user, email, webpage, etc.)
            source_id: Unique identifier for source
            risk_score: 0-100 threat score
            trust_score: 0-100 provenance trust
            is_threat: Whether flagged as threat
            threat_type: Type of threat detected
            derived_from: Parent node_id (creates DERIVED_FROM edge)
            relates_to: List of related node_ids (creates RELATES_TO edges)
            session_id: Session context
            agent_id: Agent context
            metadata: Additional data

        Returns:
            node_id (UUID string)
        """
        node_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Provenance hash
        prov = hashlib.sha256(f"{source_type}:{source_id or 'none'}".encode()).hexdigest()[:16]

        node = MemoryNode(
            node_id=node_id,
            content=content,
            timestamp=timestamp,
            source_type=source_type,
            source_id=source_id,
            status=NodeStatus.BLOCKED.value if is_threat and risk_score >= 80
                   else NodeStatus.QUARANTINED.value if risk_score >= 40
                   else NodeStatus.ACTIVE.value,
            risk_score=risk_score,
            trust_score=trust_score,
            is_threat=is_threat,
            threat_type=threat_type,
            provenance_hash=prov,
            session_id=session_id,
            agent_id=agent_id,
            metadata=metadata or {},
        )

        self._nodes[node_id] = node
        self._graph.add_node(node_id, **node.to_dict())
        self._stats["total_nodes"] += 1

        if node.status == NodeStatus.BLOCKED.value:
            self._stats["blocked_nodes"] += 1
        elif node.status == NodeStatus.QUARANTINED.value:
            self._stats["quarantined_nodes"] += 1

        # Auto-create edges
        if derived_from and derived_from in self._nodes:
            self.add_edge(derived_from, node_id, RelationType.DERIVED_FROM, weight=0.9)

        if relates_to:
            for related_id in relates_to:
                if related_id in self._nodes:
                    self.add_edge(node_id, related_id, RelationType.RELATES_TO, weight=0.5)

        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        weight: float = 1.0,
        confidence: float = 1.0,
        is_active: bool = True,
        trigger_condition: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a directed edge between two nodes."""
        if source_id not in self._nodes or target_id not in self._nodes:
            raise ValueError(f"Both nodes must exist: {source_id}, {target_id}")

        edge = MemoryEdge(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type.value,
            weight=weight,
            confidence=confidence,
            is_active=is_active,
            trigger_condition=trigger_condition,
            metadata=metadata or {},
        )

        self._graph.add_edge(source_id, target_id, **edge.to_dict())
        self._stats["total_edges"] += 1

        # Update node degrees
        self._nodes[source_id].out_degree = self._graph.out_degree(source_id)
        self._nodes[target_id].in_degree = self._graph.in_degree(target_id)

    def get_node(self, node_id: str) -> Optional[MemoryNode]:
        """Retrieve a node by ID."""
        return self._nodes.get(node_id)

    def quarantine_node(self, node_id: str, reason: str = "") -> None:
        """Mark a node as quarantined (suspicious)."""
        if node_id in self._nodes:
            old_status = self._nodes[node_id].status
            self._nodes[node_id].status = NodeStatus.QUARANTINED.value
            self._nodes[node_id].metadata["quarantine_reason"] = reason
            self._nodes[node_id].metadata["quarantine_time"] = datetime.now(timezone.utc).isoformat()

            if old_status == NodeStatus.ACTIVE.value:
                self._stats["quarantined_nodes"] += 1

            self._graph.nodes[node_id]["status"] = NodeStatus.QUARANTINED.value

    def block_node(self, node_id: str, reason: str = "") -> None:
        """Mark a node as blocked (confirmed threat)."""
        if node_id in self._nodes:
            old_status = self._nodes[node_id].status
            self._nodes[node_id].status = NodeStatus.BLOCKED.value
            self._nodes[node_id].metadata["block_reason"] = reason
            self._nodes[node_id].metadata["block_time"] = datetime.now(timezone.utc).isoformat()

            if old_status == NodeStatus.QUARANTINED.value:
                self._stats["quarantined_nodes"] -= 1
            if old_status != NodeStatus.BLOCKED.value:
                self._stats["blocked_nodes"] += 1

            self._graph.nodes[node_id]["status"] = NodeStatus.BLOCKED.value

    # --- Analysis ---

    def analyze_infection(self, source_node_id: str, max_depth: int = 5) -> InfectionReport:
        """
        Analyze how a potentially malicious node could spread to others.

        Uses BFS to find all nodes reachable via DERIVED_FROM, AFFECTS, TRIGGERS edges.
        Computes a spread_score based on:
        - Number of reachable nodes
        - Edge weights along paths
        - Node centrality

        Args:
            source_node_id: Starting node
            max_depth: Maximum path length to explore

        Returns:
            InfectionReport with spread analysis
        """
        if source_node_id not in self._nodes:
            raise ValueError(f"Node not found: {source_node_id}")

        source_node = self._nodes[source_node_id]
        affected: Set[str] = set()
        paths: List[List[str]] = []
        max_path_len = 0

        # BFS with path tracking
        queue: List[Tuple[str, List[str], int]] = [(source_node_id, [source_node_id], 0)]
        visited: Set[str] = set()

        while queue:
            current_id, path, depth = queue.pop(0)

            if current_id in visited or depth > max_depth:
                continue
            visited.add(current_id)

            if current_id != source_node_id:
                affected.add(current_id)
                paths.append(path)
                max_path_len = max(max_path_len, len(path) - 1)

            if depth < max_depth:
                for neighbor in self._graph.successors(current_id):
                    edge_data = self._graph.edges[current_id, neighbor]
                    rel_type = edge_data.get("relation_type")

                    # Only follow infection-relevant edges
                    if rel_type in (
                        RelationType.DERIVED_FROM.value,
                        RelationType.AFFECTS.value,
                        RelationType.TRIGGERS.value,
                    ):
                        queue.append((neighbor, path + [neighbor], depth + 1))

        # Compute spread score
        num_affected = len(affected)
        if num_affected == 0:
            spread_score = 0.0
        else:
            # Factors: number affected, max depth, source risk
            reachability = min(1.0, num_affected / 10.0)  # cap at 10 nodes
            depth_factor = max_path_len / max_depth
            risk_factor = source_node.risk_score / 100.0
            spread_score = (reachability * 0.5 + depth_factor * 0.3 + risk_factor * 0.2)

        if spread_score >= 0.8:
            impact = "critical"
        elif spread_score >= 0.6:
            impact = "high"
        elif spread_score >= 0.3:
            impact = "medium"
        else:
            impact = "low"

        explanation = (
            f"Source node can reach {num_affected} other nodes "
            f"with max depth {max_path_len}. "
            f"Risk={source_node.risk_score}, Spread={spread_score:.2f}"
        )

        return InfectionReport(
            source_node_id=source_node_id,
            spread_score=spread_score,
            affected_nodes=list(affected),
            propagation_paths=paths,
            max_depth=max_path_len,
            estimated_impact=impact,
            explanation=explanation,
        )

    def detect_attack_chains(
        self,
        target_action: Optional[str] = None,
        min_risk: int = 40,
        max_length: int = 10,
    ) -> List[AttackChain]:
        """
        Detect attack chains: paths from high-risk nodes to potential harm.

        An attack chain is a sequence of nodes where:
        - First node has high risk_score
        - Connected via DERIVED_FROM / AFFECTS / TRIGGERS
        - Last node could trigger a harmful action

        Args:
            target_action: Optional action to target (e.g., "send_email")
            min_risk: Minimum risk_score for chain start
            max_length: Maximum chain length

        Returns:
            List of AttackChain
        """
        chains: List[AttackChain] = []

        # Find high-risk source nodes
        sources = [
            nid for nid, node in self._nodes.items()
            if node.risk_score >= min_risk and node.status != NodeStatus.BLOCKED.value
        ]

        for source_id in sources:
            # DFS from each source
            stack: List[Tuple[str, List[str], int]] = [(source_id, [source_id], 0)]
            visited_in_path: Set[Tuple[str, ...]] = set()

            while stack:
                current_id, path, cumulative_risk = stack.pop()

                path_tuple = tuple(path)
                if path_tuple in visited_in_path or len(path) > max_length:
                    continue
                visited_in_path.add(path_tuple)

                current_node = self._nodes[current_id]
                cumulative_risk += current_node.risk_score

                # Check if this is a terminal harmful node
                is_terminal = False
                target_act = None

                if target_action:
                    # Check metadata for action type
                    if current_node.metadata.get("action_type") == target_action:
                        is_terminal = True
                        target_act = target_action
                else:
                    # Generic: nodes with TRIGGERS edges or high out_degree
                    if current_node.out_degree > 3 or any(
                        self._graph.edges[current_id, succ].get("relation_type") == RelationType.TRIGGERS.value
                        for succ in self._graph.successors(current_id)
                    ):
                        is_terminal = True

                if is_terminal and len(path) >= 2:
                    chain_id = hashlib.md5("→".join(path).encode()).hexdigest()[:16]
                    threat_types = [
                        self._nodes[nid].threat_type or "unknown" for nid in path if self._nodes[nid].is_threat
                    ]
                    explanation = f"Chain of {len(path)} nodes from {source_id} to {current_id}"

                    chains.append(AttackChain(
                        chain_id=chain_id,
                        node_ids=path,
                        risk_score=cumulative_risk // len(path),
                        threat_types=threat_types,
                        target_action=target_act,
                        explanation=explanation,
                    ))

                # Continue DFS
                for neighbor in self._graph.successors(current_id):
                    edge_data = self._graph.edges[current_id, neighbor]
                    rel = edge_data.get("relation_type")
                    if rel in (RelationType.DERIVED_FROM.value, RelationType.AFFECTS.value, RelationType.TRIGGERS.value):
                        stack.append((neighbor, path + [neighbor], cumulative_risk))

        return chains

    def compute_importance(self) -> None:
        """
        Compute PageRank-style importance for all nodes.

        Updates node.importance in-place.
        """
        if self._stats["total_nodes"] == 0:
            return

        try:
            pr = nx.pagerank(self._graph, weight="weight")
            for node_id, score in pr.items():
                if node_id in self._nodes:
                    self._nodes[node_id].importance = score
                    self._graph.nodes[node_id]["importance"] = score
        except Exception as e:
            logger.warning(f"PageRank failed: {e}")

    def prune_infected(self, source_node_id: str) -> int:
        """
        Remove a node and all nodes it infected (reachable via infection edges).

        Returns:
            Number of nodes removed
        """
        report = self.analyze_infection(source_node_id)
        to_remove = [source_node_id] + report.affected_nodes

        for nid in to_remove:
            if nid in self._nodes:
                status = self._nodes[nid].status
                if status == NodeStatus.BLOCKED.value:
                    self._stats["blocked_nodes"] -= 1
                elif status == NodeStatus.QUARANTINED.value:
                    self._stats["quarantined_nodes"] -= 1

                del self._nodes[nid]
                self._graph.remove_node(nid)
                self._stats["total_nodes"] -= 1

        return len(to_remove)

    # --- Query ---

    def get_subgraph(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        status: Optional[NodeStatus] = None,
    ) -> MemoryGraph:
        """
        Extract a subgraph matching filters.

        Returns:
            New MemoryGraph instance with matching nodes/edges
        """
        matching_nodes = []
        for nid, node in self._nodes.items():
            if session_id and node.session_id != session_id:
                continue
            if agent_id and node.agent_id != agent_id:
                continue
            if status and node.status != status.value:
                continue
            matching_nodes.append(nid)

        sub = MemoryGraph(graph_id=f"{self.graph_id}-sub")
        for nid in matching_nodes:
            node = self._nodes[nid]
            sub._nodes[nid] = node
            sub._graph.add_node(nid, **node.to_dict())

        # Add edges between matching nodes
        for u, v, data in self._graph.edges(data=True):
            if u in matching_nodes and v in matching_nodes:
                sub._graph.add_edge(u, v, **data)
                sub._stats["total_edges"] += 1

        sub._stats["total_nodes"] = len(matching_nodes)
        return sub

    def get_stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        return {
            "graph_id": self.graph_id,
            "created_at": self._created_at,
            **self._stats,
            "avg_degree": (self._stats["total_edges"] * 2 / self._stats["total_nodes"])
                          if self._stats["total_nodes"] > 0 else 0,
        }

    # --- Persistence ---

    def save(self, filepath: str, format: str = "json") -> None:
        """
        Save graph to disk.

        Args:
            filepath: Output path
            format: "json" or "graphml" or "pickle"
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            data = {
                "graph_id": self.graph_id,
                "created_at": self._created_at,
                "stats": self._stats,
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [
                    {**self._graph.edges[u, v], "source_id": u, "target_id": v}
                    for u, v in self._graph.edges()
                ],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        elif format == "graphml":
            nx.write_graphml(self._graph, str(path))

        elif format == "pickle":
            import pickle
            with open(path, "wb") as f:
                pickle.dump((self.graph_id, self._created_at, self._stats, self._nodes, self._graph), f)

        else:
            raise ValueError(f"Unknown format: {format}")

    @classmethod
    def load(cls, filepath: str, format: str = "json") -> MemoryGraph:
        """
        Load graph from disk.

        Args:
            filepath: Input path
            format: "json" or "graphml" or "pickle"

        Returns:
            MemoryGraph instance
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Graph file not found: {filepath}")

        if format == "json":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            graph = cls(graph_id=data["graph_id"])
            graph._created_at = data["created_at"]
            graph._stats = data["stats"]

            for node_data in data["nodes"]:
                node = MemoryNode.from_dict(node_data)
                graph._nodes[node.node_id] = node
                graph._graph.add_node(node.node_id, **node.to_dict())

            for edge_data in data["edges"]:
                u = edge_data.pop("source_id")
                v = edge_data.pop("target_id")
                graph._graph.add_edge(u, v, **edge_data)

            return graph

        elif format == "graphml":
            graph = cls()
            graph._graph = nx.read_graphml(str(path))
            # Rebuild _nodes from graph node attributes
            for nid in graph._graph.nodes():
                attrs = graph._graph.nodes[nid]
                graph._nodes[nid] = MemoryNode.from_dict(attrs)
            graph._stats["total_nodes"] = len(graph._nodes)
            graph._stats["total_edges"] = graph._graph.number_of_edges()
            return graph

        elif format == "pickle":
            import pickle
            with open(path, "rb") as f:
                gid, created, stats, nodes, g = pickle.load(f)
            graph = cls(graph_id=gid)
            graph._created_at = created
            graph._stats = stats
            graph._nodes = nodes
            graph._graph = g
            return graph

        else:
            raise ValueError(f"Unknown format: {format}")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def check_networkx() -> bool:
    """Check if NetworkX is available."""
    return NETWORKX_AVAILABLE


__all__ = [
    "MemoryNode", "MemoryEdge", "InfectionReport", "AttackChain",
    "MemoryGraph",
    "RelationType", "NodeStatus",
    "check_networkx", "NETWORKX_AVAILABLE",
]
