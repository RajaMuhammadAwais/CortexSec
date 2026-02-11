from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from cortexsec.api.contracts import AssessmentRequest


@dataclass
class PluginContext:
    request: AssessmentRequest
    shared_state: Dict[str, Any] = field(default_factory=dict)


class SecurityPlugin(ABC):
    """Plugin contract for scanners/analyzers/exploit modules."""

    plugin_id: str

    @abstractmethod
    def run(self, context: PluginContext) -> Dict[str, Any]:
        raise NotImplementedError


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, SecurityPlugin] = {}

    def register(self, plugin: SecurityPlugin) -> None:
        self._plugins[plugin.plugin_id] = plugin

    def get(self, plugin_id: str) -> SecurityPlugin:
        if plugin_id not in self._plugins:
            raise KeyError(f"plugin-not-registered:{plugin_id}")
        return self._plugins[plugin_id]

    def available(self) -> Iterable[str]:
        return self._plugins.keys()

    def run_many(self, plugin_ids: List[str], context: PluginContext) -> Dict[str, Any]:
        reports: Dict[str, Any] = {}
        for plugin_id in plugin_ids:
            reports[plugin_id] = self.get(plugin_id).run(context)
        return reports
