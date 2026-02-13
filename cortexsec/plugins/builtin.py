from __future__ import annotations

from typing import Any, Dict

from cortexsec.plugins.base import PluginContext, SecurityPlugin
from cortexsec.tools import NmapAdapter, ZapAdapter


class NmapPlugin(SecurityPlugin):
    plugin_id = "scanner.nmap"

    def __init__(self) -> None:
        self._adapter = NmapAdapter()

    def run(self, context: PluginContext) -> Dict[str, Any]:
        return self._adapter.invoke({"tool": "nmap", "target": context.request.target, "options": "-sV -Pn", "safe_mode": context.request.safe_mode})


class ZapPlugin(SecurityPlugin):
    plugin_id = "scanner.zap"

    def __init__(self) -> None:
        self._adapter = ZapAdapter()

    def run(self, context: PluginContext) -> Dict[str, Any]:
        return self._adapter.invoke({"tool": "zap", "target": context.request.target, "options": "", "safe_mode": context.request.safe_mode})
