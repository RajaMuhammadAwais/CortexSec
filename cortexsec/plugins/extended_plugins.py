from __future__ import annotations
from typing import Any, Dict
from cortexsec.plugins.base import PluginContext, SecurityPlugin
from cortexsec.tools import NucleiAdapter, SqlmapAdapter, NiktoAdapter, GobusterAdapter

class NucleiPlugin(SecurityPlugin):
    plugin_id = "scanner.nuclei"
    def __init__(self) -> None:
        self._adapter = NucleiAdapter()
    def run(self, context: PluginContext) -> Dict[str, Any]:
        return self._adapter.invoke({"tool": "nuclei", "target": context.request.target, "options": ""})

class SqlmapPlugin(SecurityPlugin):
    plugin_id = "scanner.sqlmap"
    def __init__(self) -> None:
        self._adapter = SqlmapAdapter()
    def run(self, context: PluginContext) -> Dict[str, Any]:
        return self._adapter.invoke({"tool": "sqlmap", "target": context.request.target, "options": ""})

class NiktoPlugin(SecurityPlugin):
    plugin_id = "scanner.nikto"
    def __init__(self) -> None:
        self._adapter = NiktoAdapter()
    def run(self, context: PluginContext) -> Dict[str, Any]:
        return self._adapter.invoke({"tool": "nikto", "target": context.request.target, "options": ""})

class GobusterPlugin(SecurityPlugin):
    plugin_id = "scanner.gobuster"
    def __init__(self) -> None:
        self._adapter = GobusterAdapter()
    def run(self, context: PluginContext) -> Dict[str, Any]:
        return self._adapter.invoke({"tool": "gobuster", "target": context.request.target, "options": ""})
