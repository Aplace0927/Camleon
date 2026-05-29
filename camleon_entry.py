import os
import sys
from pathlib import Path

import idaapi
import ida_kernwin

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PLUGIN_DIR, "src")
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from src.menu import MenuManager


class CamleonPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Camleon: OCaml analysis plugin for IDA Pro"
    help = "Camleon: OCaml analysis plugin for IDA Pro"
    wanted_name = "Camleon"
    wanted_hotkey = ""

    def init(self):
        print("Camleon Initialized")
        self._menu_manager = None
        self._actions = {}
        self._register_actions()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self._unregister_actions()

    def _register_actions(self):
        self._menu_manager = MenuManager(Path(PLUGIN_DIR) / "config")
        self._actions = self._menu_manager.build_actions()
        self._menu_manager.register_menu_tree(self._actions)

    def _unregister_actions(self):
        if self._menu_manager is None:
            return
        
        self._menu_manager.delete_menu_tree()
        for action in self._actions.values():
            self._menu_manager.unregister_action(action.name)

def PLUGIN_ENTRY():
    return CamleonPlugin()
