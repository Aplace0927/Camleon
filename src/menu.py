from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

import idaapi
import ida_kernwin
import tomllib


@dataclass(slots=True)
class MenuNode:
    key: str
    label: str
    action_key: str | None = None
    shortcut: str = ""
    tooltip: str = ""
    children: list["MenuNode"] = field(default_factory=list)


@dataclass(slots=True)
class ActionSpec:
    key: str
    name: str
    label: str
    handler_ref: str
    shortcut: str = ""
    tooltip: str = ""

@dataclass
class IDAAction:
    def __init__(
        self,
        name: str,
        label: str,
        handler: Callable,
        shortcut: str = "",
        tooltip: str = ""
    ) -> None:
        self.name = name
        self.label = label
        self.handler = handler
        self.shortcut = shortcut
        self.tooltip = tooltip



class CallableActionHandler(idaapi.action_handler_t):
    def __init__(self, callback: Callable):
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class MenuManager:
    _MENU_META_KEYS = {"name", "label", "action", "shortcut", "tooltip"}

    def __init__(self, config_dir: str | Path):
        if isinstance(config_dir, str):
            config_dir = Path(config_dir)
        self.config_dir = config_dir
        self.menu_config = self._load_toml(config_dir / "menu.toml")
        self.action_config = self._load_toml(config_dir / "actions.toml")
        self.root_menu = str(self.menu_config.get("root", "")).strip().strip("/")
        self.action_specs = self._parse_action_specs(self.action_config)
        self.menu_tree = self._parse_menu_tree(self.menu_config)

    def _load_toml(self, file_path: Path) -> Mapping[str, object]:
        with open(file_path, "rb") as f:
            return tomllib.load(f)

    def _parse_action_specs(self, table: Mapping[str, object]) -> dict[str, ActionSpec]:
        actions: dict[str, ActionSpec] = {}
        for key, value in table.items():
            if not isinstance(value, Mapping):
                continue
            actions[key] = ActionSpec(
                key=key,
                name=str(value.get("name") or key),
                label=str(value.get("label") or key),
                handler_ref=str(value.get("handler") or key),
                shortcut=str(value.get("shortcut") or ""),
                tooltip=str(value.get("tooltip") or ""),
            )
        return actions

    def _parse_menu_tree(self, table: Mapping[str, object]) -> list[MenuNode]:
        nodes: list[MenuNode] = []
        for key, value in table.items():
            if key == "root":
                continue
            if not isinstance(value, Mapping):
                continue
            nodes.append(self._parse_menu_node(key, value))
        return nodes

    def _parse_menu_node(self, key: str, table: Mapping[str, object]) -> MenuNode:
        label = str(table.get("name") or table.get("label") or key)
        action_key = table.get("action")
        shortcut = str(table.get("shortcut") or "")
        tooltip = str(table.get("tooltip") or "")
        children: list[MenuNode] = []

        for child_key, child_value in table.items():
            if child_key in self._MENU_META_KEYS:
                continue
            if isinstance(child_value, Mapping):
                children.append(self._parse_menu_node(child_key, child_value))

        return MenuNode(
            key=key,
            label=label,
            action_key=str(action_key) if action_key else None,
            shortcut=shortcut,
            tooltip=tooltip,
            children=children,
        )

    def _menu_path(self, labels: list[str]) -> str:
        path_parts = [part.strip("/") for part in labels if part]
        if self.root_menu:
            path_parts.insert(0, self.root_menu)
        return "/".join(path_parts)

    def _menu_parent_path(self, labels: list[str]) -> str:
        parent_path = self._menu_path(labels)
        if not parent_path:
            return ""
        return parent_path if parent_path.endswith("/") else f"{parent_path}/"

    def _menu_id(self, keys: list[str]) -> str:
        return "/".join(keys)

    def _register_menu_node(
        self,
        node: MenuNode,
        action_registry: Mapping[str, IDAAction],
        parent_labels: list[str] | None = None,
        parent_keys: list[str] | None = None,
    ) -> None:
        parent_labels = [] if parent_labels is None else parent_labels
        parent_keys = [] if parent_keys is None else parent_keys

        labels = [*parent_labels, node.label]
        keys = [*parent_keys, node.key]
        menu_path = self._menu_path(labels)

        if node.children:
            try:
                ida_kernwin.create_menu(self._menu_id(keys), node.label, self._menu_parent_path(parent_labels))
            except Exception:
                pass

        if node.action_key:
            action = action_registry.get(node.action_key)
            if action is None:
                raise KeyError(f"No action registered for '{node.action_key}'")
            self.register_action_to_menu(action, menu_path)

        for child in node.children:
            self._register_menu_node(child, action_registry, labels, keys)

    def iter_menu_paths(self):
        yield from self._iter_menu_paths(self.menu_tree)

    def _iter_menu_paths(
        self,
        nodes: list[MenuNode],
        parent_labels: list[str] | None = None,
    ):
        parent_labels = [] if parent_labels is None else parent_labels

        for node in nodes:
            labels = [*parent_labels, node.label]
            if node.children:
                yield self._menu_path(labels)
            if node.children:
                yield from self._iter_menu_paths(node.children, labels)

    def delete_menu_tree(self) -> None:
        for menu_path in reversed(list(self.iter_menu_paths())):
            try:
                ida_kernwin.delete_menu(menu_path)
            except Exception:
                pass

    def register_menu_tree(self, actions: Mapping[str, IDAAction]) -> None:
        for node in self.menu_tree:
            self._register_menu_node(node, actions)

    def _resolve_handler(self, handler_ref: str) -> Callable:
        if ":" not in handler_ref:
            raise ValueError(f"Invalid handler reference '{handler_ref}'")

        module_name, symbol_name = handler_ref.split(":", 1)
        module = importlib.import_module(module_name)
        callback = getattr(module, symbol_name)
        if not callable(callback):
            raise TypeError(f"Handler '{handler_ref}' is not callable")
        return callback

    def build_actions(self) -> dict[str, IDAAction]:
        actions: dict[str, IDAAction] = {}
        for key, spec in self.action_specs.items():
            handler = CallableActionHandler(self._resolve_handler(spec.handler_ref))
            actions[key] = IDAAction(
                name=spec.name,
                label=spec.label,
                handler=handler,
                shortcut=spec.shortcut,
                tooltip=spec.tooltip,
            )
        return actions

    def register_action_to_menu(self, action: IDAAction, menu_path: str):
        
        action_desc = idaapi.action_desc_t(
            action.name,
            action.label,
            action.handler,
            action.shortcut,
            action.tooltip,
        )
        idaapi.register_action(action_desc)
        ida_kernwin.attach_action_to_menu(menu_path, action.name, ida_kernwin.SETMENU_APP)

        return menu_path

    def unregister_action(self, action_name: str) -> None:
        idaapi.unregister_action(action_name)
