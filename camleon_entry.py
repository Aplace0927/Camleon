import os
import sys

import idaapi
import ida_kernwin


class CamleonPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Camleon: OCaml analysis plugin for IDA Pro"
    help = "Camleon: OCaml analysis plugin for IDA Pro"
    wanted_name = "Camleon"
    wanted_hotkey = ""

    def init(self):
        print("Camleon plugin initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("Camleon plugin running")


def PLUGIN_ENTRY():
    return CamleonPlugin()
