# Copyright (C) 2016 Justaguy @ Cybersprint B.V.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class KovterBot(Signature):
    name = "bot_kovter"
    description = "Performs HTTP requests like Kovter"
    severity = 3
    categories = ["http"]
    authors = ["Brae"]
    minimum = "2.0"
    families = ["kovter"]

    def on_complete(self):
        # 1. Check through dropped files for strange file extensions (5 or more chars?)
        for dropped in self.get_results("dropped", []):
            name_parts = dropped['name'].split('.')
            self.extension = name_parts[len(name_parts)-1]
            if re.match(r"[a-zA-Z0-9]{5,}", self.extension):
                self.mark_ioc("file",dropped['filepath'])                

        # 2. Check through registry creations (HKEY_CLASSES_ROOT\) for keys with the same name as the file extension
        for regkey in self.check_key(pattern=r"HKEY_CLASSES_ROOT\\\." + self.extension, regex=True, actions=["regkey_written"], all=True):
            

        # 3. Check through run keys for new .bat files or .lnk files in AppData or LocalAppData

            # 3.1 Identify dropped bat or lnk file


        return self.has_marks()
