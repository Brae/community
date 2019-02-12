from lib.cuckoo.common.abstracts import Signature
import re

class CerberNetwork(Signature):
    name = "ransomware_cerber"
    description = "Found behaviour indicative of Cerber Ransomware"
    severity = 3
    categories = ["ransomware"]
    families = ["cerber"]
    authors = ["Brae"]
    minimum = "2.0"

    re_uri = [
        r".*\/v1\/btc\/addrs\/.*",
        r".*\/api\/v1\/address\/txs\/.*"
    ]

    re_machineguid = r".*\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"

    filter_apinames = "RegQueryValueExW"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.file_extension = ""

    def on_call(self, call, process):
        rkey = call["arguments"]["regkey"]
        if re.match(self.re_machineguid, rkey):
            guid = call["arguments"]["value"]
            if guid != "":
                self.file_extension = "." + guid.split("-")[3]

    def on_complete(self):
        for http in self.get_results("network", {}).get("http", []):
            for regx in self.re_uri:
                if re.match(regx, http['uri']):
                    self.mark_ioc("url", http['uri'])

        if self.file_extension != "":
            for dropped in self.get_results("dropped", []):
                if "filepath" in dropped:
                    if dropped["filepath"].endswith(self.file_extension):
                        self.mark_ioc("encrypted file", dropped["filepath"])

        return self.has_marks()    
