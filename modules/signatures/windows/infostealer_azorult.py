from lib.cuckoo.common.abstracts import Signature

import re

class InfostealerAzorultNetwork(Signature):
    name = "infostealer_azorult_network"
    description = "Potential AZORult C&C check-in identified"
    severity = 3
    confidence = 2
    categories = ["infostealer"]
    authors = ["Brae"]
    minimum = "2.0"

    user_agent =  "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"

    def on_complete(self):
        for http in self.get_results("network", {}).get("http_ex", []):
            if http['method'] == "POST" and "index.php" in http['uri']:
                req_ua = re.search(r"User-Agent\:[A-Za-z0-9\/\ \(\)\.\;]+", http['request'])
                if req_ua:
                    if req_ua.group() == self.user_agent:
                        self.mark_ioc("network", http['request'])
                    
