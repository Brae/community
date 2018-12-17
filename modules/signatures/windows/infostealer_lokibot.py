from lib.cuckoo.common.abstracts import Signature

class UA_LokiBot(Signature):
    name = "infostealer_lokibot"
    description = "Detected User Agent associated specific to LokiBot malware family"
    severity = 5
    categories = ["network"]
    authors = ["brae"]
    minimum = "2.0"

    user_agent = "Mozilla/4.08 (Charon; Inferno)"

    def on_complete(self):
        urls = []
        for http in self.get_net_http():
            if http.get("user-agent", "") == self.user_agent:
                urls.append(http.get("uri", "")

        if len(urls) > 0:
            self.mark_config({
                "family":"Loki-Bot information stealer detected",
                "url":urls,
                "type":"Steals credentials and CryptoCoin wallets"
            })
