from lib.cuckoo.common.abstracts import Signature

import re

class InfostealerAzorultNetwork(Signature):
    name = "infostealer_azorult_network"
    description = "Potential AZORult C&C check-in identified"
    severity = 3
    confidence = 2
    categories = ["infostealer"]
    authors = ["Brae","Alwin"]
    minimum = "2.0"

    user_agent =  "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"
    keys = [(0x3, 0x55, 0xae), (0xfe, 0x29, 0x36), (0xd, 0xa, 0xc8)]

    def decrypt_req(self, hash_str, key):
        out_str = ""
        for i in xrange(len(hash_str)):
            out_str += chr(ord(hash_str[i]) ^ key[i % len(key)])
        return out_str

    def on_complete(self):
        for http in self.get_results("network", {}).get("http", []):
            if http['method'] == "POST" and "index.php" in http['uri']:
                if http['user-agent'] == self.user_agent:
                    self.mark_ioc("network", http['uri'])
                # Extract request data and decrypt for infected user 'ID'
                body = http['body']
                for key in self.keys:
                    plaintext = self.decrypt_req(body, key)
                    if re.match(r".*([A-Z0-9]{8}-){4}", plaintext):
                        self.mark_ioc("checkin", plaintext)
                    
                   
        return self.has_marks() 
