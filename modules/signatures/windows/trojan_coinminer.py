# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import re

class CoinminerMutexes(Signature):
    # Note the CoinMiner is not a family in the standard sense, more a collective term for trojans which leverage cryptomining capabilities (often adapted legit mining software)
    # Detection for these can be tricky depending on the environment - have the usual problem of dead C&C likely stopping us seeing the actual miner/payload, as well as some miners having built in anti-virtualisation which prevents running on many platforms. Relying here on fairly narrow indicators spotted in scripts, memory dumps etc.
    name = "coinminer_troj"
    description = "Shows signs of mining cryptocurrency"
    severity = 3
    categories = ["trojan"]
    families = ["coinminer"]
    authors = ["Redsocks","Brae"]
    references = [
        "https://www.symantec.com/security-center/writeup/2018-040903-3834-99#technicaldescription",
        "https://blog.trendmicro.com/trendlabs-security-intelligence/cryptocurrency-mining-malware-2018-new-menace/",
        "https://cloudblogs.microsoft.com/microsoftsecure/2018/03/13/invisible-resource-thieves-the-increasing-threat-of-cryptocurrency-miners/",
        "https://fortiguard.com/encyclopedia/virus/6368104",
    ]
    minimum = "2.0"

    mutexes_re = [
        ".*SamaelLovesMe",
    ]

    urls_re = [
        r".*xmrpool\.[a-z]{2,3}",
        r".*minexmr.[a-z]{2,3}",
        r".*pumpmywallet.com",
        r".*\/dyndns\/getip",
        r".*xmr5b\..*",
        r".*mymyxmra\..*",
        r"\/\/223\.\w+\.247\..*"
    ]

    xmr_address_re = '-u[ ]*4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}'
    xmr_strings = ["stratum+tcp://", "xmrig", "xmr-stak", "supportxmr.com:", "dwarfpool.com:", "minergate"]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        for dns in self.get_results("network", {}).get("dns", []):
            for url in self.urls_re:
                if re.match(re.compile(url, re.I), dns['request']):
                    self.mark_ioc("url", dns['request'])

        for cmdline in self.get_command_lines():
            if re.search(self.xmr_address_re, cmdline):
                self.mark_ioc("cmdline", cmdline)
            for xmr_string in self.xmr_strings:
                if xmr_string in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        if self.has_marks():
            self.mark_config({
                "family":"Coin Miner",
                "type":"Shows signs of a malicious cryptocurrency miner"
            })
            

        return self.has_marks()
