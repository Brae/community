# Copyright (C) 2016 Kevin Ross.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature
import re

class PDFJavaScript(Signature):
    name = "pdf_javascript"
    description = "The PDF file contains JavaScript code"
    severity = 3
    confidence = 3
    categories = ["static"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    re_annots = [
        r"[']{0,}g[ '+]{1,}e[ '+]{0,}t[ '+]{0,}A[ '+]{0,}(n[ '+]{0,}){2}o[ '+]{0,}t[ '+]{0,}s[ '+]{0,}",
        r"[']{0,}s[ '+]{0,}y[ '+]{0,}n[ '+]{0,}c[ '+]{0,}A[ '+]{0,}n[ '+]{0,}n[ '+]{0,}o[ '+]{0,}t[ '+]{0,}S[ '+]{0,}c[ '+]{0,}a[ '+]{0,}n[ '+]{0,}"
    ]

    def on_complete(self):
        for pdf in self.get_results("static", {}).get("pdf", {}):
            if "javascript" in pdf and len(pdf["javascript"]) > 0:
                for js in pdf["javascript"]:
					for re_ex in self.re_annots:
						mtch = re.search(re_ex, js["beautified"]):
						if mtch:
							self.severity = 3
							self.description = "The PDF file contains \
								JavaScript with functions commonly used \
								for obfuscation/exploitation"
							self.mark_ioc("Javascript code", js["beautified"])
						else:
							self.mark_ioc("Javascript code", js["beautified"])
                return True

class PDFAttachments(Signature):
    name = "pdf_attachments"
    description = "The PDF file contains an attachment"
    severity = 2
    categories = ["static"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_complete(self):
        for pdf in self.get_results("static", {}).get("pdf", {}):
            if "attachments" in pdf and len(pdf["attachments"]) > 0:
                for att in pdf["attachments"]:
                    self.mark_ioc("Attached file", att["filename"])
                return True

class PDFOpenAction(Signature):
    name = "pdf_openaction"
    description = "The PDF file contains an open action"
    severity = 2
    confidence = 2
    categories = ["static"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_complete(self):
        for pdf in self.get_results("static", {}).get("pdf", {}):
            if "openaction" in pdf and pdf["openaction"]:
                self.mark_ioc("Open action", pdf["openaction"])
                return True

class PDFOpenActionJS(Signature):
    name = "pdf_openaction_js"
    description = "The PDF open action contains JavaScript code"
    severity = 3
    confidence = 3
    categories = ["static"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_complete(self):
        for pdf in self.get_results("static", {}).get("pdf", {}):
            if ("openaction" in pdf and pdf["openaction"] and 
                    ("/JavaScript" in pdf["openaction"] or "/JS" in pdf["openaction"])):
                self.mark_ioc("Open action", pdf["openaction"])
                return True
