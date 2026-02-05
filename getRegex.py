# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem, JOptionPane
from java.util import ArrayList
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Regex Utility")
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        menu = ArrayList()

        menu.add(JMenuItem("Generate Regex", actionPerformed=lambda x: self.generate_regex(invocation, as_regextag=False)))
        menu.add(JMenuItem("Generate REGEXTAG Payload", actionPerformed=lambda x: self.generate_regex(invocation, as_regextag=True)))
        menu.add(JMenuItem("Extract Variable", actionPerformed=lambda x: self.extract_variable(invocation)))

        return menu

    # ----------------------------
    # Core: generate regex
    # ----------------------------
    def generate_regex(self, invocation, as_regextag=False):
        try:
            messages = invocation.getSelectedMessages()
            if not messages:
                self._callbacks.printError("No messages selected.")
                return

            message = messages[0]
            context = invocation.getInvocationContext()

            if context in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
                isRequest = True
            elif context in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
                isRequest = False
            else:
                self._callbacks.printError("Unsupported context.")
                return

            offsets = invocation.getSelectionBounds()
            if not offsets or len(offsets) != 2:
                self._callbacks.printError("No text selected.")
                return

            start, end = offsets
            if start == end:
                self._callbacks.printError("No text selected (empty selection).")
                return

            if isRequest:
                data = message.getRequest()
                if data is None:
                    self._callbacks.printError("No request data.")
                    return
                analyzed = self._helpers.analyzeRequest(data)
            else:
                data = message.getResponse()
                if data is None:
                    self._callbacks.printError("No response data.")
                    return
                analyzed = self._helpers.analyzeResponse(data)

            data_str = self._helpers.bytesToString(data)
            selected_text = data_str[start:end]

            body_offset = analyzed.getBodyOffset()
            body = data_str[body_offset:]

            regex = None

            if end <= body_offset:
                # Selection in headers
                headers_str = data_str[:body_offset]
                headers_list = headers_str.split('\r\n')

                current_pos = 0
                selected_header = None
                for header in headers_list:
                    header_len = len(header) + 2  # \r\n
                    if start >= current_pos and end <= current_pos + header_len:
                        selected_header = header
                        break
                    current_pos += header_len

                if not selected_header:
                    self._callbacks.printError("Selection does not fall within any header.")
                    return

                regex = self.generate_header_regex(selected_header, selected_text)
            else:
                # Selection in body
                regex = self.generate_context_regex(body, selected_text)
                if not regex:
                    regex = self.generate_general_regex(data_str, selected_text, start, end)

            if not regex:
                self._callbacks.printError("Failed to generate regex.")
                return

            regex_with_newline = regex.replace("{{NEWLINE}}", "\\n")

            if as_regextag:
                payload = u"[REGEXTAG={{{%s}}}]" % regex_with_newline
                self.copy_to_clipboard(payload)
                JOptionPane.showMessageDialog(None, u"Generated REGEXTAG payload (copied):\n%s" % payload)
                self._callbacks.printOutput("Generated REGEXTAG payload: %s" % payload)
            else:
                self.copy_to_clipboard(regex_with_newline)
                JOptionPane.showMessageDialog(None, u"Generated regex (copied):\n%s" % regex_with_newline)
                self._callbacks.printOutput("Generated regex: %s" % regex_with_newline)

        except Exception as e:
            self._callbacks.printError("Error generating regex: %s" % str(e))

    # ----------------------------
    # Clipboard
    # ----------------------------
    def copy_to_clipboard(self, text):
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(text), None)
        except Exception as e:
            self._callbacks.printError("Error copying to clipboard: %s" % str(e))

    # ----------------------------
    # Header regex generation (FIXED for Jython + Location paths)
    # ----------------------------
    def generate_header_regex(self, header_line, selected_text):
        """
        Makes a regex that extracts the selected_text from a header line.
        Fixes:
          - no (?i:...) (Jython can throw 'unknown extension')
          - allows path prefixes by adding .*? after header start
        """
        try:
            if ':' not in header_line:
                return None

            sep = header_line.index(':')
            header_name = header_line[:sep].strip()
            header_value = header_line[sep+1:].lstrip(' \t').rstrip("\r\n")

            sel = (selected_text or "").strip()
            if not sel:
                return None

            escaped_sel = re.escape(sel)
            m = re.search(escaped_sel, header_value)
            if not m:
                self._callbacks.printError("Selected text not found in header value.")
                return None

            start_index = m.start()
            end_index = m.end()

            context_size = 20
            prefix_start = max(0, start_index - context_size)
            suffix_end = min(len(header_value), end_index + context_size)

            prefix = header_value[prefix_start:start_index]
            suffix = header_value[end_index:suffix_end]

            prefix_escaped = re.escape(prefix)
            suffix_escaped = re.escape(suffix)

            # KEY: .*? after header start so it matches Location: /post/comment/...
            # Also: only (?m) here, IGNORECASE is applied in Extract Variable anyway.
            header_name_escaped = re.escape(header_name)
            regex = r"(?m)^%s:\s*.*?%s(.*?)%s\s*$" % (header_name_escaped, prefix_escaped, suffix_escaped)
            return regex

        except Exception as e:
            self._callbacks.printError("Error generating header regex: %s" % str(e))
            return None

    # ----------------------------
    # Body regex generation
    # ----------------------------
    def generate_context_regex(self, body, selected_text):
        try:
            escaped_selected_text = re.escape((selected_text or "").strip())
            if not escaped_selected_text:
                return None

            match = re.search(escaped_selected_text, body, re.DOTALL)
            if not match:
                self._callbacks.printError("Selected text not found in response body.")
                return None

            start_index = match.start()
            end_index = match.end()

            context_size = 30
            prefix_start = max(0, start_index - context_size)
            suffix_end = min(len(body), end_index + context_size)

            prefix = body[prefix_start:start_index]
            suffix = body[end_index:suffix_end]

            prefix = re.escape(prefix).replace("\\n", "{{NEWLINE}}").replace("\\r", "{{NEWLINE}}").replace("\\t", "{{NEWLINE}}").replace("\n", "{{NEWLINE}}")
            suffix = re.escape(suffix).replace("\\n", "{{NEWLINE}}").replace("\\r", "{{NEWLINE}}").replace("\\t", "{{NEWLINE}}").replace("\n", "{{NEWLINE}}")

            return "{}(.*?){}".format(prefix, suffix)
        except Exception as e:
            self._callbacks.printError("Error generating context regex: %s" % str(e))
            return None

    def generate_general_regex(self, data_str, selected_text, start, end):
        try:
            context_size = 10
            prefix_start = max(0, start - context_size)
            suffix_end = min(len(data_str), end + context_size)

            prefix = data_str[prefix_start:start]
            suffix = data_str[end:suffix_end]

            return "{}(.*?){}".format(re.escape(prefix), re.escape(suffix))
        except Exception as e:
            self._callbacks.printError("Error generating general regex: %s" % str(e))
            return None

    # ----------------------------
    # Extract variable
    # ----------------------------
    def extract_variable(self, invocation):
        try:
            regex_pattern = JOptionPane.showInputDialog("Enter the regex pattern (or full [REGEXTAG=...]):")
            if not regex_pattern or regex_pattern.strip() == "":
                self._callbacks.printError("No regex pattern provided.")
                return

            # Allow pasting full payload:
            # [REGEXTAG={{{...}}}]
            m = re.match(r'^\[REGEXTAG=\{\{\{(.*)\}\}\}\]$', regex_pattern, re.DOTALL)
            if m:
                regex_pattern = m.group(1)

            messages = invocation.getSelectedMessages()
            if not messages:
                self._callbacks.printError("No messages selected.")
                return

            message = messages[0]
            data = message.getResponse()
            if data is None:
                self._callbacks.printError("No response data.")
                return

            data_str = self._helpers.bytesToString(data)

            # Compile first so we can show a clean error if regex is invalid in Jython
            try:
                compiled = re.compile(regex_pattern, re.DOTALL | re.IGNORECASE | re.MULTILINE)
            except Exception as rex:
                JOptionPane.showMessageDialog(None, "Regex compile error:\n%s" % str(rex))
                self._callbacks.printError("Regex compile error: %s" % str(rex))
                return

            matches = compiled.findall(data_str)
            if matches:
                extracted_value = matches[0]
                if isinstance(extracted_value, tuple):
                    extracted_value = ''.join(extracted_value)

                if regex_pattern.endswith("$"):
                    extracted_value = extracted_value.split("\r\n", 1)[0]

                JOptionPane.showMessageDialog(None, "Extracted value:\n%s" % extracted_value)
                self._callbacks.printOutput("Extracted value:\n%s" % extracted_value)
            else:
                JOptionPane.showMessageDialog(None, "No matches found.")
                self._callbacks.printOutput("No matches found.")

        except Exception as e:
            self._callbacks.printError("Error extracting variable: %s" % str(e))
        return
