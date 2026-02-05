# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab

from javax.swing import JPanel, JScrollPane, JMenuItem, JOptionPane
from javax.swing import JEditorPane
from java.awt import BorderLayout
from java.util import ArrayList
import re
import json

class BurpExtender(IBurpExtender, IContextMenuFactory, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Colored EI + Pretty + EI-PAYLOAD + Hackvertor Tags")

        # 1) Menu kontekstowe (manipulacja EI-PAYLOAD + opcjonalny hackvertor tag)
        callbacks.registerContextMenuFactory(self)

        # 2) Zakładka EI
        callbacks.registerMessageEditorTabFactory(self)

        # Hackvertor tags list
        # Uwaga: Hackvertor ma sporo tagów – tutaj jest komplet “sensownych”, plus Custom…
        # Jeśli chcesz „100% wszystkie”, najlepsza droga to podpięcie pod plik konfiguracyjny / export z Hackvertora.
        self._hackvertor_tags = [
            "(none)",
            "burp_urlencode",
            "burp_urldecode",
            "js_string",
            "burp_double_urlencode",
            "burp_base64encode",
            "burp_base64decode",
            "burp_htmlencode",
            "burp_htmldecode",
            "burp_hexencode",
            "burp_hexdecode",
            "burp_md5",
            "burp_sha1",
            "burp_sha256",
            "burp_sha512",
            "burp_gzip",
            "burp_gunzip",
            "burp_to_upper",
            "burp_to_lower",
            "burp_reverse",
            "burp_rot13",
            "burp_json_escape",
            "burp_xml_escape",
            "burp_regex_replace",
            "hex_entities",
            "Custom..."
        ]

    #
    # IContextMenuFactory
    #
    def createMenuItems(self, invocation):
        menu = ArrayList()
        # 64 -> Repeater
        if invocation.getToolFlag() == 64:
            menu.add(JMenuItem("Locate Interesting Insertion Points",
                               actionPerformed=lambda x: self.locate_interesting_params(invocation, use_hackvertor=False)))

            menu.add(JMenuItem("Locate Interesting Insertion Points (Hackvertor tag)",
                               actionPerformed=lambda x: self.locate_interesting_params(invocation, use_hackvertor=True)))

            menu.add(JMenuItem("Add Insertion Point",
                               actionPerformed=lambda x: self.add_insertion_point(invocation, use_hackvertor=False)))

            menu.add(JMenuItem("Add Insertion Point (Hackvertor tag)",
                               actionPerformed=lambda x: self.add_insertion_point(invocation, use_hackvertor=True)))

            menu.add(JMenuItem("Remove insertion points in selected text",
                               actionPerformed=lambda x: self.remove_insertion_in_selection(invocation)))

            menu.add(JMenuItem("Remove all insertion points",
                               actionPerformed=lambda x: self.remove_all_insertion_points(invocation)))

        return menu if menu.size() > 0 else None

    #
    # IMessageEditorTabFactory
    #
    def createNewInstance(self, controller, editable):
        return EIColoredTab(self._cb, editable)

    # ---------------- Hackvertor helpers ----------------

    def _choose_hackvertor_tag(self):
        """
        Zwraca string taga, np. 'burp_urlencode' albo None jeśli '(none)' / anulowano.
        """
        try:
            selection_values = self._hackvertor_tags
            selected = JOptionPane.showInputDialog(
                None,
                "Choose Hackvertor tag to wrap EI-PAYLOAD (or none):",
                "Hackvertor tag",
                JOptionPane.QUESTION_MESSAGE,
                None,
                selection_values,
                selection_values[0]
            )

            if selected is None:
                return None

            selected = unicode(selected)

            if selected == "(none)":
                return None

            if selected == "Custom...":
                custom = JOptionPane.showInputDialog("Enter custom Hackvertor tag (without <@ >):")
                if custom is None:
                    return None
                custom = unicode(custom).strip()
                if not custom:
                    return None
                # basic sanitize (hackvertor tags usually safe)
                custom = re.sub(ur"[^a-zA-Z0-9_\-]", u"", custom)
                return custom if custom else None

            return selected

        except:
            # fallback to manual
            try:
                custom = JOptionPane.showInputDialog("Enter Hackvertor tag (leave empty for none):")
                if custom is None:
                    return None
                custom = unicode(custom).strip()
                if not custom:
                    return None
                custom = re.sub(ur"[^a-zA-Z0-9_\-]", u"", custom)
                return custom if custom else None
            except:
                return None

    def _wrap_with_hackvertor(self, inner_text, tag):
        """
        Zwraca: <@tag>inner_text</@tag> jeśli tag != None, inaczej inner_text.
        """
        if not tag:
            return inner_text
        return u"<@%s>%s</@%s>" % (tag, inner_text, tag)

    #
    # --- Funkcje do manipulacji znacznikami [{{{EI-PAYLOAD}}}] ... [/{{{EI-PAYLOAD}}}] ---
    #

    def locate_interesting_params(self, invocation, use_hackvertor=False):
        """
        Szuka w requestach interesujących parametrów i automatycznie
        otacza ich wartości znacznikami [{{{EI-PAYLOAD}}}] ... [/{{{EI-PAYLOAD}}}].
        Opcjonalnie owija dodatkowo całość tagiem hackvertora: <@tag> ... </@tag>
        """
        messages = invocation.getSelectedMessages()
        if not messages:
            return

        hv_tag = None
        if use_hackvertor:
            hv_tag = self._choose_hackvertor_tag()

        msg = messages[0]
        info = self._helpers.analyzeRequest(msg)
        req_bytes = msg.getRequest()
        text = self._helpers.bytesToString(req_bytes)
        if not isinstance(text, unicode):
            text = text.decode('utf-8', 'replace')

        ctype = self.guess_ct(info.getHeaders(), text)
        out = text
        start_tag = u"[{{{EI-PAYLOAD}}}]"
        end_tag   = u"[/{{{EI-PAYLOAD}}}]"

        def wrap_payload(val):
            inner = start_tag + val + end_tag
            return self._wrap_with_hackvertor(inner, hv_tag)

        if ctype in ["application/x-www-form-urlencoded", "GET"]:
            params = info.getParameters()
            # reversed żeby nie rozjechać offsetów
            for pa in reversed(params):
                val = out[pa.getValueStart():pa.getValueEnd()]
                out = out[:pa.getValueStart()] + wrap_payload(val) + out[pa.getValueEnd():]

        elif ctype == "application/json":
            # Proste otaczanie wartości w JSON
            pat = re.compile(ur'(".*?")\s*:\s*(".*?")')
            def rep(m):
                k = m.group(1)
                v = m.group(2)
                payload_wrapped = wrap_payload(v[1:-1])
                return k + u': "' + payload_wrapped + u'"'
            out = pat.sub(rep, out)

        elif "<soap:" in text.lower():
            pat = re.compile(ur'>([^<]+)<')
            def sp(mo):
                tx = mo.group(1)
                if not tx.strip():
                    return u">" + tx + u"<"
                return u">" + wrap_payload(tx) + u"<"
            out = pat.sub(sp, out)

        elif "query" in text or "mutation" in text:
            # GraphQL
            pat = re.compile(ur'(\w+)\s*:\s*"([^"]*)"')
            def gl(mo):
                return u'%s: "%s"' % (mo.group(1), wrap_payload(mo.group(2)))
            out = pat.sub(gl, out)

        else:
            params = info.getParameters()
            for pa in reversed(params):
                val = out[pa.getValueStart():pa.getValueEnd()]
                out = out[:pa.getValueStart()] + wrap_payload(val) + out[pa.getValueEnd():]

        msg.setRequest(self._helpers.stringToBytes(out.encode('utf-8', 'replace')))

    def add_insertion_point(self, invocation, use_hackvertor=False):
        """
        Otacza zaznaczony fragment znacznikami [{{{EI-PAYLOAD}}}] ... [/{{{EI-PAYLOAD}}}].
        Opcjonalnie owija dodatkowo tagiem hackvertora: <@tag> ... </@tag>
        """
        messages = invocation.getSelectedMessages()
        if not messages:
            return

        rng = invocation.getSelectionBounds()
        if not rng:
            return
        s, e = rng
        if s == e:
            return

        hv_tag = None
        if use_hackvertor:
            hv_tag = self._choose_hackvertor_tag()

        msg = messages[0]
        req = msg.getRequest()
        st = self._helpers.bytesToString(req)
        if not isinstance(st, unicode):
            st = st.decode('utf-8','replace')

        start_tag = u"[{{{EI-PAYLOAD}}}]"
        end_tag   = u"[/{{{EI-PAYLOAD}}}]"
        inner = start_tag + st[s:e] + end_tag
        wrapped = self._wrap_with_hackvertor(inner, hv_tag)

        new_st = st[:s] + wrapped + st[e:]
        msg.setRequest(self._helpers.stringToBytes(new_st.encode('utf-8','replace')))

    def remove_insertion_in_selection(self, invocation):
        """
        Usuwa tagi EI-PAYLOAD w zaznaczonym fragmencie.
        Nie usuwa hackvertor tagów (bo mogą być użyteczne w payloadach),
        ale możesz je usunąć ręcznie jeśli chcesz.
        """
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        rng = invocation.getSelectionBounds()
        if not rng:
            return
        s, e = rng
        if s == e:
            return

        msg = messages[0]
        req = msg.getRequest()
        st = self._helpers.bytesToString(req)
        if not isinstance(st, unicode):
            st = st.decode('utf-8','replace')

        sel = st[s:e]
        sel_cleaned = (sel.replace(u"[{{{EI-PAYLOAD}}}]", u"")
                          .replace(u"[/{{{EI-PAYLOAD}}}]", u""))
        new_st = st[:s] + sel_cleaned + st[e:]
        msg.setRequest(self._helpers.stringToBytes(new_st.encode('utf-8','replace')))

    def remove_all_insertion_points(self, invocation):
        """
        Usuwa wszystkie tagi [{{{EI-PAYLOAD}}}] i [/{{{EI-PAYLOAD}}}] z requestu.
        Nie usuwa hackvertor tagów.
        """
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        msg = messages[0]
        req = msg.getRequest()
        st = self._helpers.bytesToString(req)
        if not isinstance(st, unicode):
            st = st.decode('utf-8','replace')

        new_st = (st.replace(u"[{{{EI-PAYLOAD}}}]", u"")
                    .replace(u"[/{{{EI-PAYLOAD}}}]", u""))
        msg.setRequest(self._helpers.stringToBytes(new_st.encode('utf-8','replace')))

    def guess_ct(self, headers, s):
        """
        Pomocnicza metoda do wykrywania content-type (lub GET).
        """
        if not headers:
            return "other"
        f = headers[0]
        if f.startswith("GET "):
            return "GET"
        for h in headers:
            if h.lower().startswith("content-type:"):
                val = h.split(":",1)[1].strip().lower()
                if "application/json" in val:
                    return "application/json"
                if "xml" in val or "soap" in val:
                    return "application/xml"
                if "x-www-form-urlencoded" in val:
                    return "application/x-www-form-urlencoded"
        return "other"


#
# Karta "EI" z formatowaniem + podświetlaniem znaczników EI-PAYLOAD
#
class EIColoredTab(IMessageEditorTab):
    def __init__(self, callbacks, editable):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        self._editable = editable

        self._orig = None
        self._isRequest = True

        self._panel = JPanel(BorderLayout())

        self._editorPane = JEditorPane("text/html","")
        self._editorPane.setEditable(False)

        self._scroll = JScrollPane(self._editorPane)
        self._panel.add(self._scroll, BorderLayout.CENTER)

    def getTabCaption(self):
        return "EI"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        return True if content else False

    def setMessage(self, content, isRequest):
        self._orig = content
        self._isRequest = isRequest
        if not content:
            self._editorPane.setText("")
            return

        text = self._helpers.bytesToString(content)
        if not isinstance(text, unicode):
            text = text.decode('utf-8','replace')

        text = self.prettify_if_json(text)
        html = self.make_html_colored(text)

        self._editorPane.setText(html)
        self._editorPane.setCaretPosition(0)

    def getMessage(self):
        return self._orig

    def isModified(self):
        return False

    def getSelectedData(self):
        return None

    def getHttpService(self):
        return None

    def prettify_if_json(self, raw_text):
        idx = raw_text.find("\r\n\r\n")
        if idx < 0:
            return raw_text
        hdr = raw_text[:idx]
        body = raw_text[idx+4:]

        content_type = ""
        for line in hdr.split("\n"):
            if line.lower().startswith("content-type:") and "application/json" in line.lower():
                content_type = "json"
                break
        if not content_type:
            return raw_text

        try:
            obj = json.loads(body)
            j2 = json.dumps(obj, indent=2, ensure_ascii=False)
            return hdr + "\r\n\r\n" + j2
        except:
            return raw_text

    def make_html_colored(self, raw):
        idx = raw.find("\r\n\r\n")
        if idx < 0:
            headers_part = raw
            body_part = ""
        else:
            headers_part = raw[:idx]
            body_part = raw[idx+4:]

        lines = headers_part.split("\n")
        if not lines:
            lines = [headers_part]

        if len(lines) >= 1:
            start_line = lines[0].strip()
            header_lines = lines[1:]
        else:
            start_line = ""
            header_lines = []

        start_html = self.color_request_line(start_line)
        header_html_list = [self.color_header_line(h.strip()) for h in header_lines]

        body_html = self.html_escape(body_part)
        body_html = self.highlight_ei_payload(body_html)

        out = []
        out.append("<html><body style='font-family:monospace; white-space:pre;'>")
        out.append(start_html + "\n")
        for h in header_html_list:
            out.append(h + "\n")
        if body_html.strip():
            out.append("\n")
            out.append(body_html)
        out.append("</body></html>")
        return "\n".join(out)

    def color_request_line(self, line):
        parts = line.split(" ")
        if len(parts) >= 3:
            method = parts[0]
            path = " ".join(parts[1:-1])
            proto = parts[-1]
            return (
                "<span style='color:orange; font-weight:bold;'>%s</span> "
                "<span style='color:green;'>%s</span> "
                "<span style='color:blue;'>%s</span>"
            ) % (self.html_escape(method), self.html_escape(path), self.html_escape(proto))
        else:
            return self.html_escape(line)

    def color_header_line(self, line):
        if not line:
            return ""
        if ": " in line:
            left, right = line.split(": ", 1)
            return (
                "<span style='color:#F7767B; font-weight:bold;'>%s:</span> "
                "<span style='color:#C8C8C8;'>%s</span>"
            ) % (self.html_escape(left), self.html_escape(right))
        else:
            return self.html_escape(line)

    def highlight_ei_payload(self, html_text):
        """
        Podświetla fragmenty w znacznikach [{{{EI-PAYLOAD}}}] ... [/{{{EI-PAYLOAD}}}]
        - działa też jeśli całość jest owinięta tagami hackvertora, bo szukamy EI-PAYLOAD w środku.
        """
        pat = re.compile(u"\[{{{EI-PAYLOAD}}}](.*?)\[/{{{EI-PAYLOAD}}}]", re.DOTALL)
        def rep(m):
            return u"<mark style='background-color:yellow; color:black;'>%s</mark>" % m.group(1)
        return pat.sub(rep, html_text)

    def html_escape(self, s):
        return (s.replace("&","&amp;")
                .replace("<","&lt;")
                .replace(">","&gt;")
                .replace("\"","&quot;"))
