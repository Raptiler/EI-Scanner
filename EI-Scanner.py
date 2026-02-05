# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IScanIssue, IHttpRequestResponse
from javax.swing import JMenu, JMenuItem, JDialog, JCheckBox, JScrollPane, JButton, JLabel, JPanel, BoxLayout, SwingConstants, JRadioButton, ButtonGroup
from java.awt import BorderLayout, Dimension
from java.util import ArrayList
import json
import threading
import codecs
import sys
import re
import time
import base64
import os
import traceback
from java.net import URL, MalformedURLException

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Intruder Payload Scanner with verifier")

        sys.stdout = codecs.getwriter('utf-8')(callbacks.getStdout())
        sys.stderr = codecs.getwriter('utf-8')(callbacks.getStderr())

        self._callbacks.registerContextMenuFactory(self)
        self.collab_context = self._callbacks.createBurpCollaboratorClientContext()
        self.collab_payload = self.collab_context.generatePayload(True)

        self.verifier_requests = []

        print(u"Intruder Payload Scanner with verifier extension loaded")
        print(u"Collaborator payload initialized: {}".format(self.collab_payload))

        # Load payload categories from .json files in the extension directory
        self.payload_categories = self.get_payload_categories_from_files()

    def createMenuItems(self, invocation):
        self.context = invocation
        menu = ArrayList()

        category_menu = JMenu("Scan by Category")
        for category in self.payload_categories:
            menu_item = JMenuItem("Scan {}".format(category), actionPerformed=lambda event, cat=category: self.scan_with_intruder_by_category(cat))
            category_menu.add(menu_item)

        menu.add(JMenuItem("Scan with Intruder Payload Scanner", actionPerformed=self.scan_with_intruder))
        menu.add(category_menu)
        menu.add(JMenuItem("Add as Verifier Request", actionPerformed=self.add_as_verifier))
        menu.add(JMenuItem("Remove Verifier Requests", actionPerformed=self.remove_verifiers))

        return menu

    def add_as_verifier(self, event):
        selected_messages = self.context.getSelectedMessages()
        if selected_messages:
            self.verifier_requests.append(selected_messages[0])
            print("Added verifier request. Total verifier requests: {}".format(len(self.verifier_requests)))

    def remove_verifiers(self, event):
        self.verifier_requests = []
        print("Verifier requests removed.")

    def get_payload_categories_from_files(self):
        extension_dir = os.path.dirname(self._callbacks.getExtensionFilename())
        json_files = [f for f in os.listdir(extension_dir) if f.endswith('.json')]
        categories = set()
        for json_file in json_files:
            categories.update(self.get_payload_categories(json_file))
        return list(categories)

    def get_payload_categories(self, filepath):
        extension_dir = os.path.dirname(self._callbacks.getExtensionFilename())
        full_path = os.path.join(extension_dir, filepath)
        try:
            with codecs.open(full_path, 'r', 'utf-8') as f:
                payloads = json.load(f)
                categories = set(payload.get('category', 'Uncategorized') for payload in payloads)
                return list(categories)
        except Exception as e:
            print(u"Error loading payloads from {}: {}".format(filepath, e))
            return []

    def scan_with_intruder(self, event):
        selected_files, scanning_mode = self.show_configuration_dialog()
        if not selected_files:
            print("No payload files selected.")
            return

        selected_messages = self.context.getSelectedMessages()
        payloads = []
        for filename in selected_files:
            payloads.extend(self.load_payloads(filename))

        scan_thread = threading.Thread(target=self.run_scan, args=(selected_messages, payloads, list(self.verifier_requests), scanning_mode))
        scan_thread.start()

    def scan_with_intruder_by_category(self, category):
        selected_files, scanning_mode = self.show_configuration_dialog()
        if not selected_files:
            print("No payload files selected.")
            return

        selected_messages = self.context.getSelectedMessages()
        payloads = []
        for filename in selected_files:
            payloads.extend(self.load_payloads(filename, category))

        scan_thread = threading.Thread(target=self.run_scan, args=(selected_messages, payloads, list(self.verifier_requests), scanning_mode))
        scan_thread.start()

    def load_payloads(self, filepath, category=None):
        extension_dir = os.path.dirname(self._callbacks.getExtensionFilename())
        full_path = os.path.join(extension_dir, filepath)
        try:
            with codecs.open(full_path, 'r', 'utf-8') as f:
                payloads = json.load(f)
                if category:
                    payloads = [p for p in payloads if p.get('category') == category]
                return payloads
        except Exception as e:
            print(u"Error loading payloads from {}: {}".format(full_path, e))
            return []

    def show_configuration_dialog(self):
        dialog = JDialog()
        dialog.setTitle("Select Payload Files and Scanning Mode")
        dialog.setSize(400, 450)
        dialog.setModal(True)
        dialog.setLayout(BorderLayout())

        extension_dir = os.path.dirname(self._callbacks.getExtensionFilename())
        json_files = [f for f in os.listdir(extension_dir) if f.endswith('.json')]

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        checkboxes = []
        for json_file in json_files:
            checkbox = JCheckBox(json_file)
            panel.add(checkbox)
            checkboxes.append(checkbox)

        panel.add(JLabel("Select Scanning Mode:"))
        sniper_radio = JRadioButton("Sniper", selected=True)
        battering_ram_radio = JRadioButton("Battering Ram")
        mode_group = ButtonGroup()
        mode_group.add(sniper_radio)
        mode_group.add(battering_ram_radio)
        panel.add(sniper_radio)
        panel.add(battering_ram_radio)

        scroll_pane = JScrollPane(panel)
        scroll_pane.setPreferredSize(Dimension(380, 300))
        dialog.add(scroll_pane, BorderLayout.CENTER)

        verifier_label = JLabel("Number of Verifier Requests: {}".format(len(self.verifier_requests)), SwingConstants.CENTER)
        dialog.add(verifier_label, BorderLayout.NORTH)

        ok_button = JButton("OK", actionPerformed=lambda event: dialog.dispose())
        dialog.add(ok_button, BorderLayout.SOUTH)

        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

        selected_files = [cb.getText() for cb in checkboxes if cb.isSelected()]
        scanning_mode = "sniper" if sniper_radio.isSelected() else "battering_ram"
        return selected_files, scanning_mode

    def run_scan(self, selected_messages, payloads, verifier_requests, scanning_mode):
        increment_value = 1

        all_requests = []
        pattern = re.compile(u'\[{{{EI-PAYLOAD}}}](.*?)\[/{{{EI-PAYLOAD}}}]')

        for message in selected_messages:
            service = message.getHttpService()
            request_bytes = message.getRequest()
            request_str = self._helpers.bytesToString(request_bytes)
            request_str = unicode(request_str, 'utf-8')
            positions = list(pattern.finditer(request_str))
            all_requests.append({
                'message': message,
                'service': service,
                'request_str': request_str,
                'positions': positions,
                'pattern': pattern
            })

        for verifier_message in verifier_requests:
            verifier_service = verifier_message.getHttpService()
            verifier_request_bytes = verifier_message.getRequest()
            verifier_request_str = self._helpers.bytesToString(verifier_request_bytes)
            verifier_request_str = unicode(verifier_request_str, 'utf-8')
            verifier_positions = list(pattern.finditer(verifier_request_str))
            all_requests.append({
                'message': verifier_message,
                'service': verifier_service,
                'request_str': verifier_request_str,
                'positions': verifier_positions,
                'pattern': pattern
            })

        total_positions = []
        for req_idx, request_info in enumerate(all_requests):
            for pos_idx, match in enumerate(request_info['positions']):
                total_positions.append((req_idx, pos_idx))

        for payload_data in payloads:
            payload = payload_data["payload"]
            payload_str = self.prepare_payload(payload)
            self.current_payload_str = payload_str

            if payload_data.get("category") == "XSS (STORED)":
                if scanning_mode == 'sniper':
                    for pos_idx, (req_idx, match_idx) in enumerate(total_positions):
                        request_info = all_requests[req_idx]
                        modified_request_str = request_info['request_str']
                        modified_request_str = self.replace_single_match(modified_request_str, request_info['pattern'], payload_str, match_idx)
                        modified_request_str = self.remove_paragraph_tags(modified_request_str, scanning_mode)
                        modified_request_str = self.replace_increment_tags(modified_request_str, increment_value)
                        modified_request_str = self.replace_regex_tags(modified_request_str, None)
                        increment_value += 1
                        self.handle_xss_stored(modified_request_str, request_info['service'], verifier_requests, increment_value)

                elif scanning_mode == 'battering_ram':
                    for request_info in all_requests:
                        modified_request_str = request_info['request_str']
                        modified_request_str = self.replace_all_placeholders(modified_request_str, request_info['pattern'], payload_str)
                        modified_request_str = self.remove_paragraph_tags(modified_request_str, scanning_mode)
                        modified_request_str = self.replace_increment_tags(modified_request_str, increment_value)
                        modified_request_str = self.replace_regex_tags(modified_request_str, None)
                        increment_value += 1
                        self.handle_xss_stored(modified_request_str, request_info['service'], verifier_requests, increment_value)
                continue

            previous_response_str = None

            if scanning_mode == 'sniper':
                for pos_idx, (req_idx, match_idx) in enumerate(total_positions):
                    http_messages_so_far = []

                    for i, request_info in enumerate(all_requests):
                        modified_request_str = request_info['request_str']
                        if i == req_idx:
                            modified_request_str = self.replace_single_match(modified_request_str, request_info['pattern'], payload_str, match_idx)

                        modified_request_str = self.remove_paragraph_tags(modified_request_str, scanning_mode)
                        modified_request_str = self.replace_increment_tags(modified_request_str, increment_value)
                        modified_request_str = self.replace_regex_tags(modified_request_str, previous_response_str)

                        modified_request_bytes = self._helpers.stringToBytes(modified_request_str)

                        start_time = time.time()
                        modified_response = self._callbacks.makeHttpRequest(request_info['service'], modified_request_bytes)
                        final_response = self.follow_redirects(modified_response, request_info['service'], modified_request_bytes)
                        end_time = time.time()
                        response_time = end_time - start_time

                        if final_response is None or final_response.getResponse() is None:
                            print("No response received for modified request.")
                            continue

                        custom_request_response = CustomHttpRequestResponse(
                            modified_request_bytes,
                            final_response.getResponse(),
                            request_info['service']
                        )

                        http_messages_so_far.append(custom_request_response)
                        self.analyze_response(custom_request_response, payload_data, response_time, http_messages_so_far)
                        previous_response_str = self._helpers.bytesToString(final_response.getResponse())
                        increment_value += 1

            elif scanning_mode == 'battering_ram':
                http_messages_so_far = []

                for request_info in all_requests:
                    modified_request_str = request_info['request_str']
                    modified_request_str = self.replace_all_placeholders(modified_request_str, request_info['pattern'], payload_str)

                    modified_request_str = self.remove_paragraph_tags(modified_request_str, scanning_mode)
                    modified_request_str = self.replace_increment_tags(modified_request_str, increment_value)
                    modified_request_str = self.replace_regex_tags(modified_request_str, previous_response_str)

                    modified_request_bytes = self._helpers.stringToBytes(modified_request_str)

                    start_time = time.time()
                    modified_response = self._callbacks.makeHttpRequest(request_info['service'], modified_request_bytes)
                    final_response = self.follow_redirects(modified_response, request_info['service'], modified_request_bytes)
                    end_time = time.time()
                    response_time = end_time - start_time

                    if final_response is None or final_response.getResponse() is None:
                        print("No response received for modified request.")
                        continue

                    custom_request_response = CustomHttpRequestResponse(
                        modified_request_bytes,
                        final_response.getResponse(),
                        request_info['service']
                    )

                    http_messages_so_far.append(custom_request_response)
                    self.analyze_response(custom_request_response, payload_data, response_time, http_messages_so_far)
                    previous_response_str = self._helpers.bytesToString(final_response.getResponse())

                increment_value += 1

    def follow_redirects(self, response, service, original_request_bytes, max_redirects=5):
        redirect_count = 0
        current_response = response
        current_service = service
        current_request_bytes = original_request_bytes
        cookies = self.extract_cookies_from_request(original_request_bytes)

        while redirect_count < max_redirects:
            response_info = self._helpers.analyzeResponse(current_response.getResponse())
            status_code = response_info.getStatusCode()

            if status_code in [301, 302, 303, 307, 308]:
                headers = response_info.getHeaders()
                location = None
                response_cookies = response_info.getCookies()
                cookies.extend([(cookie.getName(), cookie.getValue()) for cookie in response_cookies])

                for header in headers:
                    if header.lower().startswith('location:'):
                        location = header[len('Location:'):].strip()
                        break
                if not location:
                    break

                new_url = self.build_absolute_url(location, current_service)
                if not new_url:
                    break

                try:
                    new_request_bytes = self.build_redirect_request(new_url, current_request_bytes, status_code)
                    new_service = self.get_service_from_url(new_url)
                    new_request_bytes = self.update_request_cookies(new_request_bytes, cookies)

                    current_response = self._callbacks.makeHttpRequest(new_service, new_request_bytes)
                    current_service = new_service
                    current_request_bytes = new_request_bytes
                    redirect_count += 1
                except Exception as e:
                    print("Error following redirect: {}".format(e))
                    break
            else:
                break
        return current_response

    def extract_cookies_from_request(self, request_bytes):
        analyzed_request = self._helpers.analyzeRequest(request_bytes)
        headers = analyzed_request.getHeaders()
        cookies = []
        for header in headers:
            if header.lower().startswith('cookie:'):
                cookie_header = header[len('Cookie:'):].strip()
                cookie_pairs = cookie_header.split(';')
                for pair in cookie_pairs:
                    name_value = pair.strip().split('=', 1)
                    if len(name_value) == 2:
                        name, value = name_value
                        cookies.append((name.strip(), value.strip()))
        return cookies

    def update_request_cookies(self, request_bytes, cookies):
        analyzed_request = self._helpers.analyzeRequest(request_bytes)
        headers = list(analyzed_request.getHeaders())
        body = request_bytes[analyzed_request.getBodyOffset():]

        headers = [header for header in headers if not header.lower().startswith('cookie:')]

        if cookies:
            cookie_strings = ["{}={}".format(name, value) for name, value in cookies]
            headers.append("Cookie: {}".format("; ".join(cookie_strings)))

        new_request_bytes = self._helpers.buildHttpMessage(headers, body)
        return new_request_bytes

    def build_absolute_url(self, location, service):
        try:
            if location.startswith('http://') or location.startswith('https://'):
                return location
            protocol = 'https' if service.getProtocol() == 'https' or service.getPort() == 443 else 'http'
            host = service.getHost()
            port = service.getPort()
            if port == 80 and protocol == 'http':
                port_str = ''
            elif port == 443 and protocol == 'https':
                port_str = ''
            else:
                port_str = ':{}'.format(port)
            if location.startswith('/'):
                return "{}://{}{}{}".format(protocol, host, port_str, location)
            else:
                return "{}://{}{}{}/{}".format(protocol, host, port_str, '/', location)
        except Exception as e:
            print("Error building absolute URL: {}".format(e))
            return None

    def build_redirect_request(self, url, original_request_bytes, status_code):
        try:
            parsed_url = URL(url)
            path = parsed_url.getPath()
            if parsed_url.getQuery():
                path += '?' + parsed_url.getQuery()
            analyzed_request = self._helpers.analyzeRequest(original_request_bytes)
            headers = list(analyzed_request.getHeaders())
            body = original_request_bytes[analyzed_request.getBodyOffset():]

            request_line = headers[0]
            method = request_line.split(' ')[0]
            if status_code in [301, 302]:
                if method.upper() not in ['GET', 'HEAD']:
                    method = 'GET'
                    body = b''
            elif status_code == 303:
                method = 'GET'
                body = b''

            headers[0] = "{} {} HTTP/1.1".format(method, path)

            for i in range(len(headers)):
                if headers[i].lower().startswith('host:'):
                    headers[i] = "Host: {}".format(parsed_url.getAuthority())
                    break

            if not body:
                headers = [header for header in headers if not header.lower().startswith('content-length:')]

            new_request_bytes = self._helpers.buildHttpMessage(headers, body)
            return new_request_bytes
        except Exception as e:
            print("Error building redirect request: {}".format(e))
            raise

    def get_service_from_url(self, url):
        try:
            parsed_url = URL(url)
            protocol = parsed_url.getProtocol()
            host = parsed_url.getHost()
            port = parsed_url.getPort()
            if port == -1:
                port = 443 if protocol == 'https' else 80
            return self._helpers.buildHttpService(host, port, protocol == 'https')
        except Exception as e:
            print("Error getting service from URL: {}".format(e))
            return None

    ##########################################################################
    # NOWE (KLUCZOWE): wyciąganie fragmentu "#..." Z SUROWEGO REQUEST STR
    # zanim Burp zrobi analyzeRequest (bo analyzeRequest może fragment zgubić).
    ##########################################################################
    def extract_fragment_from_raw_request_str(self, request_str):
        """
        request_str: unicode z pełnym requestem HTTP.
        Zwraca: (request_str_bez_fragmentu_w_request_line, fragment_or_none)

        Obsługuje:
          - origin-form:   GET /path?x=1#frag HTTP/1.1
          - absolute-form: GET https://host/path?x=1#frag HTTP/1.1
        """
        try:
            if not request_str:
                return request_str, None

            # Podziel na linie, zachowaj resztę bez zmian
            lines = request_str.splitlines()
            if not lines:
                return request_str, None

            reqline = lines[0]
            parts = reqline.split(' ')
            if len(parts) < 3:
                return request_str, None

            method = parts[0]
            target = parts[1]
            version = ' '.join(parts[2:])

            if '#' not in target:
                return request_str, None

            before, frag = target.split('#', 1)
            if frag is None or frag == '':
                # sam # bez wartości -> olej
                return request_str, None

            # usuń fragment z request-line
            new_target = before if before else '/'
            lines[0] = "{} {} {}".format(method, new_target, version)

            # zlep z powrotem: preferuj CRLF (Burp i tak to łyka)
            new_request_str = "\r\n".join(lines)
            return new_request_str, frag
        except Exception as e:
            print("Error in extract_fragment_from_raw_request_str: {}".format(e))
            return request_str, None

    ##########################################################################
    # Zmiana w funkcji usuwającej placeholdery
    ##########################################################################
    def remove_paragraph_tags(self, request_str, scanning_mode):
        return (request_str
                .replace('[{{{EI-PAYLOAD}}}]', '')
                .replace('[/{{{EI-PAYLOAD}}}]', ''))

    def replace_single_match(self, request_str, pattern, replacement, match_index):
        matches = list(pattern.finditer(request_str))
        if 0 <= match_index < len(matches):
            match = matches[match_index]
            start, end = match.span()
            return request_str[:start] + replacement + request_str[end:]
        return request_str

    def replace_other_placeholders_with_original(self, request_str, pattern, match_index):
        return request_str

    def replace_placeholders_with_original_content(self, request_str, pattern):
        return request_str

    def replace_all_placeholders(self, request_str, pattern, replacement):
        return pattern.sub(replacement, request_str)

    def replace_increment_tags(self, request_str, increment_value):
        increment_pattern = r'\[increment](\d*)\[/increment]'
        def increment_match(match):
            if match.group(1):
                current_value = int(match.group(1))
                return str(current_value + increment_value)
            return str(increment_value)
        return re.sub(increment_pattern, increment_match, request_str)

    def replace_regex_tags(self, request_str, response_str_for_search_regex):
        """
        Safely replaces [REGEXTAG={{{regex}}}] using the LAST response.
        Fix: supports regexes generated by getRegex.py that contain literal \\n/\\r/\\t.
        """
        try:
            if not response_str_for_search_regex:
                return request_str

            tag_pattern = r'\[REGEXTAG=\{\{\{(.*?)\}\}\}\]'
            tags_iter = list(re.finditer(tag_pattern, request_str, re.DOTALL))
            if not tags_iter:
                return request_str

            for m in tags_iter:
                raw_regex = m.group(1)
                full_tag = m.group(0)

                if not raw_regex or not raw_regex.strip():
                    continue

                # ✅ KLUCZ: unescape common sequences coming from clipboard / getRegex.py
                # so "\\n" becomes real newline etc.
                normalized = raw_regex
                normalized = normalized.replace("\\r\\n", "\r\n")
                normalized = normalized.replace("\\n", "\n")
                normalized = normalized.replace("\\r", "\r")
                normalized = normalized.replace("\\t", "\t")
                normalized = normalized.replace("{{NEWLINE}}", "\n")  # if it ever appears

                try:
                    compiled = re.compile(normalized, re.DOTALL | re.MULTILINE | re.IGNORECASE)
                except re.error as e:
                    self._callbacks.printError("REGEXTAG compile error [%s]: %s" % (raw_regex, e))
                    continue

                r = compiled.search(response_str_for_search_regex)
                if not r:
                    self._callbacks.printError("REGEXTAG no match for regex: %s" % raw_regex)
                    continue

                # Prefer first capturing group, fallback to whole match
                if r.lastindex:
                    replacement = r.group(1)
                else:
                    replacement = r.group(0)

                if replacement is None:
                    continue

                request_str = request_str.replace(full_tag, replacement, 1)

            return request_str

        except Exception as e:
            self._callbacks.printError("Error in replace_regex_tags: %s" % str(e))
            traceback.print_exc()
            return request_str

    def prepare_payload(self, payload):
        return payload.replace("[COLLAB]", self.collab_payload)

    def handle_xss_stored(self, request_str, service, verifier_requests, increment_value):
        try:
            http_messages_so_far = []

            # ✅ KLUCZ: wyciągnij #fragment z SUROWEGO request_str (payload może go wprowadzać)
            request_str, extracted_fragment = self.extract_fragment_from_raw_request_str(request_str)

            request_bytes = self._helpers.stringToBytes(request_str)
            analyzed_request = self._helpers.analyzeRequest(service, request_bytes)
            headers = list(analyzed_request.getHeaders())
            body_bytes = request_bytes[analyzed_request.getBodyOffset():]

            protocol = "https" if service.getPort() == 443 or service.getProtocol() == 'https' else "http"
            target_url = "{}://{}:{}".format(protocol, service.getHost(), service.getPort())
            http_method = analyzed_request.getMethod()
            csp = 0

            headers.append("EI-Target: {}".format(target_url))
            headers.append("EI-Method: {}".format(http_method))
            headers.append("EI-CSP: {}".format(csp))

            # ✅ dodaj EI-Fragment tylko jeśli realnie był wyciągnięty
            if extracted_fragment:
                headers.append("EI-Fragment: {}".format(extracted_fragment))

            if headers[0].endswith(" HTTP/2"):
                headers[0] = headers[0].replace(" HTTP/2", " HTTP/1.1", 1)

            if http_method.upper() == "GET":
                new_request_bytes = self._helpers.buildHttpMessage(headers, b'')
            else:
                new_request_bytes = self._helpers.buildHttpMessage(headers, body_bytes)

            localhost_service = self._helpers.buildHttpService("localhost", 7437, False)
            response = self._callbacks.makeHttpRequest(localhost_service, new_request_bytes)
            if response is None or response.getResponse() is None:
                print("No response received from XSS (STORED) request.")
                return

            custom_request_response = CustomHttpRequestResponse(
                new_request_bytes,
                response.getResponse(),
                localhost_service
            )
            http_messages_so_far.append(custom_request_response)

            response_bytes = response.getResponse()
            analyzed_response = self._helpers.analyzeResponse(response_bytes)
            body_offset = analyzed_response.getBodyOffset()
            response_body_bytes = response_bytes[body_offset:]
            response_body_str = self._helpers.bytesToString(response_body_bytes)

            try:
                response_json = json.loads(response_body_str)
                if response_json.get('alert_detected', False):
                    self.report_issue(
                        service,
                        "XSS (STORED) detected in Request",
                        "XSS (STORED)",
                        http_messages_so_far
                    )
                response_str = response_json.get('response', '')
            except Exception as e:
                print("Error parsing JSON from response body: {}".format(e))
                response_str = ''

            previous_response_str = response_str

            for verifier_request in verifier_requests:
                verifier_request_bytes = verifier_request.getRequest()
                verifier_request_str = self._helpers.bytesToString(verifier_request_bytes)
                verifier_request_str = unicode(verifier_request_str, 'utf-8')

                pattern = re.compile(u'\[{{{EI-PAYLOAD}}}](.*?)\[/{{{EI-PAYLOAD}}}]')
                matches = list(pattern.finditer(verifier_request_str))
                if matches:
                    verifier_request_str = self.replace_all_placeholders(verifier_request_str, pattern, self.current_payload_str)

                verifier_request_str = self.remove_paragraph_tags(verifier_request_str, 'battering_ram')
                verifier_request_str = self.replace_increment_tags(verifier_request_str, increment_value)
                verifier_request_str = self.replace_regex_tags(verifier_request_str, previous_response_str)
                increment_value += 1

                # ✅ KLUCZ: wyciągnij #fragment także z verifiera (zanim analyzeRequest)
                verifier_request_str, verifier_fragment = self.extract_fragment_from_raw_request_str(verifier_request_str)

                analyzed_verifier_request = self._helpers.analyzeRequest(service, self._helpers.stringToBytes(verifier_request_str))
                verifier_headers = list(analyzed_verifier_request.getHeaders())
                verifier_body_bytes = self._helpers.stringToBytes(verifier_request_str)[analyzed_verifier_request.getBodyOffset():]
                verifier_http_method = analyzed_verifier_request.getMethod()

                verifier_headers.append("EI-Target: {}".format(target_url))
                verifier_headers.append("EI-Method: {}".format(verifier_http_method))
                verifier_headers.append("EI-CSP: {}".format(csp))

                if verifier_fragment:
                    verifier_headers.append("EI-Fragment: {}".format(verifier_fragment))

                if verifier_headers[0].endswith(" HTTP/2"):
                    verifier_headers[0] = verifier_headers[0].replace(" HTTP/2", " HTTP/1.1", 1)

                if verifier_http_method.upper() == "GET":
                    new_verifier_request_bytes = self._helpers.buildHttpMessage(verifier_headers, b'')
                else:
                    new_verifier_request_bytes = self._helpers.buildHttpMessage(verifier_headers, verifier_body_bytes)

                verifier_response = self._callbacks.makeHttpRequest(localhost_service, new_verifier_request_bytes)
                if verifier_response is None or verifier_response.getResponse() is None:
                    print("No response received from verifier request in XSS (STORED).")
                    continue

                custom_verifier_request_response = CustomHttpRequestResponse(
                    new_verifier_request_bytes,
                    verifier_response.getResponse(),
                    localhost_service
                )
                http_messages_so_far.append(custom_verifier_request_response)

                verifier_response_bytes = verifier_response.getResponse()
                analyzed_verifier_response = self._helpers.analyzeResponse(verifier_response_bytes)
                verifier_body_offset = analyzed_verifier_response.getBodyOffset()
                verifier_response_body_bytes = verifier_response_bytes[verifier_body_offset:]
                verifier_response_body_str = self._helpers.bytesToString(verifier_response_body_bytes)

                try:
                    verifier_response_json = json.loads(verifier_response_body_str)
                    if verifier_response_json.get('alert_detected', False):
                        self.report_issue(
                            service,
                            "XSS (STORED) detected in Verifier Request",
                            "XSS (STORED)",
                            http_messages_so_far
                        )
                    verifier_response_str = verifier_response_json.get('response', '')
                except Exception as e:
                    print("Error parsing JSON from verifier response body: {}".format(e))
                    verifier_response_str = ''

                previous_response_str = verifier_response_str

        except Exception as e:
            print(u"Error during XSS (STORED) request: {}".format(e))
            traceback.print_exc()

    def analyze_response(self, response, payload_data, response_time, http_messages_so_far):
        if response is None or response.getResponse() is None:
            print("No response received.")
            return

        response_info = self._helpers.analyzeResponse(response.getResponse())
        response_str = self._helpers.bytesToString(response.getResponse())

        issues_found = False

        expected_response = payload_data.get("expectedResponse", "")
        if expected_response and expected_response in response_str:
            issues_found = True
            print("Expected response found in response.")
            self.report_issue(response.getHttpService(), "Response matched expected response", "Potential Vulnerability", list(http_messages_so_far))

        expected_delay_str = payload_data.get("expectedDelay")
        if expected_delay_str is None:
            expected_delay = 0
        else:
            try:
                expected_delay = float(expected_delay_str)
            except (ValueError, TypeError):
                expected_delay = 0

        print("Response time: {:.2f} seconds, Expected delay: {} seconds".format(response_time, expected_delay))
        if expected_delay > 0 and response_time > expected_delay:
            issues_found = True
            print("Response time exceeded expected delay.")
            self.report_issue(response.getHttpService(), "Response delay exceeded expected time", "Potential Vulnerability", list(http_messages_so_far))

        if payload_data.get("expectingCollab", False):
            interactions = self.collab_context.fetchCollaboratorInteractionsFor(self.collab_payload)
            if interactions:
                issues_found = True
                print("Collaborator interaction detected.")
                self.report_issue(response.getHttpService(), "Collaborator interaction detected", "Potential Vulnerability", list(http_messages_so_far))

                self.collab_context = self._callbacks.createBurpCollaboratorClientContext()
                self.collab_payload = self.collab_context.generatePayload(True)

    def report_issue(self, http_service, detail, name, http_messages):
        try:
            analyzed_request = self._helpers.analyzeRequest(http_messages[0].getHttpService(), http_messages[0].getRequest())
            url = analyzed_request.getUrl()
            if url is None:
                protocol = "https" if http_service.getPort() == 443 else "http"
                host = http_service.getHost()
                port = http_service.getPort()
                url = URL("{}://{}:{}".format(protocol, host, port))
            print("Reporting issue for URL: {}".format(url))
            issue = CustomScanIssue(
                http_service, url, http_messages, name, detail, "High"
            )
            self._callbacks.addScanIssue(issue)
            print("Issue reported successfully.")
        except Exception as e:
            print("Error during report_issue: {}".format(e))
            traceback.print_exc()

class CustomHttpRequestResponse(IHttpRequestResponse):
    def __init__(self, request, response, http_service):
        self._request = request
        self._response = response
        self._http_service = http_service
        self._comment = None
        self._highlight = None

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def getHttpService(self):
        return self._http_service

    def setRequest(self, message):
        self._request = message

    def setResponse(self, message):
        self._response = message

    def setHttpService(self, http_service):
        self._http_service = http_service

    def getComment(self):
        return self._comment

    def setComment(self, comment):
        self._comment = comment

    def getHighlight(self):
        return self._highlight

    def setHighlight(self, color):
        self._highlight = color

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        print("CustomScanIssue created with URL: {}".format(url))

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None
