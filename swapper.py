# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JCheckBox, JButton, JScrollPane, BorderFactory, JSpinner, SpinnerNumberModel, JMenuItem
from java.awt.event import ActionListener
from java.util.concurrent import Executors, TimeUnit
from java.lang import Runnable
import re
import threading
import time
import Queue

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SWAPPER")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.token_lock = threading.Lock()
        self.shutdown_flag = False
        self.token_worker_thread = None
        self.token_request_config = {
            'host': 'the.host.net',
            'port': 443,
            'use_https': True,
            'headers': [],
            'body': ''
        } 
        self.response_regex = r'<sessionId>([^<]+)</sessionId>'
        self.request_regex = r'<sessionId>[^<]*</sessionId>'
        self.replacement_template = '<sessionId>{token}</sessionId>'
        self.regex_pairs = [
            {'response': self.response_regex, 'request': self.request_regex, 'replacement': self.replacement_template}
        ]
        self.regex_pair_panels = []
        self.enabled_tools = {
            'scanner': True,
            'repeater': True,
            'intruder': True,
            'target': False,
            'sequencer': False,
            'extender': False
        }
        self.fresh_token_per_request = True
        self.extension_enabled = False
        self.auto_refresh_enabled = True
        self.refresh_interval = 240   
        self.scheduler = None
        self.current_token = None
        self.current_tokens = {} 
        self.token_last_updated = 0
        self.createGUI()
        callbacks.addSuiteTab(self)
        self.startBackgroundWorker()
        print("Started SWAPPER");
        print("Author: Dave Blandford");
        print("Email: dave@mailo.com");
        print(
        '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
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
JSYTJzaX2Ds2ClCwTyz5P4Gjx6CoKwBIdsEspog=
=iIJQ
-----END PGP PUBLIC KEY BLOCK-----
        '''
        )
    
    def createGUI(self):
        self.panel = JPanel(BorderLayout())
        content_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.NORTHWEST
        top_panel = JPanel(GridBagLayout())
        top_gbc = GridBagConstraints()
        top_gbc.insets = Insets(5, 5, 5, 5)
        top_gbc.anchor = GridBagConstraints.NORTHWEST
        instructions_section = JPanel(BorderLayout())
        instructions_section.setBorder(BorderFactory.createTitledBorder("Instructions"))
        instructions_section.setPreferredSize(Dimension(400, 300))
        self.instructions_area = JTextArea(15, 30)
        self.instructions_area.setEditable(False)  
        self.instructions_area.setText("""SWAPPER
                                 
An extension for easy match/replace of tokens/CSRF/anything using regex. Handles XML and JSON. By default, SWAPPER sends a request to obtain the token/value every 4 minutes. You can change the time to request a new token. Disabling auto-refresh will request a token for each Request(needed every now and again...). A new value will be requested for each interval. There is not logout logic implemented in the tool. Can pull multiple patterns out of Response and set multiple patterns to replace.
        
HOW TO USE:

1. Right-click on any request in Target/History
2. Select "Send to Swapper" to populate fields
3. Modify the request details to create your token request
4. Set up regex patterns for token extraction/replacement
5. Test your configuration
6. Enable tools and auto-refresh as needed

Remember to save configuration to update changes.

When using Repeater, the changes will not show. Check Logger/Logger++ to verify replacement. 

Test Token Request will send Request and display in status the regex match. For the Request, go to Request in Proxy history and under extensions, select `Test Request Regex`. Match will show in Status field.
""")
        self.instructions_area.setLineWrap(True)
        self.instructions_area.setWrapStyleWord(True)
        instructions_scroll = JScrollPane(self.instructions_area)
        instructions_section.add(instructions_scroll, BorderLayout.CENTER)
        token_section = JPanel(BorderLayout())
        token_section.setBorder(BorderFactory.createTitledBorder("SWAPPER Configuration"))
        token_section.setPreferredSize(Dimension(400, 300))   
        token_config_panel = JPanel(GridBagLayout())
        token_gbc = GridBagConstraints()
        token_gbc.insets = Insets(3, 3, 3, 3)
        token_gbc.anchor = GridBagConstraints.WEST
        connection_panel = JPanel(GridBagLayout())
        conn_gbc = GridBagConstraints()
        conn_gbc.insets = Insets(2, 2, 2, 2)
        conn_gbc.gridx = 0; conn_gbc.gridy = 0
        connection_panel.add(JLabel("Host:"), conn_gbc)
        conn_gbc.gridx = 1; conn_gbc.fill = GridBagConstraints.HORIZONTAL; conn_gbc.weightx = 1.0
        self.host_field = JTextField(self.token_request_config['host'], 15)
        connection_panel.add(self.host_field, conn_gbc)
        conn_gbc.gridx = 2; conn_gbc.fill = GridBagConstraints.NONE; conn_gbc.weightx = 0
        connection_panel.add(JLabel("Port:"), conn_gbc)
        conn_gbc.gridx = 3; conn_gbc.fill = GridBagConstraints.HORIZONTAL; conn_gbc.weightx = 0.3
        self.port_field = JTextField(str(self.token_request_config['port']), 6)
        connection_panel.add(self.port_field, conn_gbc)
        conn_gbc.gridx = 4; conn_gbc.fill = GridBagConstraints.NONE; conn_gbc.weightx = 0
        self.https_checkbox = JCheckBox("HTTPS", self.token_request_config['use_https'])
        connection_panel.add(self.https_checkbox, conn_gbc)
        token_gbc.gridx = 0; token_gbc.gridy = 0; token_gbc.gridwidth = 2; token_gbc.fill = GridBagConstraints.HORIZONTAL; token_gbc.weightx = 1.0
        token_config_panel.add(connection_panel, token_gbc)
        token_gbc.gridx = 0; token_gbc.gridy = 1; token_gbc.gridwidth = 1; token_gbc.fill = GridBagConstraints.NONE; token_gbc.weightx = 0
        token_config_panel.add(JLabel("Headers:"), token_gbc)
        token_gbc.gridx = 0; token_gbc.gridy = 2; token_gbc.fill = GridBagConstraints.BOTH; token_gbc.weightx = 1.0; token_gbc.weighty = 0.4
        self.headers_area = JTextArea(6, 30)
        self.headers_area.setLineWrap(True)
        self.headers_area.setWrapStyleWord(True)
        self.headers_area.setText('''Can build out your Request Headers here
Or they will populate when you send to SWAPPER
''')
        headers_scroll = JScrollPane(self.headers_area)
        token_config_panel.add(headers_scroll, token_gbc)
        token_gbc.gridx = 0; token_gbc.gridy = 3; token_gbc.weighty = 0
        token_config_panel.add(JLabel("Body:"), token_gbc)
        token_gbc.gridx = 0; token_gbc.gridy = 4; token_gbc.weighty = 0.6
        self.body_area = JTextArea(8, 30)
        self.body_area.setLineWrap(True)
        self.body_area.setWrapStyleWord(True)
        self.body_area.setText('''You can build the request body here
Or find the request to send in your history and send to SWAPPER
''')
        body_scroll = JScrollPane(self.body_area)
        token_config_panel.add(body_scroll, token_gbc)
        token_section.add(token_config_panel, BorderLayout.CENTER)
        top_gbc.gridx = 0; top_gbc.gridy = 0; top_gbc.fill = GridBagConstraints.BOTH; top_gbc.weightx = 0.5; top_gbc.weighty = 1.0
        top_panel.add(instructions_section, top_gbc)
        top_gbc.gridx = 1; top_gbc.weightx = 0.5
        top_panel.add(token_section, top_gbc)
        regex_section = JPanel(BorderLayout())
        regex_section.setBorder(BorderFactory.createTitledBorder("Regex Configuration"))
        self.main_regex_panel = JPanel(GridBagLayout())
        self.regex_scroll = JScrollPane(self.main_regex_panel)
        self.regex_scroll.setPreferredSize(Dimension(600, 200))
        regex_section.add(self.regex_scroll, BorderLayout.CENTER)
        button_regex_panel = JPanel()
        self.add_regex_button = JButton("Add Another Regex Pair")
        self.add_regex_button.addActionListener(self)
        button_regex_panel.add(self.add_regex_button)
        regex_section.add(button_regex_panel, BorderLayout.SOUTH)
        self.createRegexPair(0)
        control_section = JPanel(BorderLayout())
        control_section.setBorder(BorderFactory.createTitledBorder("Extension Control"))
        control_panel = JPanel(GridBagLayout())
        control_gbc = GridBagConstraints()
        control_gbc.insets = Insets(3, 3, 3, 3)
        control_gbc.anchor = GridBagConstraints.WEST
        control_gbc.gridx = 0; control_gbc.gridy = 0
        self.enable_extension_checkbox = JCheckBox("Enable Extension", self.extension_enabled)
        self.enable_extension_checkbox.addActionListener(self)
        control_panel.add(self.enable_extension_checkbox, control_gbc)
        control_gbc.gridx = 1
        enable_help = JLabel("Default grabs a token for each request (auto-refresh can override)")
        control_panel.add(enable_help, control_gbc)
        control_section.add(control_panel, BorderLayout.CENTER)
        tools_section = JPanel(BorderLayout())
        tools_section.setBorder(BorderFactory.createTitledBorder("Enable for Tools"))
        tools_panel = JPanel(GridBagLayout())
        tools_gbc = GridBagConstraints()
        tools_gbc.insets = Insets(3, 3, 3, 3)
        tools_gbc.anchor = GridBagConstraints.WEST
        tools_gbc.gridx = 0; tools_gbc.gridy = 0
        self.scanner_checkbox = JCheckBox("Scanner", self.enabled_tools['scanner'])
        tools_panel.add(self.scanner_checkbox, tools_gbc)
        tools_gbc.gridx = 1
        self.repeater_checkbox = JCheckBox("Repeater", self.enabled_tools['repeater'])
        tools_panel.add(self.repeater_checkbox, tools_gbc)
        tools_gbc.gridx = 2
        self.intruder_checkbox = JCheckBox("Intruder", self.enabled_tools['intruder'])
        tools_panel.add(self.intruder_checkbox, tools_gbc)
        tools_gbc.gridx = 0; tools_gbc.gridy = 1
        self.target_checkbox = JCheckBox("Target", self.enabled_tools['target'])
        tools_panel.add(self.target_checkbox, tools_gbc)
        tools_gbc.gridx = 1
        self.sequencer_checkbox = JCheckBox("Sequencer", self.enabled_tools['sequencer'])
        tools_panel.add(self.sequencer_checkbox, tools_gbc)
        tools_gbc.gridx = 2
        self.extender_checkbox = JCheckBox("Extender", self.enabled_tools['extender'])
        tools_panel.add(self.extender_checkbox, tools_gbc)
        tools_section.add(tools_panel, BorderLayout.CENTER)
        refresh_section = JPanel(BorderLayout())
        refresh_section.setBorder(BorderFactory.createTitledBorder("Auto-refresh Settings"))
        refresh_panel = JPanel(GridBagLayout())
        refresh_gbc = GridBagConstraints()
        refresh_gbc.insets = Insets(3, 3, 3, 3)
        refresh_gbc.anchor = GridBagConstraints.WEST
        refresh_gbc.gridx = 0; refresh_gbc.gridy = 0
        self.auto_refresh_checkbox = JCheckBox("Enable Auto-refresh", self.auto_refresh_enabled)
        self.auto_refresh_checkbox.addActionListener(self)
        refresh_panel.add(self.auto_refresh_checkbox, refresh_gbc)
        refresh_gbc.gridx = 1
        refresh_panel.add(JLabel("Interval (seconds):"), refresh_gbc)
        refresh_gbc.gridx = 2
        self.interval_spinner = JSpinner(SpinnerNumberModel(self.refresh_interval, 1, 3600, 1))
        refresh_panel.add(self.interval_spinner, refresh_gbc)
        refresh_section.add(refresh_panel, BorderLayout.CENTER)
        sent_section = JPanel(BorderLayout())
        sent_section.setBorder(BorderFactory.createTitledBorder("Sent Requests Queue"))
        sent_panel = JPanel(GridBagLayout())
        sent_gbc = GridBagConstraints()
        sent_gbc.insets = Insets(3, 3, 3, 3)
        sent_gbc.anchor = GridBagConstraints.WEST
        sent_gbc.gridx = 0; sent_gbc.gridy = 0; sent_gbc.fill = GridBagConstraints.BOTH; sent_gbc.weightx = 1.0; sent_gbc.weighty = 1.0
        self.sent_requests_area = JTextArea(6, 50)
        self.sent_requests_area.setEditable(False)
        sent_requests_scroll = JScrollPane(self.sent_requests_area)
        sent_panel.add(sent_requests_scroll, sent_gbc)
        sent_gbc.gridy = 1; sent_gbc.fill = GridBagConstraints.NONE; sent_gbc.weighty = 0
        sent_button_panel = JPanel()
        self.process_queue_button = JButton("Process Queue")
        self.process_queue_button.addActionListener(self)
        self.clear_queue_button = JButton("Clear Queue")
        self.clear_queue_button.addActionListener(self)
        sent_button_panel.add(self.process_queue_button)
        sent_button_panel.add(self.clear_queue_button)
        sent_panel.add(sent_button_panel, sent_gbc)
        sent_section.add(sent_panel, BorderLayout.CENTER)
        button_panel = JPanel()
        self.test_button = JButton("Test Token Request")
        self.test_button.addActionListener(self)
        self.save_button = JButton("Save Configuration")
        self.save_button.addActionListener(self)
        button_panel.add(self.test_button)
        button_panel.add(self.save_button)
        self.status_area = JTextArea(5, 50)
        self.status_area.setEditable(False)
        status_scroll = JScrollPane(self.status_area)
        status_scroll.setBorder(BorderFactory.createTitledBorder("Status"))
        gbc.gridx = 0; gbc.gridy = 0; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 0.6
        content_panel.add(top_panel, gbc)
        gbc.gridy = 1
        content_panel.add(control_section, gbc)
        gbc.gridy = 2
        content_panel.add(regex_section, gbc)
        gbc.gridy = 3
        content_panel.add(tools_section, gbc)
        gbc.gridy = 4
        content_panel.add(refresh_section, gbc)
        gbc.gridy = 5; gbc.fill = GridBagConstraints.NONE
        content_panel.add(button_panel, gbc)
        gbc.gridy = 6; gbc.fill = GridBagConstraints.BOTH; gbc.weighty = 1.0
        content_panel.add(status_scroll, gbc)
        scroll_pane = JScrollPane(content_panel)
        self.panel.add(scroll_pane, BorderLayout.CENTER)

    def createRegexPair(self, index):
        pair_panel = JPanel(GridBagLayout())
        pair_panel.setBorder(BorderFactory.createTitledBorder("Regex Pair #%d" % (index + 1)))
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 3, 3, 3)
        gbc.anchor = GridBagConstraints.WEST
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 3
        enable_checkbox = JCheckBox("Enable this pair", index == 0)
        enable_checkbox.addActionListener(self)
        pair_panel.add(enable_checkbox, gbc)
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1
        pair_panel.add(JLabel("Response Regex:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        response_field = JTextField(self.regex_pairs[index]['response'] if index < len(self.regex_pairs) else '', 25)
        pair_panel.add(response_field, gbc)
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0
        pair_panel.add(JLabel("Request Regex:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        request_field = JTextField(self.regex_pairs[index]['request'] if index < len(self.regex_pairs) else '', 25)
        pair_panel.add(request_field, gbc)
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0
        pair_panel.add(JLabel("Replacement:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        replacement_field = JTextField(self.regex_pairs[index]['replacement'] if index < len(self.regex_pairs) else '{token}', 25)
        pair_panel.add(replacement_field, gbc)
        pair_data = {
            'panel': pair_panel,
            'enabled': enable_checkbox,
            'response_field': response_field,
            'request_field': request_field,
            'replacement_field': replacement_field
        } 
        self.regex_pair_panels.append(pair_data)
        main_gbc = GridBagConstraints()
        main_gbc.gridx = 0; main_gbc.gridy = len(self.regex_pair_panels) - 1
        main_gbc.fill = GridBagConstraints.HORIZONTAL; main_gbc.weightx = 1.0
        main_gbc.insets = Insets(5, 5, 5, 5)
        self.main_regex_panel.add(pair_panel, main_gbc)
        self.panel.revalidate()
        self.panel.repaint()

    def refreshRegexDisplay(self):
        self.main_regex_panel.removeAll()
        for i, pair_data in enumerate(self.regex_pair_panels):
            main_gbc = GridBagConstraints()
            main_gbc.gridx = 0; main_gbc.gridy = i
            main_gbc.fill = GridBagConstraints.HORIZONTAL; main_gbc.weightx = 1.0
            main_gbc.insets = Insets(5, 5, 5, 5)
            self.main_regex_panel.add(pair_data['panel'], main_gbc)
        self.panel.revalidate()
        self.panel.repaint()
    
    def actionPerformed(self, event):
        if event.getSource() == self.test_button:
            self.testTokenRequest()
        elif event.getSource() == self.save_button:
            self.saveConfiguration()
        elif event.getSource() == self.auto_refresh_checkbox:
            self.toggleAutoRefresh()
        elif event.getSource() == self.enable_extension_checkbox:
            self.toggleExtension()
        elif event.getSource() == self.add_regex_button:
            self.addRegexPair()    
            
    def addRegexPair(self):
        new_index = len(self.regex_pair_panels)
        self.regex_pairs.append({'response': '', 'request': '', 'replacement': '{token}'})
        self.createRegexPair(new_index)
    
    def testTokenRequest(self):
        self.addStatus("Testing token request...")
        thread = threading.Thread(target=self._testTokenRequestBackground)
        thread.daemon = True
        thread.start()
    
    def _testTokenRequestBackground(self):
        try:
            tokens_result = self._getNewTokenSync()
            if tokens_result:
                with self.token_lock:
                    if hasattr(self, 'current_tokens') and self.current_tokens:
                        self.addStatus("Got %d tokens total:" % len(self.current_tokens))
                        for pair_index, token_value in self.current_tokens.items():
                            self.addStatus("  Pair %d token: %s" % (pair_index + 1, token_value))
                    else:
                        self.addStatus("Got tokens but none stored")
            else:
                self.addStatus("Could not retrieve any tokens")
        except Exception as e:
            self.addStatus("Error in background token test: %s" % str(e))
    
    def toggleExtension(self):
        self.extension_enabled = self.enable_extension_checkbox.isSelected()
        if self.extension_enabled:
            self.startBackgroundWorker()  
            self.addStatus("Extension ENABLED - will process requests")
        else:
            self.stopBackgroundWorker()  
            self.addStatus("Extension DISABLED - will not process requests")
    
    def saveConfiguration(self):
        self.token_request_config['host'] = self.host_field.getText()
        self.token_request_config['port'] = int(self.port_field.getText())
        self.token_request_config['use_https'] = self.https_checkbox.isSelected()
        self.regex_pairs = []
        for pair_data in self.regex_pair_panels:
            self.regex_pairs.append({
                'response': pair_data['response_field'].getText(),
                'request': pair_data['request_field'].getText(),
                'replacement': pair_data['replacement_field'].getText()
            })               
        self.enabled_tools['scanner'] = self.scanner_checkbox.isSelected()
        self.enabled_tools['repeater'] = self.repeater_checkbox.isSelected()
        self.enabled_tools['intruder'] = self.intruder_checkbox.isSelected()
        self.enabled_tools['target'] = self.target_checkbox.isSelected()
        self.enabled_tools['sequencer'] = self.sequencer_checkbox.isSelected()
        self.enabled_tools['extender'] = self.extender_checkbox.isSelected()
        self.refresh_interval = self.interval_spinner.getValue()
        self.addStatus("Configuration saved successfully")
    
    def toggleAutoRefresh(self):
        self.auto_refresh_enabled = self.auto_refresh_checkbox.isSelected()
        if self.auto_refresh_enabled:
            self.startAutoRefresh()
            self.addStatus("Auto-refresh enabled with %d second interval" % self.refresh_interval)
        else:
            self.stopAutoRefresh()
            self.addStatus("Auto-refresh disabled")

    def startAutoRefresh(self):
        if self.scheduler and not self.scheduler.isShutdown():
            self.scheduler.shutdown()
            try:
                self.scheduler.awaitTermination(2, TimeUnit.SECONDS)  
            except:
                pass
        self.scheduler = Executors.newScheduledThreadPool(1)
        self.scheduler.scheduleAtFixedRate(
            TokenRefreshTask(self), 
            0, 
            self.refresh_interval, 
            TimeUnit.SECONDS
        )
    
    def stopAutoRefresh(self):
        if self.scheduler:
            self.scheduler.shutdown()
            self.scheduler = None
    
    def addStatus(self, message):
        current_text = self.status_area.getText()
        timestamp = time.strftime("%H:%M:%S")
        new_text = "[%s] %s\n%s" % (timestamp, message, current_text)
        self.status_area.setText(new_text)

    def startBackgroundWorker(self):
        if not hasattr(self, 'token_worker_thread') or self.token_worker_thread is None or not self.token_worker_thread.isAlive():
            self.shutdown_flag = False
            self.token_worker_thread = threading.Thread(target=self._tokenWorker)
            self.token_worker_thread.daemon = True
            self.token_worker_thread.start()

    def stopBackgroundWorker(self):
        self.shutdown_flag = True
        if hasattr(self, 'token_worker_thread') and self.token_worker_thread and self.token_worker_thread.isAlive():
            for i in range(50): 
                if not self.token_worker_thread.isAlive():
                    break
                time.sleep(0.1)

    def _tokenWorker(self):
        while not getattr(self, 'shutdown_flag', True):
            try:
                need_refresh = (not hasattr(self, 'current_tokens') or 
                              not self.current_tokens or 
                              (not self.auto_refresh_enabled and 
                               time.time() - getattr(self, 'token_last_updated', 0) > 30))
                if need_refresh and getattr(self, 'extension_enabled', False):
                    success = self._getNewTokenSync()
                    if success:
                        print("Background token refresh completed")
                for i in range(50): 
                    if getattr(self, 'shutdown_flag', True):
                        break
                    time.sleep(0.1)
            except Exception as e:
                print("Token worker error: %s" % str(e))
                time.sleep(1)
        print("Token worker thread stopped")

    def _getNewTokenSync(self):
        try:
            host = str(self.host_field.getText()).strip()
            port_text = str(self.port_field.getText()).strip()
            if not host or not port_text:
                return False
            try:
                port = int(port_text)
            except:
                return False
            use_https = self.https_checkbox.isSelected()
            headers_text = str(self.headers_area.getText())
            if not headers_text.strip():
                return False
            headers = []
            for line in headers_text.split('\n'):
                line = line.strip()
                if line:
                    headers.append(line)
            body = str(self.body_area.getText())
            message = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body))
            service = self.helpers.buildHttpService(host, port, use_https)
            response = self.callbacks.makeHttpRequest(service, message)
            if response is None:
                return False
            resp_str = self.helpers.bytesToString(response.getResponse())
            enabled_pairs = []
            for i, pair_data in enumerate(self.regex_pair_panels):
                if pair_data['enabled'].isSelected():
                    enabled_pairs.append((i, pair_data))
            if not enabled_pairs:
                return False
            extracted_tokens = {}
            for pair_index, pair_data in enabled_pairs:
                pattern = str(pair_data['response_field'].getText()).strip()
                if not pattern:
                    continue
                try:
                    match = re.search(pattern, resp_str, re.IGNORECASE)
                    if match and len(match.groups()) > 0:
                        token = match.group(1).strip()
                        extracted_tokens[pair_index] = token
                        print("Got token from pair %d: %s" % (pair_index + 1, token))
                except Exception as e:
                    print("Error in pair %d regex: %s" % (pair_index + 1, str(e)))
                    continue
            if extracted_tokens:
                with self.token_lock:
                    self.current_tokens = extracted_tokens
                    self.token_last_updated = time.time()
                return True
            return False
        except Exception as e:
            print("Error getting token: %s" % str(e))
            return False

    def getNewToken(self):
        try:
            host = self.host_field.getText().strip()
            port_text = self.port_field.getText().strip()
            self.addStatus("Getting token from %s:%s" % (host, port_text))
            if not host:
                self.addStatus("ERROR: Host field is empty!")
                return None  
            if not port_text:
                self.addStatus("ERROR: Port field is empty!")
                return None  
            try:
                port = int(port_text)
            except:
                self.addStatus("ERROR: Invalid port number: %s" % port_text)
                return None   
            use_https = self.https_checkbox.isSelected()
            headers_text = self.headers_area.getText()
            if not headers_text.strip():
                self.addStatus("ERROR: Headers field is empty!")
                return None 
            headers = []
            for line in headers_text.split('\n'):
                line = line.strip()
                if line:
                    headers.append(line)
            body = self.body_area.getText()
            try:
                message = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body))
            except Exception as e:
                self.addStatus("ERROR building HTTP message: %s" % str(e))
                return None
            try:
                service = self.helpers.buildHttpService(host, port, use_https)
            except Exception as e:
                self.addStatus("ERROR building HTTP service: %s" % str(e))
                return None
            try:
                response = self.callbacks.makeHttpRequest(service, message)
            except Exception as e:
                self.addStatus("ERROR making HTTP request: %s" % str(e))
                return None
            if response is None:
                self.addStatus("ERROR: Response is None")
                return None
            try:
                resp_str = self.helpers.bytesToString(response.getResponse())
            except Exception as e:
                self.addStatus("ERROR converting response: %s" % str(e))
                return None
            enabled_pairs = [pair for pair in self.regex_pair_panels if pair['enabled'].isSelected()]
            if not enabled_pairs:
                self.addStatus("ERROR: No regex pairs are enabled!")
                return None
            extracted_tokens = {}
            for pair_index, pair_data in enumerate(enabled_pairs):
                pattern = pair_data['response_field'].getText().strip()
                if not pattern:
                    self.addStatus("WARNING: Pair %d response regex is empty, skipping" % (pair_index + 1)) 
                    continue                                                                               
                self.addStatus("Trying pattern from pair %d: %s" % (pair_index + 1, pattern))    
                try:
                    match = re.search(pattern, resp_str, re.IGNORECASE)
                    if match:
                        token = match.group(1).strip()
                        extracted_tokens[pair_index] = token                                       
                        self.addStatus("Found token using pair %d: %s" % (pair_index + 1, token))  
                        print("Got token from pair %d: %s" % (pair_index + 1, token))             
                    else:
                        self.addStatus("No token found with pair %d pattern: %s" % (pair_index + 1, pattern))  
                except Exception as e:
                    self.addStatus("ERROR in pair %d regex search: %s" % (pair_index + 1, str(e)))   
            if extracted_tokens:                                                                   
                self.current_tokens = extracted_tokens  
                self.token_last_updated = time.time()                                             
                self.addStatus("Extracted %d tokens total" % len(extracted_tokens))     
                return True                                
            else:                                                                                  
                self.addStatus("No tokens found from any of the %d enabled pairs" % len(enabled_pairs))  
                preview = resp_str[:1000] if len(resp_str) > 1000 else resp_str                   
                self.addStatus("Response preview (first 1000 chars):")                            
                self.addStatus(preview)                                                            
                self.addStatus("--- End of response preview ---")                                 
                return None                                                                        
        except Exception as e:
            error_msg = "Error getting token: %s" % str(e)
            print(error_msg)
            self.addStatus(error_msg)
            return None
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or not self.extension_enabled:
            return
        tool_enabled = (
            (toolFlag == self.callbacks.TOOL_SCANNER and self.enabled_tools['scanner']) or
            (toolFlag == self.callbacks.TOOL_REPEATER and self.enabled_tools['repeater']) or
            (toolFlag == self.callbacks.TOOL_INTRUDER and self.enabled_tools['intruder']) or
            (toolFlag == self.callbacks.TOOL_TARGET and self.enabled_tools['target']) or
            (toolFlag == self.callbacks.TOOL_SEQUENCER and self.enabled_tools['sequencer']) or
            (toolFlag == self.callbacks.TOOL_EXTENDER and self.enabled_tools['extender'])
        )
        if not tool_enabled:
            return
        req = messageInfo.getRequest()
        req_str = self.helpers.bytesToString(req)
        replaced_count = 0
        matching_pairs = []
        for pair_index, pair_data in enumerate(self.regex_pair_panels):
            if pair_data['enabled'].isSelected():
                request_pattern = pair_data['request_field'].getText().strip()
                if request_pattern and re.search(request_pattern, req_str):
                    matching_pairs.append((pair_index, pair_data, request_pattern))
        if not matching_pairs:
            return 
        need_fresh_tokens = True
        if self.auto_refresh_enabled:
            with self.token_lock:
                current_time = time.time()
                if (hasattr(self, 'current_tokens') and self.current_tokens and 
                    (current_time - getattr(self, 'token_last_updated', 0)) < self.refresh_interval):
                    need_fresh_tokens = False
        if need_fresh_tokens:
            tokens_result = self._getNewTokenSync() 
            if not tokens_result:
                return  
        with self.token_lock:
            if hasattr(self, 'current_tokens') and self.current_tokens:
                for pair_index, pair_data, request_pattern in matching_pairs:
                    if pair_index in self.current_tokens:
                        token_for_this_pair = self.current_tokens[pair_index]
                        replacement = pair_data['replacement_field'].getText().replace('{token}', token_for_this_pair)
                        req_str = re.sub(request_pattern, replacement, req_str)
                        replaced_count += 1
        if replaced_count > 0:
            messageInfo.setRequest(self.helpers.stringToBytes(req_str))
        
    def getToolName(self, toolFlag):
        tool_names = {
            self.callbacks.TOOL_SCANNER: "Scanner",
            self.callbacks.TOOL_REPEATER: "Repeater", 
            self.callbacks.TOOL_INTRUDER: "Intruder",
            self.callbacks.TOOL_TARGET: "Target",
            self.callbacks.TOOL_SEQUENCER: "Sequencer",
            self.callbacks.TOOL_EXTENDER: "Extender"
        }
        return tool_names.get(toolFlag, "Unknown")
    
    def getTabCaption(self):
        return "SWAPPER"
    
    def getUiComponent(self):
        return self.panel
    
    def createMenuItems(self, invocation):
        menu_items = []
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE, 
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
        ]:
            menu_item = JMenuItem("Send to SWAPPER")
            menu_item.addActionListener(TokenMenuHandler(self, invocation))
            menu_items.append(menu_item)
            regex_test_item = JMenuItem("Test Request Regex")
            regex_test_item.addActionListener(RegexTestHandler(self, invocation))
            menu_items.append(regex_test_item)
        return menu_items
    
    def populateFromRequest(self, request_response):
        try:
            request = request_response.getRequest()
            service = request_response.getHttpService()
            request_info = self.helpers.analyzeRequest(service, request) 
            host = service.getHost()
            port = service.getPort()
            use_https = service.getProtocol() == "https"
            self.host_field.setText(host)
            self.port_field.setText(str(port))
            self.https_checkbox.setSelected(use_https)
            headers = request_info.getHeaders()
            headers_text = "\n".join(headers)
            self.headers_area.setText(headers_text)
            body_offset = request_info.getBodyOffset()
            request_bytes = request_response.getRequest()
            if body_offset < len(request_bytes):
                body_bytes = request_bytes[body_offset:]
                body_text = self.helpers.bytesToString(body_bytes)
                self.body_area.setText(body_text)
            else:
                self.body_area.setText("")
            self.addStatus("Populated configuration from %s %s://%s:%s" % (request_info.getMethod(), service.getProtocol(), host, port)) 
        except Exception as e:
            self.addStatus("Error populating from request: %s" % str(e))

    def testRequestRegexOnMessage(self, request_response):
        enabled_pairs = [pair for pair in self.regex_pair_panels if pair['enabled'].isSelected()]    
        if not enabled_pairs:                                                                        
            self.addStatus("ERROR: No regex pairs are enabled!")
            return
        try:
            request = request_response.getRequest()
            req_str = self.helpers.bytesToString(request)
            found_matches = []                                                        
            for i, pair_data in enumerate(enabled_pairs):                                           
                pattern = pair_data['request_field'].getText().strip()                              
                if not pattern:                                                                     
                    continue                                                                         
                try:                                                                  
                    match = re.search(pattern, req_str)
                    if match:
                        found_matches.append((i+1, pattern, match.group(0)))         
                except Exception as e:                                                
                    self.addStatus("ERROR in pair %d pattern '%s': %s" % (i+1, pattern, str(e)))   
            if found_matches:                                                         
                self.addStatus("Found %d matching patterns!" % len(found_matches))
                for pair_num, pattern, matched_content in found_matches:             
                    self.addStatus("Pair %d '%s' matched: '%s'" % (pair_num, pattern, matched_content))  
            else:
                self.addStatus("None of the enabled patterns matched")                       
                self.addStatus("Request preview: %s..." % req_str[:300])
        except Exception as e:
            self.addStatus("ERROR testing regex: %s" % str(e))   
		    
class TokenMenuHandler(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    def actionPerformed(self, event):
        selected_messages = self.invocation.getSelectedMessages()
        if selected_messages and len(selected_messages) > 0:
            self.extender.populateFromRequest(selected_messages[0])

class TokenRefreshTask(Runnable):
    def __init__(self, extender):
        self.extender = extender
    def run(self):
        try:
            token = self.extender.getNewToken()
            if token:
                self.extender.addStatus("Got new token")
            else:
                self.extender.addStatus("Failed to get token")
        except Exception as e:
            self.extender.addStatus("Auto-refresh error: %s" % str(e))
            
class RegexTestHandler(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    def actionPerformed(self, event):
        selected_messages = self.invocation.getSelectedMessages()
        if selected_messages and len(selected_messages) > 0:
            self.extender.testRequestRegexOnMessage(selected_messages[0])
