# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IExtensionStateListener
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Color
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JCheckBox, JButton, JScrollPane, BorderFactory, JSpinner, SpinnerNumberModel, JMenuItem, SwingUtilities, JComboBox, DefaultComboBoxModel
from java.awt.event import ActionListener, ItemListener
from java.util.concurrent import Executors, TimeUnit
from javax.swing.event import DocumentListener as JDocumentListener, ChangeListener as JChangeListener
import re
import threading
import time

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IExtensionStateListener, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SWAPPER")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        self.token_lock = threading.Lock()
        self.scheduler = None
        self.token_endpoints = [
            {
                'poll': 1,
                'host': 'the.host.net',
                'port': 443,
                'use_https': True,
                'headers': 'Can build out your Request Headers here\nOr they will populate when you send to SWAPPER\n',
                'body': 'You can build the request body here\nOr find the request to send in your history and send to SWAPPER\n'
            }
        ]
        self.STOCK_HOST = 'the.host.net'
        self.STOCK_HEADERS = 'Can build out your Request Headers here\nOr they will populate when you send to SWAPPER\n'
        self.STOCK_BODY = 'You can build the request body here\nOr find the request to send in your history and send to SWAPPER\n'
        self.replace_on_send = True
        self.endpoint_panels = []
        self._suppress_selector_event = False
        self.selected_endpoint_index = 0
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
        self.current_token = None
        self.current_tokens = {}
        self.token_last_updated = 0
        self._unsaved_changes = False
        self.createGUI()
        callbacks.addSuiteTab(self)
        print("Started SWAPPER")
        print("Author: Dave Blandford")
        print("Twitter: @hackr1ot")
        print("Email: dave@mailo.com")
        print(
        '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
mQGNBGSNEtsBDAC1UCGz94jKVspY7Arb32h+2dlUTM8tAJt/l+TF7T52MRiiVEX6
55AXr7UXfgzpT75c0GsH6rzfRG8pmXP08fCTzpiwpRZJK8PA+Fys2g10CRtw/Bt1
3G8mTKDmWOqQkcrpMzHgFfnFYOlyLpAvxoDrDEwl4l3sEYD6GPOGqKDZvFjiHgY/
jKh/+hSitjVFAiXbR/FVaR5W81LhFxlik/delK592n/BNCPygkavqASyFExBTFCJ
EJOH7wDQS/sUe11Npknh24JQJfDhaDRVeZ3ik0y3cuMSiNjehskzfG5AmTV6PVPm
VFITwpZ8hCRsB4ciP35OkJ8eVDpSHeI1i0wBEbrqWzReag6HpCRopffQL1yiO6Om
6UJ30vXFd3+PrKMuyVTq34e68R5yRY2PiHBdPbbnp2DDQv0d77H9zSkn/lJNIbcC
VotKwCi2C/Q1NiyaxneXfrlnyA1rRFn6ozuqvFjQt6NzwwjKTPj/pAZsu7a6VfPc
tmVEnv3vdOH9QwcAEQEAAbQfZGF2ZUBtYWlsby5jb20gPGRhdmVAbWFpbG8uY29t
PokBsAQTAQoAGgQLCQgHAhUKAhYBAhkBBYJkjRLbAp4BApsDAAoJEPIgx29nyJfw
HiQMAJ5gQXTHAWCHPtgspu0FQG8aSHVNhgkpydRVAiU5aYjxXGcyobFGupvoc2Gk
9+TaFBBCHI22qrMs41YeUTVIJLF1OHoTjJGHMtq2PoJdcO6ys/Gf5v4AX9fzfblk
EMKvLv1wB+GehAQE25AroYqoOI+hLae4fHA0WL7veLhXEtqpH1qt1+4DHzGD2Rzo
9WGBrsAlPIG1YCh5F1g1nxBEbGR/TL+76t9PIH+y7WHOyWMmLQw3IYqKg6OtlipH
re9fFco1kgrZuP1Hi16vklNe/10xpD1T+En7u4JWxos4YYw7RhQ/Kcpw1nrxvBGJ
Fxisn165lyhAIeMqdj3lZrZFGYLyaNkWwfSDZ6MHdb40mj2irMOgm1F+vC+rESeM
84+HNGnnhGxhmKdRdUAMlJRt0pwEEU9Pbn3VfNFmKSRmvRVR2SM+PGTFz2gUErpO
UgbllXSwqO/EcnLcQ/+wrtXHReScsQIFXDkoEQgs1t4kHC5xHsAYTxOMQkBJxSR3
YQLHVbkBjQRkjRLbAQwAnUlq4VLwvevWsiuyJRsMleUAQsuvDotTQ+8675nqznCU
km5SaMU22rpeWXmZwOnFsQqKV82ARfNpEBXKeLWZlEBas+q8nWCkKqkWN7tEFKKk
4MnmMnzplKj5NVCQu7xpaf8niIbF6VIubO3qj0j5Gq6Yk7m15ROIJH/bpvJMQ2Ol
2zO2kyKIm5fIjD/M/IWClCoZtTWDwUSgF3EzrSDsqdGIjXW2qyyfhxOct1B3s+lB
bWLkBUzm/54NqizgkgpUJtbnnVNcgQBGHg9TB/ZjmbyrSHY4g2DG0qA3Z8Qo2M08
J9SfFG731wQO87RtCpCdIKSOvHjLVT4sdqUHRyIWye1lABwyvbcpxVwcsOImLC8H
iy9RrqdmZdgI5bdEVHTmfHUFahTGWYjmiBU37yCe0YtnL5LMHXpS7z7cfuEvAkRG
FWV0J0OP1Zv/gPhWg2zIU3JN3j/vydFnimXvxWiY6W3LDm+FtxGo4Vnv43LbDbo6
076oEHq1jdzt45b9zVFhABEBAAGJAbYEGAEKAAkFgmSNEtsCmwwAIQkQ8iDHb2fI
l/AWIQRGhTbxG1Jvt4C3axzyIMdvZ8iX8Jl2C/4qT8oqTOqP37pADcQUbcpxrixB
S79HxvyjoSCUihW4MVcYF/86gvhVrCCLShEnDEQrLRELzKyCPL67wESb5wUvEtdY
H40dEopUOHSyWN2TnCbdP1Pdxso42E3UC97HrpGG2CpUF4dFdzeivj4h60QGZmVF
PD6Tqp6Mk9RfYXGDGiOgAOZoVM15aMvykSQnXJg7d2WMB4mDg8ozQAjXF3DIq9R7
X5KiWQE03BYBowZFipNVR4uVwSC7ni7vhu3PsatDCXpo+LNUkZ1nOykZQN/l8UZJ
xjG6Su8XG20EELWQbiq5JelREzhew4IPlPzJE8Ue559SzmP8RJCR9Tjqpe3oJYaL
s6giNTcizv/Ph+uj7w5Rykqy7rdmtDh9h3Q9NpVhOcJeQCxj8sWzbmNOx91nhmvD
9XcoMbAbJuiuWIEl9/iSJxe6NNxKQcJYjRk3jqk+H8DMgk+cXdKy+H/0dFrznO4f
JSYTJzaX2Ds2ClCwTyz5P4Gjx6CoKwBIdsEspog=
=iIJQ
-----END PGP PUBLIC KEY BLOCK-----
        '''
        )

    def extensionUnloaded(self):
        print("SWAPPER: Unloading extension, cleaning up...")
        self._stopRefreshTimer()
        print("SWAPPER: Cleanup complete.")

    def _startRefreshTimer(self):
        self._stopRefreshTimer()
        self.scheduler = Executors.newSingleThreadScheduledExecutor()
        self.scheduler.scheduleAtFixedRate(
            ScheduledRefreshTask(self),
            0,
            self.refresh_interval,
            TimeUnit.SECONDS
        )

    def _stopRefreshTimer(self):
        if self.scheduler is not None:
            self.scheduler.shutdownNow()
            self.scheduler = None

    def _onRefreshTimerFire(self):
        if not self.extension_enabled or not self.auto_refresh_enabled:
            return
        try:
            success = self._getNewTokenSync()
            if success:
                self.addStatus("got new token")
            else:
                self.addStatus("failed to get token")
        except Exception as e:
            self.addStatus("error: %s" % str(e))

    def _syncTimerState(self):
        if self.extension_enabled and self.auto_refresh_enabled:
            self._startRefreshTimer()
        else:
            self._stopRefreshTimer()

    def _markUnsaved(self):
        if not self._unsaved_changes:
            self._unsaved_changes = True
            self.save_button.setText("Save Configuration (unsaved changes)")
            self.save_button.setForeground(Color(0x8B, 0x00, 0x00))

    def _markSaved(self):
        self._unsaved_changes = False
        self.save_button.setText("Save Configuration")
        self.save_button.setForeground(None)

    def _attachChangeListener(self, component):
        component.addActionListener(UnsavedChangeListener(self))

    def _attachDocChangeListener(self, text_component):
        text_component.getDocument().addDocumentListener(UnsavedDocListener(self))

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

An extension for easy match/replace of tokens/CSRF/anything using regex. Handles XML and JSON. By default, SWAPPER sends a request to obtain the token/value every 4 minutes. You can change the time to request a new token. Disabling auto-refresh will request a token for each request(needed every now and again...). A new value will be requested for each interval. Can pull multiple patterns out of response and set multiple patterns to replace.

MULTIPLE ENDPOINTS:
Add as many token endpoints as you need in the SWAPPER Configuration area. Each endpoint has a Poll # and endpoints are polled in ASCENDING order (1, then 2, then 3...) based on the interval. Use the Host dropdown at the top to switch which endpoint you are viewing/editing. Change an endpoint's Poll # to reorder it. The Regex Configuration is global so every enabled Response Regex is run against EVERY endpoint's response, meaning tokens accumulate across all endpoints.

HOW TO USE:

1. Right-click on any request in Target/History
2. Select "Send to Swapper" to populate an fields. 
3. Set up regex patterns for token extraction/replacement
4. Test your configuration
5. Enable tools and auto-refresh as needed

To check regex matches, Test Token Request will poll all endpoints and display regex hit/miss in status box. For the request, go to request you want to check in Proxy history/History/Target, right click and under extensions, select `Test Request Regex`. Resulting hit/miss will show in status box.
""")
        self.instructions_area.setLineWrap(True)
        self.instructions_area.setWrapStyleWord(True)
        instructions_scroll = JScrollPane(self.instructions_area)
        instructions_section.add(instructions_scroll, BorderLayout.CENTER)
        token_section = JPanel(BorderLayout())
        token_section.setBorder(BorderFactory.createTitledBorder("SWAPPER Configuration"))
        token_section.setPreferredSize(Dimension(400, 300))
        endpoint_top_bar = JPanel(GridBagLayout())
        bar_gbc = GridBagConstraints()
        bar_gbc.insets = Insets(2, 4, 2, 4)
        bar_gbc.anchor = GridBagConstraints.WEST
        bar_gbc.gridx = 0; bar_gbc.gridy = 0
        endpoint_top_bar.add(JLabel("Host:"), bar_gbc)
        bar_gbc.gridx = 1; bar_gbc.fill = GridBagConstraints.HORIZONTAL; bar_gbc.weightx = 1.0
        self.host_selector_model = DefaultComboBoxModel()
        self.host_selector = JComboBox(self.host_selector_model)
        self.host_selector.addItemListener(HostSelectorListener(self))
        endpoint_top_bar.add(self.host_selector, bar_gbc)
        bar_gbc.gridx = 2; bar_gbc.fill = GridBagConstraints.NONE; bar_gbc.weightx = 0
        self.replace_on_send_checkbox = JCheckBox("Replace on Send to SWAPPER", self.replace_on_send)
        self.replace_on_send_checkbox.addActionListener(self)
        endpoint_top_bar.add(self.replace_on_send_checkbox, bar_gbc)
        token_section.add(endpoint_top_bar, BorderLayout.NORTH)
        self.main_endpoint_panel = JPanel(BorderLayout())
        endpoint_scroll = JScrollPane(self.main_endpoint_panel)
        token_section.add(endpoint_scroll, BorderLayout.CENTER)
        endpoint_button_panel = JPanel()
        self.add_endpoint_button = JButton("Add Endpoint")
        self.add_endpoint_button.addActionListener(self)
        endpoint_button_panel.add(self.add_endpoint_button)
        token_section.add(endpoint_button_panel, BorderLayout.SOUTH)
        top_gbc.gridx = 0; top_gbc.gridy = 0; top_gbc.fill = GridBagConstraints.BOTH; top_gbc.weightx = 0.5; top_gbc.weighty = 1.0
        top_panel.add(instructions_section, top_gbc)
        top_gbc.gridx = 1; top_gbc.weightx = 0.5
        top_panel.add(token_section, top_gbc)
        self.selected_endpoint_index = 0
        for ep in self.token_endpoints:
            self._buildEndpointPanel(ep)
        self.refreshEndpointDisplay()
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
        control_gbc.gridy = 1
        tools_sub_panel = JPanel(GridBagLayout())
        tools_gbc = GridBagConstraints()
        tools_gbc.insets = Insets(2, 2, 2, 2)
        tools_gbc.anchor = GridBagConstraints.WEST
        tools_gbc.gridx = 0; tools_gbc.gridy = 0
        self.scanner_checkbox = JCheckBox("Scanner", self.enabled_tools['scanner'])
        tools_sub_panel.add(self.scanner_checkbox, tools_gbc)
        tools_gbc.gridx = 1
        self.repeater_checkbox = JCheckBox("Repeater", self.enabled_tools['repeater'])
        tools_sub_panel.add(self.repeater_checkbox, tools_gbc)
        tools_gbc.gridx = 2
        self.intruder_checkbox = JCheckBox("Intruder", self.enabled_tools['intruder'])
        tools_sub_panel.add(self.intruder_checkbox, tools_gbc)
        tools_gbc.gridx = 0; tools_gbc.gridy = 1
        self.target_checkbox = JCheckBox("Target", self.enabled_tools['target'])
        tools_sub_panel.add(self.target_checkbox, tools_gbc)
        tools_gbc.gridx = 1
        self.sequencer_checkbox = JCheckBox("Sequencer", self.enabled_tools['sequencer'])
        tools_sub_panel.add(self.sequencer_checkbox, tools_gbc)
        tools_gbc.gridx = 2
        self.extender_checkbox = JCheckBox("Extender", self.enabled_tools['extender'])
        tools_sub_panel.add(self.extender_checkbox, tools_gbc)
        control_panel.add(tools_sub_panel, control_gbc)
        control_gbc.gridx = 1; control_gbc.gridy = 0; control_gbc.gridheight = 2
        refresh_sub_panel = JPanel(GridBagLayout())
        refresh_gbc = GridBagConstraints()
        refresh_gbc.insets = Insets(3, 3, 3, 3)
        refresh_gbc.anchor = GridBagConstraints.WEST
        refresh_gbc.gridx = 0; refresh_gbc.gridy = 0
        self.auto_refresh_checkbox = JCheckBox("Enable Auto-refresh", self.auto_refresh_enabled)
        self.auto_refresh_checkbox.addActionListener(self)
        refresh_sub_panel.add(self.auto_refresh_checkbox, refresh_gbc)
        refresh_gbc.gridy = 1
        refresh_sub_panel.add(JLabel("Interval (seconds):"), refresh_gbc)
        refresh_gbc.gridy = 2
        self.interval_spinner = JSpinner(SpinnerNumberModel(self.refresh_interval, 1, 3600, 1))
        refresh_sub_panel.add(self.interval_spinner, refresh_gbc)
        control_panel.add(refresh_sub_panel, control_gbc)
        control_section.add(control_panel, BorderLayout.CENTER)
        button_panel = JPanel()
        self.test_button = JButton("Test Token Request")
        self.test_button.addActionListener(self)
        self.save_button = JButton("Save Configuration")
        self.save_button.addActionListener(self)
        button_panel.add(self.test_button)
        button_panel.add(self.save_button)
        self._markUnsaved()
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
        gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE
        content_panel.add(button_panel, gbc)
        gbc.gridy = 4; gbc.fill = GridBagConstraints.BOTH; gbc.weighty = 1.0
        content_panel.add(status_scroll, gbc)
        scroll_pane = JScrollPane(content_panel)
        self.panel.add(scroll_pane, BorderLayout.CENTER)
        self._attachChangeListener(self.scanner_checkbox)
        self._attachChangeListener(self.repeater_checkbox)
        self._attachChangeListener(self.intruder_checkbox)
        self._attachChangeListener(self.target_checkbox)
        self._attachChangeListener(self.sequencer_checkbox)
        self._attachChangeListener(self.extender_checkbox)
        self.interval_spinner.addChangeListener(UnsavedSpinnerListener(self))
    def _buildEndpointPanel(self, ep):
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Endpoint"))
        e_gbc = GridBagConstraints()
        e_gbc.insets = Insets(3, 3, 3, 3)
        e_gbc.anchor = GridBagConstraints.WEST

        connection_panel = JPanel(GridBagLayout())
        conn_gbc = GridBagConstraints()
        conn_gbc.insets = Insets(2, 2, 2, 2)
        conn_gbc.gridx = 0; conn_gbc.gridy = 0
        connection_panel.add(JLabel("Poll:"), conn_gbc)
        conn_gbc.gridx = 1; conn_gbc.fill = GridBagConstraints.NONE; conn_gbc.weightx = 0
        poll_spinner = JSpinner(SpinnerNumberModel(int(ep.get('poll', 1)), 1, 999, 1))
        connection_panel.add(poll_spinner, conn_gbc)
        conn_gbc.gridx = 2; conn_gbc.fill = GridBagConstraints.NONE; conn_gbc.weightx = 0
        connection_panel.add(JLabel("Host:"), conn_gbc)
        conn_gbc.gridx = 3; conn_gbc.fill = GridBagConstraints.HORIZONTAL; conn_gbc.weightx = 1.0
        host_field = JTextField(str(ep.get('host', '')), 15)
        connection_panel.add(host_field, conn_gbc)
        conn_gbc.gridx = 4; conn_gbc.fill = GridBagConstraints.NONE; conn_gbc.weightx = 0
        connection_panel.add(JLabel("Port:"), conn_gbc)
        conn_gbc.gridx = 5; conn_gbc.fill = GridBagConstraints.HORIZONTAL; conn_gbc.weightx = 0.3
        port_field = JTextField(str(ep.get('port', 443)), 6)
        connection_panel.add(port_field, conn_gbc)
        conn_gbc.gridx = 6; conn_gbc.fill = GridBagConstraints.NONE; conn_gbc.weightx = 0
        https_checkbox = JCheckBox("HTTPS", bool(ep.get('use_https', True)))
        connection_panel.add(https_checkbox, conn_gbc)
        e_gbc.gridx = 0; e_gbc.gridy = 0; e_gbc.gridwidth = 2
        e_gbc.fill = GridBagConstraints.HORIZONTAL; e_gbc.weightx = 1.0
        panel.add(connection_panel, e_gbc)
        e_gbc.gridx = 0; e_gbc.gridy = 1; e_gbc.gridwidth = 2; e_gbc.fill = GridBagConstraints.NONE; e_gbc.weightx = 0
        panel.add(JLabel("Headers:"), e_gbc)
        e_gbc.gridx = 0; e_gbc.gridy = 2; e_gbc.fill = GridBagConstraints.BOTH; e_gbc.weightx = 1.0; e_gbc.weighty = 0.4
        headers_area = JTextArea(5, 30)
        headers_area.setLineWrap(True)
        headers_area.setWrapStyleWord(True)
        headers_area.setText(str(ep.get('headers', '')))
        panel.add(JScrollPane(headers_area), e_gbc)

        e_gbc.gridx = 0; e_gbc.gridy = 3; e_gbc.weighty = 0; e_gbc.fill = GridBagConstraints.NONE
        panel.add(JLabel("Body:"), e_gbc)
        e_gbc.gridx = 0; e_gbc.gridy = 4; e_gbc.fill = GridBagConstraints.BOTH; e_gbc.weightx = 1.0; e_gbc.weighty = 0.6
        body_area = JTextArea(6, 30)
        body_area.setLineWrap(True)
        body_area.setWrapStyleWord(True)
        body_area.setText(str(ep.get('body', '')))
        panel.add(JScrollPane(body_area), e_gbc)
        ctrl_panel = JPanel()
        remove_button = JButton("Remove This Endpoint")
        remove_button.addActionListener(EndpointRemoveHandler(self, panel))
        ctrl_panel.add(remove_button)
        e_gbc.gridx = 0; e_gbc.gridy = 5; e_gbc.weighty = 0; e_gbc.fill = GridBagConstraints.NONE
        panel.add(ctrl_panel, e_gbc)
        self._attachDocChangeListener(host_field)
        self._attachDocChangeListener(port_field)
        self._attachChangeListener(https_checkbox)
        self._attachDocChangeListener(headers_area)
        self._attachDocChangeListener(body_area)
        poll_spinner.addChangeListener(PollChangeListener(self))

        ep_data = {
            'panel': panel,
            'poll_spinner': poll_spinner,
            'host_field': host_field,
            'port_field': port_field,
            'https_checkbox': https_checkbox,
            'headers_area': headers_area,
            'body_area': body_area
        }
        self.endpoint_panels.append(ep_data)
        return ep_data

    def _endpointLabel(self, idx, ep_data):
        poll = ep_data['poll_spinner'].getValue()
        host = ep_data['host_field'].getText().strip() or "(no host)"
        return "Poll %s - %s" % (poll, host)

    def _sortEndpointsByPoll(self):
        decorated = []
        for i, ep_data in enumerate(self.endpoint_panels):
            try:
                poll = int(ep_data['poll_spinner'].getValue())
            except:
                poll = 1
            decorated.append((poll, i, ep_data))
        decorated.sort(key=lambda t: (t[0], t[1]))
        self.endpoint_panels = [d[2] for d in decorated]

    def _rebuildHostSelector(self):
        self.host_selector_model.removeAllElements()
        for i, ep_data in enumerate(self.endpoint_panels):
            self.host_selector_model.addElement(self._endpointLabel(i, ep_data))
        if self.endpoint_panels:
            if self.selected_endpoint_index >= len(self.endpoint_panels):
                self.selected_endpoint_index = len(self.endpoint_panels) - 1
            if self.selected_endpoint_index < 0:
                self.selected_endpoint_index = 0
            self.host_selector.setSelectedIndex(self.selected_endpoint_index)

    def refreshEndpointDisplay(self):
        self._sortEndpointsByPoll()
        self._suppress_selector_event = True
        self._rebuildHostSelector()
        self._suppress_selector_event = False
        self._showSelectedEndpoint()

    def _showSelectedEndpoint(self):
        self.main_endpoint_panel.removeAll()
        if self.endpoint_panels:
            idx = self.selected_endpoint_index
            if idx < 0 or idx >= len(self.endpoint_panels):
                idx = 0
                self.selected_endpoint_index = 0
            ep_data = self.endpoint_panels[idx]
            ep_data['panel'].setBorder(BorderFactory.createTitledBorder(
                "Endpoint (%s)" % self._endpointLabel(idx, ep_data)))
            self.main_endpoint_panel.add(ep_data['panel'], BorderLayout.CENTER)
        self.main_endpoint_panel.revalidate()
        self.main_endpoint_panel.repaint()
        self.panel.revalidate()
        self.panel.repaint()

    def onHostSelected(self, index):
        if getattr(self, '_suppress_selector_event', False):
            return
        if index is None or index < 0:
            return
        self.selected_endpoint_index = index
        self._showSelectedEndpoint()

    def onPollChanged(self):
        if not hasattr(self, 'host_selector'):
            return
        current = None
        if 0 <= self.selected_endpoint_index < len(self.endpoint_panels):
            current = self.endpoint_panels[self.selected_endpoint_index]
        self._sortEndpointsByPoll()
        if current is not None and current in self.endpoint_panels:
            self.selected_endpoint_index = self.endpoint_panels.index(current)
        self._suppress_selector_event = True
        self._rebuildHostSelector()
        self._suppress_selector_event = False
        self._showSelectedEndpoint()
        self._markUnsaved()

    def _nextPollNumber(self):
        highest = 0
        for ep_data in self.endpoint_panels:
            try:
                v = int(ep_data['poll_spinner'].getValue())
                if v > highest:
                    highest = v
            except:
                pass
        return highest + 1

    def addEndpoint(self, ep=None, select_new=True):
        if ep is None:
            ep = {'host': '', 'port': 443, 'use_https': True, 'headers': '', 'body': ''}
        if 'poll' not in ep:
            ep['poll'] = self._nextPollNumber()
        new_ep = self._buildEndpointPanel(ep)
        if select_new:
            self._sortEndpointsByPoll()
            self.selected_endpoint_index = self.endpoint_panels.index(new_ep)
        self.refreshEndpointDisplay()
        self._markUnsaved()
        return new_ep

    def _findEndpointByPanel(self, panel):
        for idx, ep_data in enumerate(self.endpoint_panels):
            if ep_data['panel'] == panel:
                return idx
        return -1

    def removeEndpoint(self, panel):
        idx = self._findEndpointByPanel(panel)
        if idx < 0:
            return
        if len(self.endpoint_panels) <= 1:
            self.addStatus("Cannot remove the last endpoint")
            return
        del self.endpoint_panels[idx]
        if self.selected_endpoint_index >= len(self.endpoint_panels):
            self.selected_endpoint_index = len(self.endpoint_panels) - 1
        self.refreshEndpointDisplay()
        self._markUnsaved()

    def _isStockEndpoint(self, ep_data):
        host = ep_data['host_field'].getText().strip()
        headers = ep_data['headers_area'].getText()
        body = ep_data['body_area'].getText()
        return (host == self.STOCK_HOST and
                headers == self.STOCK_HEADERS and
                body == self.STOCK_BODY)

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
        self._attachDocChangeListener(response_field)
        self._attachDocChangeListener(request_field)
        self._attachDocChangeListener(replacement_field)
        self._attachChangeListener(enable_checkbox)
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
        elif event.getSource() == self.add_endpoint_button:
            self.addEndpoint()
        elif event.getSource() == self.replace_on_send_checkbox:
            self.replace_on_send = self.replace_on_send_checkbox.isSelected()

    def addRegexPair(self):
        new_index = len(self.regex_pair_panels)
        self.regex_pairs.append({'response': '', 'request': '', 'replacement': '{token}'})
        self.createRegexPair(new_index)
        self._markUnsaved()

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
                    if self.current_tokens:
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
            self._syncTimerState()
            self.addStatus("Extension ENABLED")
        else:
            self._syncTimerState()
            self.addStatus("Extension DISABLED")

    def saveConfiguration(self):
        self.refreshEndpointDisplay()
        self.token_endpoints = []
        for ep_data in self.endpoint_panels:
            try:
                port_val = int(ep_data['port_field'].getText().strip())
            except:
                port_val = 0
            try:
                poll_val = int(ep_data['poll_spinner'].getValue())
            except:
                poll_val = 1
            self.token_endpoints.append({
                'poll': poll_val,
                'host': ep_data['host_field'].getText().strip(),
                'port': port_val,
                'use_https': ep_data['https_checkbox'].isSelected(),
                'headers': ep_data['headers_area'].getText(),
                'body': ep_data['body_area'].getText()
            })
        self.replace_on_send = self.replace_on_send_checkbox.isSelected()
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
        old_interval = self.refresh_interval
        self.refresh_interval = self.interval_spinner.getValue()
        if old_interval != self.refresh_interval and self.scheduler is not None:
            self._syncTimerState()
        self._markSaved()
        self.addStatus("Configuration saved successfully (%d endpoints)" % len(self.token_endpoints))

    def toggleAutoRefresh(self):
        self.auto_refresh_enabled = self.auto_refresh_checkbox.isSelected()
        self._syncTimerState()
        if self.auto_refresh_enabled:
            self.addStatus("Auto-refresh enabled with %d second interval" % self.refresh_interval)
        else:
            self.addStatus("Auto-refresh disabled")

    def addStatus(self, message):
        current_text = self.status_area.getText()
        timestamp = time.strftime("%H:%M:%S")
        new_text = "[%s] %s\n%s" % (timestamp, message, current_text)
        self.status_area.setText(new_text)

    def cleanHttpResponse(self, response_string):
        cleaned = response_string.replace('\r\n', '\n').replace('\r', '\n')
        return cleaned

    def cleanHttpRequest(self, request_string):
        cleaned = request_string.replace('\r\n', '\n').replace('\r', '\n')
        return cleaned

    def _applyChainPlaceholders(self, text, tokens_so_far):
        if not text:
            return text
        for pair_index, token_value in tokens_so_far.items():
            text = text.replace('{token%d}' % (pair_index + 1), token_value)
        return text

    def _getNewTokenSync(self):
        try:
            endpoints = []
            for ep_data in self.endpoint_panels:
                try:
                    poll_val = int(ep_data['poll_spinner'].getValue())
                except:
                    poll_val = 1
                endpoints.append({
                    'poll': poll_val,
                    'host': str(ep_data['host_field'].getText()).strip(),
                    'port_text': str(ep_data['port_field'].getText()).strip(),
                    'use_https': ep_data['https_checkbox'].isSelected(),
                    'headers_text': str(ep_data['headers_area'].getText()),
                    'body_text': str(ep_data['body_area'].getText())
                })
            endpoints.sort(key=lambda e: e['poll'])
            if not endpoints:
                return False

            enabled_pairs = []
            for i, pair_data in enumerate(self.regex_pair_panels):
                if pair_data['enabled'].isSelected():
                    enabled_pairs.append((i, pair_data))
            if not enabled_pairs:
                return False

            extracted_tokens = {}
            for ep_num, ep in enumerate(endpoints):
                host = ep['host']
                if not host or not ep['port_text']:
                    continue
                try:
                    port = int(ep['port_text'])
                except:
                    continue

                headers_text = self._applyChainPlaceholders(ep['headers_text'], extracted_tokens)
                body_text = self._applyChainPlaceholders(ep['body_text'], extracted_tokens)
                if not headers_text.strip():
                    continue
                headers = []
                for line in headers_text.split('\n'):
                    line = line.strip()
                    if line:
                        headers.append(line)

                try:
                    message = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body_text))
                    service = self.helpers.buildHttpService(host, port, ep['use_https'])
                    response = self.callbacks.makeHttpRequest(service, message)
                except Exception as e:
                    print("Endpoint #%d request error: %s" % (ep_num + 1, str(e)))
                    continue
                if response is None:
                    continue
                resp_str = self.helpers.bytesToString(response.getResponse())
                resp_str_clean = self.cleanHttpResponse(resp_str)

                for pair_index, pair_data in enabled_pairs:
                    pattern = str(pair_data['response_field'].getText()).strip()
                    if not pattern:
                        continue
                    try:
                        match = re.search(pattern, resp_str_clean, re.IGNORECASE)
                        if match and len(match.groups()) > 0:
                            token = match.group(1).strip()
                            extracted_tokens[pair_index] = token
                            print("Got token from endpoint %d, pair %d: %s" % (ep_num + 1, pair_index + 1, token))
                    except Exception as e:
                        print("Error in pair %d regex (endpoint %d): %s" % (pair_index + 1, ep_num + 1, str(e)))
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
            endpoints = []
            for ep_data in self.endpoint_panels:
                try:
                    poll_val = int(ep_data['poll_spinner'].getValue())
                except:
                    poll_val = 1
                endpoints.append({
                    'poll': poll_val,
                    'host': ep_data['host_field'].getText().strip(),
                    'port_text': ep_data['port_field'].getText().strip(),
                    'use_https': ep_data['https_checkbox'].isSelected(),
                    'headers_text': ep_data['headers_area'].getText(),
                    'body_text': ep_data['body_area'].getText()
                })
            endpoints.sort(key=lambda e: e['poll'])
            if not endpoints:
                self.addStatus("ERROR: No endpoints configured!")
                return None

            enabled_pairs = [(i, p) for i, p in enumerate(self.regex_pair_panels) if p['enabled'].isSelected()]
            if not enabled_pairs:
                self.addStatus("ERROR: No regex pairs are enabled!")
                return None

            extracted_tokens = {}
            for ep_num, ep in enumerate(endpoints):
                host = ep['host']
                port_text = ep['port_text']
                self.addStatus("Endpoint #%d: getting token from %s:%s" % (ep_num + 1, host, port_text))
                if not host:
                    self.addStatus("  ERROR: Host field is empty, skipping")
                    continue
                if not port_text:
                    self.addStatus("  ERROR: Port field is empty, skipping")
                    continue
                try:
                    port = int(port_text)
                except:
                    self.addStatus("  ERROR: Invalid port number: %s" % port_text)
                    continue

                headers_text = self._applyChainPlaceholders(ep['headers_text'], extracted_tokens)
                body_text = self._applyChainPlaceholders(ep['body_text'], extracted_tokens)
                if not headers_text.strip():
                    self.addStatus("  ERROR: Headers field is empty, skipping")
                    continue
                headers = []
                for line in headers_text.split('\n'):
                    line = line.strip()
                    if line:
                        headers.append(line)
                try:
                    message = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(body_text))
                    service = self.helpers.buildHttpService(host, port, ep['use_https'])
                    response = self.callbacks.makeHttpRequest(service, message)
                except Exception as e:
                    self.addStatus("  ERROR making request: %s" % str(e))
                    continue
                if response is None:
                    self.addStatus("  ERROR: Response is None")
                    continue
                try:
                    resp_str = self.helpers.bytesToString(response.getResponse())
                except Exception as e:
                    self.addStatus("  ERROR converting response: %s" % str(e))
                    continue

                for pair_index, pair_data in enabled_pairs:
                    pattern = pair_data['response_field'].getText().strip()
                    if not pattern:
                        continue
                    try:
                        match = re.search(pattern, resp_str, re.IGNORECASE)
                        if match:
                            token = match.group(1).strip()
                            extracted_tokens[pair_index] = token
                            self.addStatus("  Found token (pair %d): %s" % (pair_index + 1, token))
                        else:
                            self.addStatus("  No match for pair %d: %s" % (pair_index + 1, pattern))
                    except Exception as e:
                        self.addStatus("  ERROR in pair %d regex: %s" % (pair_index + 1, str(e)))

            if extracted_tokens:
                self.current_tokens = extracted_tokens
                self.token_last_updated = time.time()
                self.addStatus("Extracted %d tokens total across %d endpoints" % (len(extracted_tokens), len(endpoints)))
                return True
            else:
                self.addStatus("No tokens found from any endpoint")
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
        req_str_clean = self.cleanHttpRequest(req_str)
        replaced_count = 0
        matching_pairs = []
        for pair_index, pair_data in enumerate(self.regex_pair_panels):
            if pair_data['enabled'].isSelected():
                request_pattern = pair_data['request_field'].getText().strip()
                if request_pattern and re.search(request_pattern, req_str_clean):
                    matching_pairs.append((pair_index, pair_data, request_pattern))
        if not matching_pairs:
            return
        need_fresh_tokens = not self.auto_refresh_enabled
        if self.auto_refresh_enabled:
            with self.token_lock:
                current_time = time.time()
                if (not self.current_tokens or
                    (current_time - self.token_last_updated) >= self.refresh_interval):
                    need_fresh_tokens = True
        if need_fresh_tokens:
            tokens_result = self._getNewTokenSync()
            if not tokens_result:
                with self.token_lock:
                    if not self.current_tokens:
                        return
        with self.token_lock:
            if self.current_tokens:
                for pair_index, pair_data, request_pattern in matching_pairs:
                    if pair_index in self.current_tokens:
                        token_for_this_pair = self.current_tokens.pop(pair_index)
                        replacement = pair_data['replacement_field'].getText().replace('{token}', token_for_this_pair)
                        original_match = re.search(request_pattern.replace('\\r\\n', '\\r?\\n?'), req_str)
                        if original_match:
                            old_value = original_match.group(0)
                            req_str = req_str.replace(old_value, replacement)
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
            headers = request_info.getHeaders()
            headers_text = "\n".join(headers)
            body_offset = request_info.getBodyOffset()
            request_bytes = request_response.getRequest()
            if body_offset < len(request_bytes):
                body_bytes = request_bytes[body_offset:]
                body_text = self.helpers.bytesToString(body_bytes)
            else:
                body_text = ""

            new_ep = {
                'host': host,
                'port': port,
                'use_https': use_https,
                'headers': headers_text,
                'body': body_text
            }

            def _fill_panel(ep_data):
                ep_data['host_field'].setText(host)
                ep_data['port_field'].setText(str(port))
                ep_data['https_checkbox'].setSelected(use_https)
                ep_data['headers_area'].setText(headers_text)
                ep_data['body_area'].setText(body_text)

            def _do_add():
                target = None
                if self.replace_on_send_checkbox.isSelected():
                    idx = self.selected_endpoint_index
                    if 0 <= idx < len(self.endpoint_panels) and self._isStockEndpoint(self.endpoint_panels[idx]):
                        target = self.endpoint_panels[idx]
                    else:
                        for ep_data in self.endpoint_panels:
                            if self._isStockEndpoint(ep_data):
                                target = ep_data
                                break

                if target is not None:
                    _fill_panel(target)
                    self.selected_endpoint_index = self.endpoint_panels.index(target)
                    self.refreshEndpointDisplay()
                    self._markUnsaved()
                    self.addStatus("Replaced stock endpoint with %s %s://%s:%s" % (
                        request_info.getMethod(), service.getProtocol(), host, port))
                else:
                    self.addEndpoint(new_ep)
                    self.addStatus("Added endpoint from %s %s://%s:%s" % (
                        request_info.getMethod(), service.getProtocol(), host, port))
            SwingUtilities.invokeLater(_AddEndpointRunnable(_do_add))
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

from java.lang import Runnable

class ScheduledRefreshTask(Runnable):
    def __init__(self, extender):
        self.extender = extender
    def run(self):
        self.extender._onRefreshTimerFire()

class _AddEndpointRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn
    def run(self):
        self.fn()

class UnsavedChangeListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender._markUnsaved()

class UnsavedDocListener(JDocumentListener):
    def __init__(self, extender):
        self.extender = extender
    def insertUpdate(self, event):
        self.extender._markUnsaved()
    def removeUpdate(self, event):
        self.extender._markUnsaved()
    def changedUpdate(self, event):
        self.extender._markUnsaved()

class UnsavedSpinnerListener(JChangeListener):
    def __init__(self, extender):
        self.extender = extender
    def stateChanged(self, event):
        self.extender._markUnsaved()

class HostSelectorListener(ItemListener):
    def __init__(self, extender):
        self.extender = extender
    def itemStateChanged(self, event):
        from java.awt.event import ItemEvent
        if event.getStateChange() == ItemEvent.SELECTED:
            self.extender.onHostSelected(self.extender.host_selector.getSelectedIndex())

class PollChangeListener(JChangeListener):
    def __init__(self, extender):
        self.extender = extender
    def stateChanged(self, event):
        self.extender.onPollChanged()

class EndpointRemoveHandler(ActionListener):
    def __init__(self, extender, panel):
        self.extender = extender
        self.panel = panel
    def actionPerformed(self, event):
        self.extender.removeEndpoint(self.panel)

class TokenMenuHandler(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    def actionPerformed(self, event):
        selected_messages = self.invocation.getSelectedMessages()
        if selected_messages and len(selected_messages) > 0:
            self.extender.populateFromRequest(selected_messages[0])

class RegexTestHandler(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    def actionPerformed(self, event):
        selected_messages = self.invocation.getSelectedMessages()
        if selected_messages and len(selected_messages) > 0:
            self.extender.testRequestRegexOnMessage(selected_messages[0])
