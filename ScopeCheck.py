from burp import IBurpExtender
from burp import ITab
from java.io import PrintWriter
from javax.swing import JTabbedPane
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import GroupLayout
from javax.swing import JTextField
from javax.swing import JTextArea
from javax.swing import JButton
from javax.swing import JSplitPane
from javax.swing import BorderFactory
from javax.swing import BoxLayout
from javax.swing import JSeparator
from javax.swing import SwingConstants
from javax.swing import DefaultListModel
from javax.swing import JList
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import ListCellRenderer
from javax.swing import DefaultListCellRenderer
from javax.swing.border import EmptyBorder
from java.awt import Dimension
from java.awt import GridBagLayout
from java.awt import Font
from java.awt import Color
from urlparse import urlparse
import java.lang as lang
from ipaddress import ip_address
from ipaddress import ip_network

import time
from socket import gethostbyaddr
from socket import getaddrinfo
from socket import gethostbyname


'''
References/Credit:
  General Code:
    https://github.com/PortSwigger/additional-csrf-checks/blob/master/EasyCSRF.py
    https://portswigger.net/burp/extender#SampleExtensions
  Formatting:
    https://github.com/PortSwigger/site-map-extractor/blob/master/site_map_extractor.py
    https://github.com/SmeegeSec/Burp-Importer/
    https://github.com/Dionach/HeadersAnalyzer/
'''

NAME = 'Scope Check'
VERSION = '1.0'
# DEBUG = False


class BurpExtender(IBurpExtender, ITab):
    # pylint: disable-next=invalid-name
    def getTabCaption(self):
        return NAME

    # pylint: disable-next=invalid-name
    def getUiComponent(self):
        return self.tabs

    # pylint: disable-next=invalid-name
    def registerExtenderCallbacks(self, callbacks):

        # Create a class level instance of callbacks to be used.
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Draw the gui
        self.draw_ui()

        # Register callbacks for name and tab creation.
        callbacks.setExtensionName(NAME)
        callbacks.customizeUiComponent(self.tabs)
        callbacks.addSuiteTab(self)

        # obtain our output and error streams
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # write a message to our output stream
        #self.stdout.println("Hello output")

        # write a message to our error stream
        #self.stderr.println("Hello errors")

        # Debug: unload extension as failsafe to prevent lockup
        # callbacks.unloadExtension()

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Successfully Loaded")

    def draw_ui(self):

        # InScope Tab
        self.in_scope = JPanel()

        # Create Title Label
        self.in_scope_label = JLabel("InScope Addresses:")
        self.in_scope_label.setFont(Font('Tahoma', Font.BOLD, 14))
        self.in_scope_label.setForeground(Color(235, 136, 0))

        # Create Description
        self.description_label = JLabel(
            "Add all IPs or Domains that SHOULD be in scope for testing below. "+
            "Currently only CIDR notation, individual IPs, and domains are supported.")
        self.description_label.setFont(Font('Tahoma', Font.PLAIN, 13))
        # self.description_label.setForeground(Color(255,255,255))

        # Create Input Field
        self.in_scope_input = JTextField("Sample Input")
        self.in_scope_input.setMaximumSize(Dimension(300, 10))

        # Create List of Loaded URLs.
        self.url_list_model = DefaultListModel()
        self.url_list = JList(self.url_list_model)
        self.url_list_pane = JScrollPane(self.url_list)
        self.url_list_pane.setMaximumSize(Dimension(300, 400))

        # Create List Results from Analysis.
        self.url_results_model = DefaultListModel()
        self.url_results = JList(self.url_results_model)
        self.url_results_pane = JScrollPane(self.url_results)
        self.url_results_pane.setMaximumSize(Dimension(300, 400))

        # Create Input Buttons and set default size
        self.input_add = JButton('Add', actionPerformed=self.entry_add)
        self.input_remove = JButton(
            'Remove', actionPerformed=self.entry_remove)
        self.input_load = JButton('Load', actionPerformed=self.entry_load)
        self.input_clear = JButton('Clear', actionPerformed=self.entry_clear)
        self.analyze = JButton('Analyze', actionPerformed=self.analyze_urls)
        self.analyze.setForeground(Color.BLACK)
        self.analyze.setBackground(Color.GREEN)
        self.analyze.setOpaque(True)

        # Create Separation Bar (to make things pretty)
        #self.bar = JSeparator(SwingConstants.HORIZONTAL)

        # Set the layout
        layout = GroupLayout(self.in_scope)
        self.in_scope.setLayout(layout)

        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                      .addComponent(self.in_scope_label)
                      .addComponent(self.description_label))
            # .addComponent(self.bar)
            # .addGap(10,10,10)
            .addGroup(layout.createSequentialGroup()
                      .addComponent(self.input_add)
                      .addComponent(self.in_scope_input))
            # .addGap(100)
            .addGroup(layout.createSequentialGroup()
                      .addGroup(layout.createParallelGroup()
                                .addComponent(self.input_clear)
                                .addComponent(self.input_load)
                                .addComponent(self.input_remove)
                                .addComponent(self.analyze))
                      .addComponent(self.url_list_pane, 0, 500, 1000)
                      .addComponent(self.url_results_pane, 0, 500, 1000)))

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createSequentialGroup()
                      .addComponent(self.in_scope_label)
                      .addComponent(self.description_label))
            # .addComponent(self.bar)
            # .addGap(10,10,10)
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.input_add)
                      .addComponent(self.in_scope_input))
            .addGroup(layout.createParallelGroup()
                      .addGroup(layout.createSequentialGroup()
                                .addComponent(self.input_clear)
                                .addComponent(self.input_load)
                                .addComponent(self.input_remove)
                                .addComponent(self.analyze))
                      .addComponent(self.url_list_pane, 0, 500, 1000)
                      .addComponent(self.url_results_pane, 0, 500, 1000))
            .addContainerGap(50, lang.Short.MAX_VALUE))

        layout.linkSize(SwingConstants.HORIZONTAL, self.input_add,
                        self.input_clear, self.input_load, self.input_remove)
        layout.linkSize(SwingConstants.HORIZONTAL,
                        self.in_scope_input, self.url_list_pane, self.url_results_pane)

        self.scope_load = JPanel(GridBagLayout())
        self.tabs = JTabbedPane()
        self.tabs.addTab('In-Scope', self.in_scope)

        # TODO: Create Scope Load tab to automatically curl all IPs and Domains from user provided
        # scope to automate the process of analyzing a large number of domains or IPs.
        # self.tabs.addTab('Scope Load', self.scope_load)

    # Return entire site_map
    def get_site_map(self):
        site_map_urls = {}
        for entry in self.callbacks.getSiteMap(None):
            request = self.helpers.analyzeRequest(entry)
            url = request.getUrl()
            try:
                decoded_url = self.helpers.urlDecode(str(url))
            except Exception as e:
                continue
            # Utilize if Port is important
            #hostname = urlparse(decoded_url).netloc
            hostname = urlparse(decoded_url).hostname
            if hostname not in site_map_urls:
                site_map_urls[hostname] = url
        return site_map_urls

    # Get all currently loaded urls/IPs.
    def get_currently_loaded(self, loadedlist):
        model = loadedlist.getModel()
        loaded = []
        # Model object is not iterable so we have to manually iterate through the list.
        for i in range(0, model.getSize()):
            loaded.append(model.getElementAt(i))
        return loaded

    def entry_add(self, e):
        source = e.getSource()
        input_text = self.in_scope_input.getText()
        # Check for blank text and exit function if input is none.
        if input_text == '':
            return
        resolved_text = self.resolve(input_text)
        currently_loaded = self.get_currently_loaded(self.url_list)
        currently_loaded.append(resolved_text)
        self.url_list.setListData(currently_loaded)
        self.analyze_urls()

    def entry_remove(self, e):
        indices = self.url_list.getSelectedIndices().tolist()
        current = self.get_currently_loaded(self.url_list)

        for index in reversed(indices):
            del current[index]

        self.url_list.setListData(current)

    def entry_load(self, e):
        choose_file = JFileChooser()
        ret = choose_file.showDialog(self.tabs, "Choose file")

        if ret == JFileChooser.APPROVE_OPTION:
            file = choose_file.getSelectedFile()
            filename = file.getCanonicalPath()
            resolved_text = []
            try:
                with open(filename, "r") as open_file:
                    text = open_file.readlines()

                    if text:
                        text = [line for line in text if not line.isspace()]
                        text = [line.rstrip('\n') for line in text]
                        for line in text:
                            resolved_text.append(self.resolve(text))
                        self.url_list.setListData(resolved_text)
            except IOError as e:
                self.stderr.println("Error reading file.\n", str(e))
            self.analyze_urls()

    # Set current list to an empty array to clear out loaded list.
    def entry_clear(self, e):
        empty_array = []
        self.url_list.setListData(empty_array)

    # Attempts to resolve IP to Hostname and Hostname to IP. Appends [IP/Hostname]
    # to the end of entry. e.g. 125.2.48.2 [testing.com]
    def resolve(self, text):
        try:
            # Test if valid IP
            ip = ip_address(text)
            try:
                name = gethostbyaddr(text)
                domain_name = name[0]
            except OSError as e:
                return ip
            return text + " [" + domain_name + "]"
        except ValueError as e:
            # Not an IP, check to see if valid hostname
            try:
                # Currently gethostbyname only supports IPv4, if IPv6 is need use either
                # of the options below
                # ip = getaddrinfo(text, 80)
                # ip = getaddrinfo(text, 444)

                # Resolve IP Address
                # NOTE: Only resolves a single IP, not multiple.
                ip = gethostbyname(text)
                return text + " [" + ip + "]"
            except Exception as e:
                # Unable to resolve hostname to IP. Just returning text
                return text

    # Function to analyze URLlist entries against target site_map.
    def analyze_urls(self, e=None):
        # Non-filtered site_map
        site_map = self.get_site_map()
        # Entire site_map filtered by suite-scope
        in_suite_scope = []
        # Filter the site_map to include on those that match the suite-scope
        for site in iter(site_map):

            if self.callbacks.isInScope(site_map[site]):
                in_suite_scope.append(self.resolve(site))
        self.url_results.setListData(in_suite_scope)
        # Scope loaded by user (non-suitescope)
        userscope = self.get_currently_loaded(self.url_list)

        self.url_results.setCellRenderer(ResultScopeCellRenderer(
            userscope, self.stdout, self.stderr))
        # time.sleep(5)
        # self.callbacks.unloadExtension()


class ResultScopeCellRenderer(ListCellRenderer):

    # Iniitialize external variables, stdout and stderr for printing to burp outputs.
    def __init__(self, userscope, stdout=None, stderr=None):
        self._userscope = userscope
        self._stdout = stdout
        self._stderr = stderr

        # Create JLabel to be returned and set within JList.
        self.results = JLabel(horizontalAlignment=SwingConstants.LEFT)

    # Function used to accept each list component and set specific values.
    # Dynamically called by swing to paint each cell component.
    def getListCellRendererComponent(self, Jlist, value, index, isSelected, cellHasFocus):
        # Default set background to Red, if in-scope will be set to Green later.
        self.results.setBackground(Color.RED)
        # Attempt to seperate JList value into two parts (hostname and ip)
        split_value = value.split('[', 1)
        initial_value = split_value[0]
        try:
            secondary_value = split_value[1][0:-1]
        except IndexError as e:
            secondary_value = ""

        for user_val in self._userscope:
            # Check if cidr range was provided.
            if "/" in user_val:
                try:
                    cidr_range = ip_network(str(user_val).decode('utf8'))
                    try:
                        ip = ip_address(initial_value)
                        if ip in cidr_range:
                            self.results.setBackground(Color.GREEN)
                    except Exception as e:
                        try:
                            ip = ip_address(secondary_value)
                            if ip in cidr_range:
                                self.results.setBackground(Color.GREEN)
                        except Exception as e:
                            pass
                except Exception as e:
                    self._stderr.printf(
                        "Invalid CIDR range provided: %s\n", user_val)
                    self._stderr.printf("Error: %s\n", e)
            # If CIDR value was not provided check for hostname/ip combo
            user_split_value = user_val.split('[', 1)
            user_initial_value = user_split_value[0]
            try:
                user_secondary_value = user_split_value[1][0:-1]
            except IndexError as e:
                user_secondary_value = ""

            # Compare current JList value to user supplied values. Mark row Green if found
            # Mark as Red if not found.
            if initial_value == user_initial_value or initial_value == user_secondary_value:
                self.results.setBackground(Color.GREEN)
            if secondary_value == user_initial_value or secondary_value == user_secondary_value:
                self.results.setBackground(Color.GREEN)

        self.results.setText(value)
        # Manually set foreground color to prevent readability issues when using dark mode.
        self.results.setForeground(Color.BLACK)
        self.results.setEnabled(Jlist.isEnabled())
        self.results.setOpaque(True)
        return self.results
