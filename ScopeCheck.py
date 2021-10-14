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
from javax.swing.border import EmptyBorder
from java.awt import Dimension
from java.awt import GridBagLayout
from java.awt import Font
from java.awt import Color
from urlparse import urlparse
import java.lang as lang

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
VERSION = '0.1'
DEBUG = False


class BurpExtender(IBurpExtender, ITab):
    def getTabCaption(self):
        return NAME

    def getUiComponent(self):
        return self.tabs

    def registerExtenderCallbacks(self, callbacks):

        # Create a class level instance of callbacks to be used.
        self._callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Draw the gui
        self.drawUI()

        # Register callbacks for name and tab creation.
        callbacks.setExtensionName(NAME)
        callbacks.customizeUiComponent(self.tabs)
        callbacks.addSuiteTab(self)

        # obtain our output and error streams
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # write a message to our output stream
        #stdout.println("Hello output")

        # write a message to our error stream
        #stderr.println("Hello errors")

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Successfully Loaded")

    def drawUI(self):

        # InScope Tab
        self.inScope = JPanel()

        # Create Title Label
        self.inScopeLabel = JLabel("InScope Addresses:")
        self.inScopeLabel.setFont(Font('Tahoma', Font.BOLD, 14))
        self.inScopeLabel.setForeground(Color(235, 136, 0))

        # Create Description
        self.descriptionLabel = JLabel(
            "Add all IPs or Domains that SHOULD be in scope for testing below. Currently only CIDR notation, individual IPs, and domains are supported.")
        self.descriptionLabel.setFont(Font('Tahoma', Font.PLAIN, 13))
        # self.descriptionLabel.setForeground(Color(255,255,255))

        # Create Input Field
        self.inScopeInput = JTextField("Sample Input")
        self.inScopeInput.setMaximumSize(Dimension(300, 10))

        # Create List of Loaded URLs.
        self.urlListModel = DefaultListModel()
        self.urlList = JList(self.urlListModel)
        self.urlListPane = JScrollPane(self.urlList)
        self.urlListPane.setMaximumSize(Dimension(300, 400))

        # Create List Results from Analysis.
        self.urlResultsModel = DefaultListModel()
        self.urlResults = JList(self.urlResultsModel)
        self.urlResultsPane = JScrollPane(self.urlList)
        self.urlResultsPane.setMaximumSize(Dimension(300, 400))

        # Create Input Buttons and set default size
        self.InputAdd = JButton('Add', actionPerformed=self.entryAdd)
        self.InputRemove = JButton('Remove', actionPerformed=self.entryRemove)
        self.InputLoad = JButton('Load', actionPerformed=self.entryLoad)
        self.InputClear = JButton('Clear', actionPerformed=self.entryClear)
        self.Analyze = JButton('Analyze', actionPerformed=self.analyze)
        self.Analyze.setForeground(Color.BLACK)
        self.Analyze.setBackground(Color.GREEN)
        self.Analyze.setOpaque(True)

        # Create Separation Bar (to make things pretty)
        #self.bar = JSeparator(SwingConstants.HORIZONTAL)

        # Set the layout
        layout = GroupLayout(self.inScope)
        self.inScope.setLayout(layout)

        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                      .addComponent(self.inScopeLabel)
                      .addComponent(self.descriptionLabel))
            # .addComponent(self.bar)
            # .addGap(10,10,10)
            .addGroup(layout.createSequentialGroup()
                      .addComponent(self.InputAdd)
                      .addComponent(self.inScopeInput))
            # .addGap(100)
            .addGroup(layout.createSequentialGroup()
                      .addGroup(layout.createParallelGroup()
                                .addComponent(self.InputClear)
                                .addComponent(self.InputLoad)
                                .addComponent(self.InputRemove)
                                .addComponent(self.Analyze))
                      .addComponent(self.urlListPane, 0, 500, 1000)
                      .addComponent(self.urlResultsPane, 0, 500, 1000)))

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createSequentialGroup()
                      .addComponent(self.inScopeLabel)
                      .addComponent(self.descriptionLabel))
            # .addComponent(self.bar)
            # .addGap(10,10,10)
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.InputAdd)
                      .addComponent(self.inScopeInput))
            .addGroup(layout.createParallelGroup()
                      .addGroup(layout.createSequentialGroup()
                                .addComponent(self.InputClear)
                                .addComponent(self.InputLoad)
                                .addComponent(self.InputRemove)
                                .addComponent(self.Analyze))
                      .addComponent(self.urlListPane, 0, 500, 1000)
                      .addComponent(self.urlResultsPane, 0, 500, 1000))
            .addContainerGap(50, lang.Short.MAX_VALUE))

        layout.linkSize(SwingConstants.HORIZONTAL, self.InputAdd,
                        self.InputClear, self.InputLoad, self.InputRemove)
        layout.linkSize(SwingConstants.HORIZONTAL,
                        self.inScopeInput, self.urlListPane)

        # TODO: Duplicate above with different layout and content.
        self.scopeLoad = JPanel(GridBagLayout())
        self.tabs = JTabbedPane()
        self.tabs.addTab('In-Scope', self.inScope)
        self.tabs.addTab('Scope Load', self.scopeLoad)

    # Return entire sitemap
    def getSiteMap(self):
        siteMapURLs = {}
        for entry in self._callbacks.getSiteMap(None):
          request = self.helpers.analyzeRequest(entry)
          url = request.getUrl()
          try:
            decodeUrl = self.helpers.urlDecode(str(url))
          except Exception as e:
            continue
          #Utilize if Port is important
          #hostname = urlparse(decodeUrl).netloc
          hostname = urlparse(decodeUrl).hostname 
          if hostname not in siteMapURLs:
            siteMapURLs[hostname] = url
        return siteMapURLs

    # Get all currently loaded urls/IPs.
    def getCurrentlyLoaded(self):
        model = self.urlList.getModel()
        current = []
        # Model object is not iterable so we have to manually iterate through the list.
        for i in range(0, model.getSize()):
            current.append(model.getElementAt(i))
        return current

    def entryAdd(self, e):
        source = e.getSource()
        inputText = self.inScopeInput.getText()
        # Check for blank text and exit function if input is none.
        if inputText == '':
            return
        currentlyLoaded = self.getCurrentlyLoaded()
        currentlyLoaded.append(inputText)
        self.urlList.setListData(currentlyLoaded)

    def entryRemove(self, e):
        indices = self.urlList.getSelectedIndices().tolist()
        current = self.getCurrentlyLoaded()

        for index in reversed(indices):
            del current[index]

        self.urlList.setListData(current)

    def entryLoad(self, e):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.tabs, "Choose file")

        if ret == JFileChooser.APPROVE_OPTION:
            file = chooseFile.getSelectedFile()
            filename = file.getCanonicalPath()
            try:
                f = open(filename, "r")
                text = f.readlines()

                if text:
                    text = [line for line in text if not line.isspace()]
                    text = [line.rstrip('\n') for line in text]
                    self.urlList.setListData(text)
            except IOError as e:
                self.stderr.println("Error reading file.\n", str(e))

    # Set current list to an empty array to clear out loaded list.
    def entryClear(self, e):
        emptyArray = []
        self.urlList.setListData(emptyArray)

    # Function to analyze URLlist entries against target sitemap.

    def analyze(self, e):
        # Non-filtered sitemap
        siteMap = self.getSiteMap()
        # Entire siteMap filtered by suite-scope
        inSuiteScope = []
        # Filter the sitemap to include on those that match the suite-scope
        for site in iter(siteMap):
            
            if self._callbacks.isInScope(siteMap[site]):
                #Only Appending 1???
                inSuiteScope.append(site)
        # Set filtered list of inScope results to results pane BEFORE coloring.(Just in case there are errors you can see where)
        self.stdout.format("SuiteScope: %s", inSuiteScope)
        self.urlResults.setListData(inSuiteScope)
        # Check if items in filtered sitemap match uploaded scope. Resolve Names to IPs as neccesary.
        '''
    - Check if Site domain is in scopeList
    - Resolve subdomain to IP
    - Resolve tld domain to IP
    - Resolve CIDR notation and ranges to individual IPs OR identify ways to check if Site IP is in CIDR range.
    - Check IP in scopeList
    - Take SiteMap list and output to Results Pane
    - Color inScope IPs/Names based off scoping.
    '''
