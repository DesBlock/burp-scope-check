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
from javax.swing.border import EmptyBorder
from java.awt import Dimension
from java.awt import GridBagLayout
from java.awt import Font
from java.awt import Color
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
        
    self.drawUI()
    callbacks.setExtensionName(NAME)
    callbacks.customizeUiComponent(self.tabs)
    callbacks.addSuiteTab(self)
    # obtain our output and error streams
    stdout = PrintWriter(callbacks.getStdout(), True)
    stderr = PrintWriter(callbacks.getStderr(), True)
    
    # write a message to our output stream
    #stdout.println("Hello output")
    
    # write a message to our error stream
    #stderr.println("Hello errors")
    
    # write a message to the Burp alerts tab
    callbacks.issueAlert("Successfully Loaded")

  def drawUI(self):

    #InScope Tab
    self.inScope = JPanel()

    #Create Header Label
    self.inScopeLabel = JLabel("InScope Addresses:")
    self.inScopeLabel.setFont(Font('Tahoma', Font.BOLD, 14))
    self.inScopeLabel.setForeground(Color(235,136,0))

    #Create Description
    self.descriptionLabel = JLabel("Add all IPs or Domains that SHOULD be in scope for testing below.")
    self.descriptionLabel.setFont(Font('Tahoma', Font.PLAIN, 13))
    #self.descriptionLabel.setForeground(Color(255,255,255))
    #self.descriptionLabel.setLayout(BoxLayout(self.descriptionLabel, BoxLayout.X_AXIS))

    #Create Input Pane
    self.inputResultsPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)  
    self.inputResultsPane.setMaximumSize(Dimension(800,500))
    self.inputResultsPane.setDividerSize(5)
    self.inputResultsPane.setBorder(BorderFactory.createLineBorder(Color.black))

    # #Create Input Panel
    self.inputPane = JPanel()
    self.inputPane.setMaximumSize(Dimension(500, 20))
    #self.inputPane.setBorder(EmptyBorder(10,10,10,10))
    self.inputPane.setBorder(BorderFactory.createLineBorder(Color.blue))
    self.inputPane.setLayout(BoxLayout(self.inputPane, BoxLayout.X_AXIS))

    #Create Input Field
    self.inScopeInput = JTextField("Sample Input")
    self.inScopeInput.setPreferredSize(Dimension(300,10))
    self.inputPane.add(self.inScopeInput)

    #LoadedInputResults
    self.inScopeInputLoaded = JTextArea("Sample Results")
    self.inScopeInputLoaded.setColumns(1)
    self.inScopeInputLoaded.setRows(10)
    self.inScopeInputLoaded.setEditable(False)
    self.inputResultsPane.setLeftComponent(self.inScopeInputLoaded)

    #Create Input Buttons and set default size
    self.InputAdd = JButton('Add',actionPerformed=self.entryAdd)
    self.InputRemove = JButton('Remove',actionPerformed=self.entryRemove)
    self.InputLoad = JButton('Load',actionPerformed=self.entryLoad)
    self.InputClear = JButton('Clear',actionPerformed=self.entryClear)

    self.InputAdd.setAlignmentX(self.InputAdd.CENTER_ALIGNMENT)
    self.InputRemove.setAlignmentX(self.InputRemove.CENTER_ALIGNMENT)
    self.InputLoad.setAlignmentX(self.InputLoad.CENTER_ALIGNMENT)
    self.InputClear.setAlignmentX(self.InputClear.CENTER_ALIGNMENT)

    self.InputAdd.setMinimumSize(Dimension(50,100))
    self.InputRemove.setMinimumSize(Dimension(50,100))
    self.InputLoad.setMinimumSize(Dimension(50,100))
    self.InputClear.setMinimumSize(Dimension(50,100))


    #Create Input Buttons Panel
    self.InputButtonPanel = JPanel()
    self.InputButtonPanel.setPreferredSize(Dimension(100, 20))
    self.InputButtonPanel.setLayout(BoxLayout(self.InputButtonPanel, BoxLayout.Y_AXIS))
    self.InputButtonPanel.add(self.InputAdd)
    self.InputButtonPanel.add(self.InputRemove)
    self.InputButtonPanel.add(self.InputLoad)
    self.InputButtonPanel.add(self.InputClear)

    #Set Button Layout
    self.InputButtonPanel.add(self.InputAdd,BoxLayout.Y_AXIS)
    self.InputButtonPanel.add(self.InputRemove,BoxLayout.Y_AXIS)
    self.InputButtonPanel.add(self.InputLoad,BoxLayout.Y_AXIS)
    self.InputButtonPanel.add(self.InputClear,BoxLayout.Y_AXIS)
    self.inputResultsPane.setRightComponent(self.InputButtonPanel)

    #Create Separation Bar (to make things pretty)
    #self.bar = JSeparator(SwingConstants.HORIZONTAL)


    #Set the layout
    layout = GroupLayout(self.inScope)
    self.inScope.setLayout(layout)

    layout.setAutoCreateGaps(True)
    layout.setAutoCreateContainerGaps(True)

    layout.setHorizontalGroup(
      layout.createParallelGroup(GroupLayout.Alignment.LEADING)
      .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
          .addComponent(self.inScopeLabel)
          .addComponent(self.descriptionLabel))
      #.addComponent(self.bar)
      #.addGap(10,10,10)
      .addGroup(layout.createSequentialGroup()
          .addComponent(self.inputPane))
      .addGroup(layout.createSequentialGroup()
          .addComponent(self.inputResultsPane)))

    layout.setVerticalGroup(
      layout.createSequentialGroup()
      .addGroup(layout.createSequentialGroup()
          .addComponent(self.inScopeLabel)
          .addComponent(self.descriptionLabel))
      #.addComponent(self.bar)
      #.addGap(10,10,10)
      .addGroup(layout.createSequentialGroup()
          .addComponent(self.inputPane))
      .addGroup(layout.createSequentialGroup()
          .addComponent(self.inputResultsPane)
          .addContainerGap(26, lang.Short.MAX_VALUE)))


    #TODO: Duplicate above with different layout and content.
    self.scopeLoad = JPanel(GridBagLayout())
    self.tabs = JTabbedPane()
    self.tabs.addTab('In-Scope', self.inScope)
    self.tabs.addTab('Scope Load', self.scopeLoad)
  
  def entryAdd():
    pass

  def entryRemove():
    pass

  def entryLoad():
    pass

  def entryClear():
    pass
  