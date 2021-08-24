from burp import IBurpExtender
from burp import ITab

NAME = 'Scope Check'
VERSION = '0.1'
DEBUG = False

class BurpExtender(IBurpExtender, ITab):
  def getTabCaption(self):
    return NAME
  '''
  def getUiComponent(self):
    return self.tabs
  '''
