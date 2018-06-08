"""
WCF Binary Soap Inspector - Burp Suite plugin

(Python 2.7 code meant for consumption by Burp Suite Jython)

An evolution of this project:

https://github.com/GDSSecurity/WCF-Binary-SOAP-Plug-In

And additional credit to helping me get started with an
encoder/decoder type Burp Suite plugin in Python goes to:

https://labs.neohapsis.com/2013/09/16/burp-extensions-in-python-pentesting-custom-web-services/

"""

# Java classes being imported using Python syntax (Jython magic)
from burp import IBurpExtender
from burp import IExtensionHelpers
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
 
from datetime import datetime

class CustomDecoderTab(IMessageEditorTab):
    
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._controller = controller
        # create an instance of Burp's text editor to display decoded data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self._currentMessage = ''
        return

    def getTabCaption(self):
        return 'soap+msbin1'

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        if content:
            httpService = self._controller.getHttpService()
            if httpService:
                if isRequest:
                    requestInfo = self._extender._helpers.analyzeRequest(httpService, content)
                    headers = requestInfo.getHeaders()
                    for h in headers:
                        if 'application/soap+msbin' in h:
                            return True
                    return False
                else:
                    # TODO not working for responses yet
                    return False
        return False

    def setMessage(self, content, isRequest):
        try:
            if not content:
                self._txtInput.setText('Error how did this happen oh no')
                self._txtInput.setEditable(False)
            else:
                requestInfo = self._extender._helpers.analyzeRequest(self._controller.getHttpService(), content)
                headers = requestInfo.getHeaders()
                for h in headers:
                    if 'application/soap+msbin' in h:
                        # TODO do something here then set this content
                        content = 'PLACEHOLDER'
                        if content:
                            self._txtInput.setText(content)
                            self._currentMessage = content
                        else:
                            self._currentMessage = ''
        except Exception, e:
            print(e.__doc__)
            print(e.message)
        return

    def getMessage(self):
        # Pointless (?) method that Burp calls when you switch out of the tab (?)
        return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('WCF Binary Soap Inspector')
        callbacks.registerMessageEditorTabFactory(self)
        return
 
    # ** Message Editor Tab Factory method
    def createNewInstance(self, controller, editable):
        return CustomDecoderTab(self, controller, editable)
