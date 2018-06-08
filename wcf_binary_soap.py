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
from burp import IHttpListener
 
from datetime import datetime
 
class BurpExtender(IBurpExtender, IHttpListener):
 
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('WCF Binary Soap Inspector')
        callbacks.registerHttpListener(self)
        return
 
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        # Only process requests
        if not messageIsRequest:
            return
         
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = requestInfo.getHeaders()
        newHeaders = list(headers)  # Get Python list from Java arraylist

        for h in newHeaders:
            if 'application/soap+msbin' in h:
                timestamp = datetime.now()
                print 'Found WCF Binary Soap @ ' + str(timestamp.isoformat())
                #bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
                #bodyStr = self._helpers.bytesToString(bodyBytes)
                print '\n'

        #newMsgBody = bodyStr + timestamp.isoformat()
        #newMessage = self._helpers.buildHttpMessage(newHeaders,newMsgBody)

        #print "Sending modified message:"
        #print "----------------------------------------------"
        #print self._helpers.bytesToString(newMessage)
        #print "----------------------------------------------\n\n"
         
        #currentRequest.setRequest(newMessage)
        
        return
