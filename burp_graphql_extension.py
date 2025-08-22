# -*- coding: utf-8 -*-
#
# Burp Suite DelledoxGQL Logger & Viewer
# Logs GraphQL requests/responses in a Burp tab
# Author: Delledox Security
#

from burp import IBurpExtender, IHttpListener, IMessageEditorController, ITab
from java.awt import BorderLayout
from javax.swing import JPanel, JSplitPane, JScrollPane, JTable, ListSelectionModel
from javax.swing.table import AbstractTableModel
import re

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorController, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("DelledoxGQL Logger")

        self._data = []      # List of tuples: (IHttpRequestResponse, parsed_info)
        self._index = {}     # Map key -> index in _data
        self._selected = None

        # Build UI
        self._mainPanel = JPanel(BorderLayout())

        self._tableModel = GraphQLTableModel(self._data, self._helpers)
        self._table = JTable(self._tableModel)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.getSelectionModel().addListSelectionListener(self.onTableSelect)
        scrollPane = JScrollPane(self._table)

        # Request/Response viewers
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)

        splitBottom = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                 self._requestViewer.getComponent(),
                                 self._responseViewer.getComponent())
        splitBottom.setResizeWeight(0.5)

        splitMain = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                               scrollPane,
                               splitBottom)
        splitMain.setResizeWeight(0.3)

        self._mainPanel.add(splitMain, BorderLayout.CENTER)

        # Register with Burp
        self._callbacks.customizeUiComponent(self._table)
        self._callbacks.customizeUiComponent(scrollPane)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

    #
    # ITab
    #
    def getTabCaption(self):
        return "DelledoxGQL Logger"

    def getUiComponent(self):
        return self._mainPanel

    #
    # IHttpListener
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            http_service = messageInfo.getHttpService()
            analyzed = self._helpers.analyzeRequest(http_service, messageInfo.getRequest())
            url = str(analyzed.getUrl())
            method = analyzed.getMethod()
            host = http_service.getHost()

            if "/graphql" not in url.lower():
                return

            key = (host, url, method)  # unique key for request/response pair

            if messageIsRequest:
                # Parse operationName
                opName = self.extractOperationName(messageInfo.getRequest(), analyzed)
                info = {
                    "host": host,
                    "method": method,
                    "url": url,
                    "opName": opName,
                    "status": ""
                }
                self._data.append((messageInfo, info))
                self._index[key] = len(self._data) - 1
                self._tableModel.fireTableDataChanged()
            else:
                # Response — update status
                if key in self._index:
                    idx = self._index[key]
                    msg, info = self._data[idx]
                    if messageInfo.getResponse():
                        analyzedResp = self._helpers.analyzeResponse(messageInfo.getResponse())
                        info["status"] = str(analyzedResp.getStatusCode())
                        # replace messageInfo so response is available
                        self._data[idx] = (messageInfo, info)
                    self._tableModel.fireTableRowsUpdated(idx, idx)

        except Exception as e:
            print("[!] Error processing message: {}".format(e))

    #
    # IMessageEditorController
    #
    def getHttpService(self):
        return self._selected.getHttpService() if self._selected else None

    def getRequest(self):
        return self._selected.getRequest() if self._selected else None

    def getResponse(self):
        return self._selected.getResponse() if self._selected else None

    #
    # Helpers
    #
    def onTableSelect(self, event):
        if not event.getValueIsAdjusting():
            row = self._table.getSelectedRow()
            if 0 <= row < len(self._data):
                self._selected = self._data[row][0]
                self._requestViewer.setMessage(self._selected.getRequest(), True)
                self._responseViewer.setMessage(self._selected.getResponse(), False)

    def extractOperationName(self, request, analyzed):
        try:
            body = request[analyzed.getBodyOffset():].tostring()
            m = re.search(r'"operationName"\s*:\s*"([^"]+)"', body)
            if m:
                return m.group(1)
        except:
            pass
        return ""


#
# Table Model
#
class GraphQLTableModel(AbstractTableModel):
    def __init__(self, data, helpers):
        self._data = data
        self._helpers = helpers
        self._cols = ["#", "Host", "Method", "URL", "OpName", "Status"]

    def getRowCount(self):
        return len(self._data)

    def getColumnCount(self):
        return len(self._cols)

    def getColumnName(self, col):
        return self._cols[col]

    def getValueAt(self, row, col):
        msg, info = self._data[row]
        if col == 0:
            return row + 1
        elif col == 1:
            return info["host"]
        elif col == 2:
            return info["method"]
        elif col == 3:
            return info["url"]
        elif col == 4:
            return info["opName"]
        elif col == 5:
            return info.get("status", "")
        return ""

