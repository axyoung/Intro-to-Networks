from segment import Segment

# #################################################################################################################### #
# RDTLayer                                                                                                             #
#                                                                                                                      #
# Description:                                                                                                         #
# The reliable data transfer (RDT) layer is used as a communication layer to resolve issues over an unreliable         #
# channel.                                                                                                             #
#                                                                                                                      #
#                                                                                                                      #
# Notes:                                                                                                               #
# This file is meant to be changed.                                                                                    #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #

# Author: Alex Young
# CS372 Intro to Computer Networks
# Date: 5/3/2021

# Sources Cited:
# https://stackoverflow.com/questions/9475241/split-string-every-nth-character
# https://www.w3schools.com/python/python_lists.asp

class RDTLayer(object):
    # ################################################################################################################ #
    # Class Scope Variables                                                                                            #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    DATA_LENGTH = 4 # in characters                     # The length of the string data that will be sent per packet...
    FLOW_CONTROL_WIN_SIZE = 15 # in characters          # Receive window size for flow-control
    sendChannel = None
    receiveChannel = None
    dataToSend = ''
    currentIteration = 0                                # Use this for segment 'timeouts'
    # Add items as needed
    FLOW_CONTROL_SEGS = 3

    # ################################################################################################################ #
    # __init__()                                                                                                       #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __init__(self):
        self.sendChannel = None
        self.receiveChannel = None
        self.dataToSend = ''
        self.currentIteration = 0
        # Add items as needed
        self.countSegmentTimeouts = 0
        self.dataList = []
        self.seqnum = 0
        self.receiveData = ''
        self.receiveArray = []
        self.receiveMissing = []
        self.acknum = 0
        self.prevMissing = False

    # ################################################################################################################ #
    # setSendChannel()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable sending lower-layer channel                                                 #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setSendChannel(self, channel):
        self.sendChannel = channel

    # ################################################################################################################ #
    # setReceiveChannel()                                                                                              #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable receiving lower-layer channel                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setReceiveChannel(self, channel):
        self.receiveChannel = channel

    # ################################################################################################################ #
    # setDataToSend()                                                                                                  #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the string data to send                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setDataToSend(self,data):
        self.dataToSend = data
        self.dataList = [data[x:x+(RDTLayer.DATA_LENGTH)] for x in range(0, len(data), RDTLayer.DATA_LENGTH)]
        # referenced from https://stackoverflow.com/questions/9475241/split-string-every-nth-character

    # ################################################################################################################ #
    # getDataReceived()                                                                                                #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to get the currently received and buffered string data, in order                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def getDataReceived(self):
        return self.receiveData

    # ################################################################################################################ #
    # processData()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # "timeslice". Called by main once per iteration                                                                   #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processData(self):
        self.currentIteration += 1
        self.processSend()
        self.processReceiveAndSendRespond()

    # ################################################################################################################ #
    # processSend()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment sending tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processSend(self):

        # You should pipeline segments to fit the flow-control window
        # The flow-control window is the constant RDTLayer.FLOW_CONTROL_WIN_SIZE
        # The maximum data that you can send in a segment is RDTLayer.DATA_LENGTH
        # These constants are given in # characters

        # Somewhere in here you will be creating data segments to send.
        # The data is just part of the entire string that you are trying to send.
        # The seqnum is the sequence number for the segment (in character number, not bytes)
        if self.currentIteration == 1:
            
            n = 0
            while n < RDTLayer.FLOW_CONTROL_SEGS and n < (len(self.dataList) - self.seqnum):
                temp = Segment()
                temp.setData(str(n+self.seqnum), self.dataList[n+self.seqnum])

                # ############################################################################################################ #
                # Display sending segment
                print("Sending segment: ", temp.to_string())

                # Use the unreliable sendChannel to send the segment
                self.sendChannel.send(temp)

                n += 1
            self.seqnum = n + self.seqnum

    # ################################################################################################################ #
    # processReceive()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment receive tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processReceiveAndSendRespond(self):
        segmentAck = Segment()                  # Segment acknowledging packet(s) received

        # This call returns a list of incoming segments (see Segment class)...
        listIncomingSegments = self.receiveChannel.receive()

        order = []
        receiveAck = []
        for x in range(len(listIncomingSegments)):
            listIncomingSegments[x].printToConsole()
            order.append(int(listIncomingSegments[x].seqnum))
            
        order.sort(reverse=True)
        # Read incoming segments into data array or ack array
        if self.prevMissing == False and len(self.dataList) == 0:
            for x in range(RDTLayer.FLOW_CONTROL_SEGS):
                self.receiveArray.append(None)
        for x in range(len(order)):
            if order[x] != -1:
                for y in range(len(listIncomingSegments)):
                    if int(listIncomingSegments[y].seqnum) == order[x] and self.receiveArray[order[x]] == None and listIncomingSegments[y].checkChecksum() == True:
                        self.receiveArray[order[x]] = listIncomingSegments[y].payload
            else:
                receiveAck.append(int(listIncomingSegments[x].acknum))
        
        # receiveMissing array includes the segments that were missing
        for x in range(len(self.receiveArray)):
            if self.receiveArray[x] == None:
                self.receiveMissing.append(x)
            elif self.receiveMissing.count(x) > 0:
                self.receiveMissing.remove(x)
        self.receiveMissing = list(set(self.receiveMissing))

        # Sending Data segments
        if len(self.dataList) > 0:
            if len(receiveAck) > 0:
                serverCaughtUp = False
                for x in range(len(receiveAck)):
                    if receiveAck[x] == self.seqnum:
                        serverCaughtUp = True
                if serverCaughtUp == False:
                    receiveAck.sort()
                    for x in range(0, len(receiveAck)):
                        if receiveAck[x] < len(self.dataList):
                            temp = Segment()
                            temp.setData(str(receiveAck[x]), self.dataList[receiveAck[x]])
                            print("Sending segment: ", temp.to_string())
                            self.sendChannel.send(temp)
                            # I am keeping track of the segment timeouts as the number of times I resend segments that I already sent
                            # The instuctor made a comment in the ED saying that depending on how you implement the protocol the timeouts would be flexible
                            # This is why my code doesn't use the iterations to wait for a timeout, as the protocol will wait for a resend request instead
                            self.countSegmentTimeouts += 1
                
                elif self.currentIteration > 1:
                    n = 0
                    while n < RDTLayer.FLOW_CONTROL_SEGS and n < (len(self.dataList) - self.seqnum):
                        temp = Segment()
                        temp.setData(str(n+self.seqnum), self.dataList[n+self.seqnum])
                        print("Sending segment: ", temp.to_string())
                        self.sendChannel.send(temp)
                        n += 1
                    self.seqnum = n + self.seqnum

        # Sending contents of ack segments
        else:
            self.receiveMissing.sort()
            if len(self.receiveMissing) == 0:
                self.receiveData = ''
                for x in range(len(self.receiveArray)):       
                    self.acknum = max(self.acknum, x)
                    self.receiveData = self.receiveData + self.receiveArray[x]
                self.acknum += 1
                segmentAck.setAck(self.acknum)
                self.sendChannel.send(segmentAck)
                print("Sending ack: ", segmentAck.to_string())
                self.prevMissing = False
            else:
                self.receiveData = ''
                for x in range(self.receiveMissing[0]):       
                    self.acknum = max(self.acknum, x)
                    self.receiveData = self.receiveData + self.receiveArray[x]
                for x in range(len(self.receiveMissing)):
                    temp = Segment()
                    temp.setAck(self.receiveMissing[x])
                    self.sendChannel.send(temp)
                    print("Sending ack: ", temp.to_string())
                
                self.prevMissing = True
            