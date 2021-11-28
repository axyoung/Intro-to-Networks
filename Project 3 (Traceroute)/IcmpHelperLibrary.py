# #################################################################################################################### #
# Alex Young                                                                                                           #
# CS 372 OSU ecampus                                                                                                   #
# Project 3: Traceroute                                                                                                #
# 5/23/2021                                                                                                            #
#                                                                                                                      #
# #################################################################################################################### #
# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select
import errno

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live
        rtt = 0
        reply_type = 0                  # Store the reply type
        packet_lost = False             # Check if packet was lost

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl
        
        def getRtt(self):
            return self.rtt
            
        def getReply_type(self):
            return self.reply_type
            
        def getPacket_lost(self):
            return self.packet_lost

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setRtt(self, rtt):
            self.rtt = rtt

        def setReply_type(self, type):
            self.reply_type = type

        def setPacket_lost(self, booleanValue):
            self.packet_lost = booleanValue

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.    
            # Individually compare ID, sequence number, and raw data for original packet and response to check validity        
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier():
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
                icmpReplyPacket.setIcmpIdentifier_Expected(self.getPacketIdentifier)

            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
                icmpReplyPacket.setIcmpSequenceNumber_Expected(self.getPacketSequenceNumber)
            
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIcmpData_isValid(True)
                icmpReplyPacket.setIcmpData_Expected(self.getDataRaw)
                        
            # If all 3 are valid, the the Response as a whole is valid
            if icmpReplyPacket.getIcmpSequenceNumber_isValid() and icmpReplyPacket.getIcmpIdentifier_isValid() and icmpReplyPacket.getIcmpData_isValid():
                icmpReplyPacket.setIsValidResponse(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
            
            # Debug messages with Expected and Actual ID
            print("Expected ID:", self.getPacketIdentifier(), "Actual ID:", icmpReplyPacket.getIcmpIdentifier()) if self.__DEBUG_IcmpPacket else 0
            print("Expected Sequence Number:", self.getPacketSequenceNumber(), "Actual Sequence Number:", icmpReplyPacket.getIcmpSequenceNumber()) if self.__DEBUG_IcmpPacket else 0
            print("Expected Data:", self.getDataRaw(), "Actual Data:", icmpReplyPacket.getIcmpData()) if self.__DEBUG_IcmpPacket else 0

            pass

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                    self.setPacket_lost(True)
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    self.setPacket_lost(True)

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    self.setReply_type(icmpType)

                    if icmpType == 11:                          # Time Exceeded
                        self.setRtt((timeReceived - pingStartTime) * 1000)
                        temp_host = ""
                        # source - https://searchsignals.com/how-to-do-a-reverse-dns-lookup to learn how to reverse dns lookup in python
                        # source - https://christophergs.com/python/2017/01/15/python-errno/ to learn how to use errno in python
                        # Print out TTL, RTT, Type, Code, host address, host name (if it exists)
                        try:
                            temp = gethostbyaddr(addr[0])[0]
                            temp_host = "(%s)" %temp
                        except IOError:
                            pass
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s  %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0],
                                    temp_host
                                )
                              )
                        if icmpCode == 0:
                            print("Time to Live exceeded in Transit")
                        elif icmpCode == 1:
                            print("Fragment Reassembly Time Exceeded")

                    elif icmpType == 3:                         # Destination Unreachable
                        self.setRtt((timeReceived - pingStartTime) * 1000)
                        temp_host = ""
                        try:
                            temp = gethostbyaddr(addr[0])[0]
                            temp_host = "(%s)" %temp
                        except IOError:
                            pass
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s  %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0],
                                      temp_host
                                  )
                              )
                        # Print out the error given the code
                        if icmpCode == 0:
                            print("Error: Destination Network Unreachable")
                        elif icmpCode == 1:
                            print("Error: Destination Host Unreachable")
                        elif icmpCode == 2:
                            print("Error: Destination Protocol Unreachable")
                        elif icmpCode == 3:
                            print("Error: Destination Port Unreachable")
                        elif icmpCode == 4:
                            print("Error: Fragmentation Needed and Don't Fragment was Set	")
                        elif icmpCode == 5:
                            print("Error: Source Route Failed")
                        elif icmpCode == 6:
                            print("Error: Destination Network Unknown")
                        elif icmpCode == 7:
                            print("Error: Destination Host Unknown")
                        elif icmpCode == 8:
                            print("Error: Source Host Isolated")
                        elif icmpCode == 9:
                            print("Error: Communication with Destination Network is Administratively Prohibited")
                        elif icmpCode == 10:
                            print("Error: Communication with Destination Host is Administratively Prohibited")
                        elif icmpCode == 11:
                            print("Error: Destination Network Unreachable for Type of Service")
                        elif icmpCode == 12:
                            print("Error: Destination Host Unreachable for Type of Service")
                        elif icmpCode == 13:
                            print("Error: Communication Administratively Prohibited")
                        elif icmpCode == 14:
                            print("Error: Host Precedence Violation")
                        elif icmpCode == 15:
                            print("Error: Precedence cutoff in effect")

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        self.setRtt(icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr))
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
                self.setPacket_lost(True)
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        IcmpIdentifier_isValid = False
        IcmpType_isValid = False
        IcmpCode_isValid = False
        IcmpSequenceNumber_isValid = False
        IcmpData_isValid = False
        IcmpIdentifier_Expected = 0
        IcmpSequenceNumber_Expected = 0
        IcmpData_Expected = ""

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # The following methods are used to get if an aspect of the response is valid
        def getIcmpIdentifier_isValid(self):
            return self.IcmpIdentifier_isValid
        
        def getIcmpSequenceNumber_isValid(self):
            return self.IcmpSequenceNumber_isValid
        
        def getIcmpData_isValid(self):
            return self.IcmpData_isValid
        
        # The following methods are used to get the expected value of an aspect of the response
        def getIcmpIdentifier_Expected(self):
            return self.IcmpIdentifier_Expected()
        
        def getIcmpSequenceNumber_Expected(self):
            return self.IcmpSequenceNumber_Expected()
        
        def getIcmpData_Expected(self):
            return self.IcmpData_Expected()

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.IcmpIdentifier_isValid = booleanValue
        
        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.IcmpSequenceNumber_isValid = booleanValue
        
        def setIcmpData_isValid(self, booleanValue):
            self.IcmpData_isValid = booleanValue

        def setIcmpIdentifier_Expected(self, intValue):
            self.IcmpIdentifier_Expected = intValue
        
        def setIcmpSequenceNumber_Expected(self, intValue):
            self.IcmpSequenceNumber_Expected = intValue
        
        def setIcmpData_Expected(self, stringValue):
            self.IcmpData_Expected = stringValue
        
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            # If the response is not valid, this will be printed out to the console as well
            if self.getIcmpIdentifier_isValid() == False:
                print("Expected ID:", self.getIcmpIdentifier_Expected(), "Actual ID:", self.getIcmpIdentifier())
            if self.getIcmpSequenceNumber_isValid() == False:
                print("Expected Sequence Number:", self.getIcmpSequenceNumber_Expected(), "Actual Sequence Number:", self.getIcmpSequenceNumber())
            if self.getIcmpData_isValid() == False:
                print("Expected Data:", self.getIcmpData_Expected(), "Actual Data:", self.getIcmpData())
            # Return the RTT for use in the Min/Max/Avg RTTs for the ping function
            return (timeReceived - timeSent) * 1000

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        rtt_list = []   # list to store the RTTs
        min_rtt = 0     # minimum RTT
        max_rtt = 0     # maximum RTT
        sum_rtt = 0     # sum of all the RTTs
        avg_rtt = 0     # average RTT
        j = 0           # total number of packets sent

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data
            if icmpPacket.getPacket_lost() == False:
                rtt_list.append(icmpPacket.getRtt())
            j += 1
        
        # loop through the RTT list to ifnd the min/max/avg values
        for x in range(len(rtt_list)):
            if min_rtt == 0:
                min_rtt = rtt_list[x]
            else:
                min_rtt = min(min_rtt, rtt_list[x])
            max_rtt = max(max_rtt, rtt_list[x])
            sum_rtt += rtt_list[x]
        if len(rtt_list) > 0:
            avg_rtt = sum_rtt / len(rtt_list)
        percent_lost = ( (j-len(rtt_list)) / j ) * 100
        # formatting based on windows ping cmd - Print out the results
        print("\nPing Statistics for %s:\n\tPackets: Sent = %.0f, Revieved = %.0f, Lost = %.0f (%.0f percent loss)," %(host, j, len(rtt_list), j - len(rtt_list), percent_lost))
        if len(rtt_list) > 0:
            print("Approximate Round Trip Time in ms:\n\tMinimum = %.0f, Maximum = %.0f, Average = %.0f" % (min_rtt, max_rtt, avg_rtt))
        print("\nPing Complete.\n")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here
        try:
            print("Tracing route to %s [%s]\n" %(gethostbyaddr(host)[0], host))
        except IOError:
            print("Tracing route to %s\n" %(host))
        stop = False    # Stop when stop recieving replies
        j = 0           # total number of packets sent
        rtt_list = []   # list to store RTTs

        while stop == False:
            for i in range(1):              # keep a for loop here in case want to send more than 1 packet at a time (with the same TTL) when doing traceroute
                # Build packet
                icmpPacket = IcmpHelperLibrary.IcmpPacket()
                icmpPacket.setTtl(j)        # TTL is set as j - which increments up by 1

                randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                            # Some PIDs are larger than 16 bit

                packetIdentifier = randomIdentifier
                packetSequenceNumber = i

                icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
                icmpPacket.setIcmpTarget(host)
                icmpPacket.sendEchoRequest()                                                # Build IP

                icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                
                # if no packet was lost, add the packet RTT to the list
                if icmpPacket.getPacket_lost() == False:
                    rtt_list.append(icmpPacket.getRtt())
                
                # stop sending pings if recieved the last reply
                if icmpPacket.getReply_type() != 11:
                    stop = True
            j += 1
        
        percent_lost = ((j-len(rtt_list)) / j ) * 100
        # Print out results
        print("\nTraceroute Statistics for %s:\n\tPackets: Sent = %.0f, Revieved = %.0f, Lost = %.0f (%.0f percent loss)," %(host, j, len(rtt_list), j - len(rtt_list), percent_lost))
        print("\nTrace Complete.\n")


    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    icmpHelperPing.sendPing("209.233.126.254")
    #icmpHelperPing.sendPing("www.google.com")
    #icmpHelperPing.sendPing("oregonstate.edu")
    #icmpHelperPing.sendPing("gaia.cs.umass.edu")
    #icmpHelperPing.sendPing("ox.ac.uk")
    #icmpHelperPing.sendPing("baidu.com")
    #icmpHelperPing.sendPing("sdn.dk") # meant to timeout
    #icmpHelperPing.traceRoute("google.com")
    #icmpHelperPing.traceRoute("oregonstate.edu")
    #icmpHelperPing.traceRoute("ox.ac.uk")
    #icmpHelperPing.traceRoute("baidu.com")
    #icmpHelperPing.traceRoute("209.233.126.254")

if __name__ == "__main__":
    main()
