# Project 1: Sockets and HTTP
# This program connects to the wireshark labs and reads in a larger message
# Author: Alex Young
# Date: 4/12/2021

# Sources used in the creation of this program:
# https://docs.python.org/3/howto/sockets.html
# https://docs.python.org/3/library/socket.html
# https://zetcode.com/python/socket/
# https://realpython.com/python-sockets/
# https://www.programiz.com/python-programming/methods/built-in/bytes

import socket                       # import python socket API

string = ""                         # String that will hold the recieved data
REQUEST_1 = "GET /wireshark-labs/INTRO-wireshark-file1.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n"
REQUEST_2 = "GET /wireshark-labs/HTTP-wireshark-file3.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n"
REQ = bytes(REQUEST_2, 'utf-8')     # Change the request into bytes for the sendall to use
HOST = "gaia.cs.umass.edu"
PORT = 80                           # Use port 80 as the standard for http
print("Request:", REQUEST_2)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))         # After generating the socket, we connect to the host port
    s.sendall(REQ)                  # and send the GET request

    while True:                     # until we break, keep recieving data from the server so that all data will be transfered
        data = s.recv(512)          # recieve 512 bytes of data at a time
        if not data:                # break out of the loop once we have read all the data
            break
        string += data.decode()     # every time we recieve data from the get request, add it to a string to be printed
    
    socket.close                    # when we are done, close the socket

print("[RECV] - length:", len(string))
print(string)