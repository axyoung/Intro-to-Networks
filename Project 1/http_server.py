# Project 1: Sockets and HTTP
# This program creates a very simple http server using python socket API
# Author: Alex Young
# Date: 4/12/2021

# Sources used in the creation of this program:
# https://docs.python.org/3/howto/sockets.html
# https://docs.python.org/3/library/socket.html
# https://realpython.com/python-sockets/
# https://www.programiz.com/python-programming/methods/built-in/bytes

import socket                       # Import python socket API

string = ""
MSG = "HTTP/1.1 200 OK\r\n"\
    "Content-Type: text/html; charset=UTF-8\r\n\r\n"\
    "<html>Congratulations! You've downloaded the first Wireshark lab file!</html>\r\n"
DATA = bytes(MSG, 'utf-8')
HOST = '127.0.0.1'
PORT = 7587                         # 127.0.0.1:7587 will be the port number for this server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))            # After generating the socket, bind it to the post
    s.listen()                      # Setup the server to listen for connection
    connection, addr = s.accept()   # Wait for an incoming connection
    print("Connected by", addr)
    data = connection.recv(2048)    # Recieve 2048 bytes of data at a time (this enough to store the entire connection)
    print("\nRecieved:", data)      # Print out the recieved data
    
    print("\nSending>>>>>>>>")
    connection.sendall(DATA)        # Send the data back to the server and print it out
    print(MSG)
    print("<<<<<<<<")
    
    socket.close                    # When we are done, close the socket
