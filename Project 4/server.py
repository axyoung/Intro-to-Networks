# Project 4: Client-Server Chat
# This program creates a very simple server using python socket API
# Author: Alex Young
# Date: 6/3/2021

# Sources used in the creation of this program:
# https://realpython.com/python-sockets/
# https://stackoverflow.com/questions/5598181/multiple-prints-on-the-same-line-in-python
# my Project 1 server code

import socket                       # Import python socket API

HOST = '127.0.0.1'                  # localhost
PORT = 7587                         # 127.0.0.1:7587 will be the port number for this server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))            # After generating the socket, bind it to the post
    s.listen()                      # Setup the server to listen for connection
    connection, addr = s.accept()   # Wait for an incoming connection
    print("Server listening on: localhost on port:", PORT)
    print("Connected by", addr)
    print("Waiting for message...")
    count = 0
    while True:
        data = connection.recv(2058)                # recieve 2058 bytes of data at a time
        string = data.decode()                      # every time we recieve data from the get request, add it to a string to be printed

        if string == "/q":                          # If the message is /q, then quit
            break
        
        print(string)                               # Print out the recieved data
        
        if count == 0:
            print("Type /q to quit\nEnter message to send...")
        
        print("> ", end="", flush=True)             # https://stackoverflow.com/questions/5598181/multiple-prints-on-the-same-line-in-python
        msg = input()                               # Prompt for reply
        connection.sendall(bytes(msg, 'utf-8'))     # Send the data back to the server and print it out

        if msg == "/q":                             # If the message is /q, then quit
            break

        count += 1
    
    socket.close                                    # When we are done, close the socket
