# Project 4: Client-Server Chat
# This program creates a very simple client using python socket API
# Author: Alex Young
# Date: 6/3/2021

# Sources used in the creation of this program:
# https://realpython.com/python-sockets/
# https://stackoverflow.com/questions/5598181/multiple-prints-on-the-same-line-in-python
# my Project 1 client code

import socket                       # import python socket API

HOST = 'localhost'                  # localhost
PORT = 7587                         # Use port 7587

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))         # After generating the socket, we connect to the host port
    print("Connected to:", HOST, "on port:", PORT)
    print("Type /q to quit\nEnter message to send...")
    while True:
        print("> ", end="", flush=True) # https://stackoverflow.com/questions/5598181/multiple-prints-on-the-same-line-in-python
        msg = input()                   # Prompt for message to send
        s.sendall(bytes(msg, 'utf-8'))  # Send the msg
        
        if msg == "/q":                 # If the message is /q, then quit
            break

        data = s.recv(2058)             # recieve 2058 bytes of data at a time
        string = data.decode()          # every time we recieve data from the get request, add it to a string to be printed
        
        if string == "/q":              # If the message is /q, then quit
            break
        
        print(string)
    
    socket.close                        # when we are done, close the socket
