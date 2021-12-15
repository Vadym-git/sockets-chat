import sys
import json
import socket
import threading
import time
from sys import argv
from common.variables import IP_ADDRESS, PORT
from PySide6 import QtCore, QtWidgets, QtGui
from common.functions import decode_message, encode_message
from common.classes import Window, ClientSocket, Socket, Client


if __name__ == "__main__":
    a = Client()
    # IP_ADDRESS = Socket.IP_ADDRESS
    # PORT = Socket.PORT
    # if argv and len(argv) == 3:  # IP and PORT check
    #     IP_ADDRESS, PORT = Socket.get_ip_port(argv)
    #
    # client = ClientSocket(IP_ADDRESS, PORT)
    # client.connect()
    # client.presence()
    # presence()
    # read_m = threading.Thread(target=client.read_mass)
    # read_m.daemon = True
    # read_m.start()
    # while True:
    #     client.send_mass({
    #         'from': client.username, 'action': 'msg', 'to': input('To:\n'), 'message': input('Text:\n')
    #     })
