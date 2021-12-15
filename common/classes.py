from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import re
import time
import json
from json import JSONDecodeError
import sys
import os
import threading
from pathlib import Path
from PySide6 import QtCore, QtWidgets, QtGui
import traceback
import winsound


class Socket:
    CODDING = 'utf-8'
    q_bites = 4096
    PORT = 9090
    IP_ADDRESS = '127.0.0.1'

    def __init__(self, ip_address: str, port: int):
        self._ip_address = ip_address
        self._port = int(port)
        self.socket = socket(AF_INET, SOCK_STREAM)

    def get_ip_port(*args):
        from common.client_log_config import client_logger
        from common.server_log_config import server_logger
        """
        Пишу логи в клиент и в сервер так как эта функция одна на двоих.
        Пока нет возможности разделить запись в замисимости от вызываемого файла
        """
        try:
            _, ip_address, port = args[0]
        except ValueError:
            ip_address, port = args
        ip_checking = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_address)
        if not ip_checking:
            server_logger.critical(f'Wrong IP: {args}')  # передаю все args чтобы видеть, что там было вообще введено
            client_logger.critical(f'Wrong IP: {args}')
            exit('WRONG IP ADDRESS FORMAT')
        if not 1025 < int(port) < 65535:
            server_logger.critical(f'Wrong PORT: {args}')  # передаю все args чтобы видеть, что там было вообще введено
            client_logger.critical(f'Wrong PORT: {args}')
            exit(f'WRONG PORT, MUST BE BETWEEN 1024 and 65535, you got {port}')
        server_logger.info(f'Started connection on IP: {ip_address}, PORT: {int(port)}')
        client_logger.info(f'Started connection on IP: {ip_address}, PORT: {int(port)}')
        return ip_address, int(port)

    @staticmethod
    def decode_message(message: bytes) -> dict:
        if not message:
            return {}
        try:
            return json.loads(message.decode())
        except JSONDecodeError:
            print('JSON Decode ERROR')
            # print(traceback.format_exc())

    @staticmethod
    def encode_message(message: dict) -> bytes:
        return json.dumps(message).encode()


class Server(Socket):

    def __init__(self, ip_address: str, port: int):
        super().__init__(ip_address, port)
        self.__to_read: dict = {}
        self.__to_write: dict = {}
        self.__clients_requests: dict = {}  # масив запросов от клиентов
        self.__server_responses: dict = {}  # масив готовых ответов от сервера
        self.__to_read[self.socket] = time.time()

    def set_up(self, timeout: float = 1.0, connections: int = 3):
        self.socket.bind((self._ip_address, self._port))
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.socket.settimeout(timeout)
        self.socket.listen(connections)

    def accept_connection(self):
        client, addr = self.socket.accept()
        print(f'Connected with {client.getpeername()}')
        self.__to_read[client] = time.time()

    def get_client_request(self, socket):
        """
        1.Получаем запрос клиента. Декодируем запрос
        2. Добавляем запрос в словарь запросов от этого сокета
        """
        try:
            request = socket.recv(Socket.q_bites)
        except ConnectionResetError:
            print(f'Disconnected: {socket.getpeername()}')
            socket.close()
            self.__to_read.pop(socket)
            self.__to_write.pop(socket)
            # broadcast(f'{name.capitalize()} left chat!')
            return
        request = Socket.decode_message(request)
        if not request:
            # print(socket)
            return
        try:
            previous_requests = self.__clients_requests[socket]
            previous_requests[time.time()] = request  # Добавляем запрос клиента в словарь запросов
        except KeyError:
            if request:
                self.__clients_requests[socket] = {time.time(): request}
        try:
            self.__to_write[socket] = request['from']  # Добавляем сокет для отслеживание на запись(отправку данных)
        except KeyError:
            self.__to_write[socket] = request['user']  # Добавляем сокет для отслеживание на запись(отправку данных)
        except TypeError:
            print(request)
            sys.stdout = traceback.format_exc()

    def send_server_answer(self, ready_to_write_list):
        try:
            for i in self.__server_responses:
                if i in ready_to_write_list:
                    responses = self.__server_responses[i]
                    for response in responses:
                        response = responses[response]
                        i.send(self.encode_message(response))
                self.__server_responses.pop(i)
        except RuntimeError:
            pass

    def make_server_answer(self):
        """
        В этом месте наш месенджер будет делать полезную работу.
        В будущем эта функция будет переписана и скорее всего розделена на несколько.
        """
        for clint_socket in self.__clients_requests:
            requests_from_socket = self.__clients_requests[clint_socket]
            try:
                for request in requests_from_socket:
                    id = request
                    request = requests_from_socket[request]
                    action = self.__server_actions[request['action']]
                    action(self, request, id, socket=clint_socket)
            except RuntimeError:
                pass
            except KeyError:
                pass

    def __presence(self, request: dict, request_id, socket):
        response: dict = {
            'response': 200,
            'action': 'presence',
            'time': time.time(),
            'alert': f'Your login is: {request["user"]}'
        }
        login = request['user']
        for i in self.__to_write:
            if self.__to_write[i] == request['user'] and i != socket:
                response['response'] = 409
                response['alert'] = 'Login was already taken'
                login = False
                break
        try:
            responses = self.__server_responses[socket]
            responses[time.time()] = response
        except KeyError:
            self.__server_responses[socket] = {time.time(): response}
        if login:
            self.__to_write[socket] = request['user'].lower()
        self.__clients_requests[socket].pop(request_id)

    def __check_user_online(self, name: str):
        for i in self.__to_write:
            if self.__to_write[i] == name:
                return i
        return False

    def __msg(self, request: dict, request_id, socket):
        """Функция будет переписываться"""
        response: dict = {
            'response': 200,
            'time': time.time(),
            'from': request['from'],
            'action': 'message',
            'message': request['message']
        }
        # проверяем готов готов ли сокет получателя для записи
        recipient = self.__check_user_online(request['to'])
        if recipient:
            try:
                responses = self.__server_responses[recipient]
                responses[time.time()] = response
            except KeyError:
                self.__server_responses[recipient] = {time.time(): response}
        else:
            try:
                responses = self.__server_responses[socket]
                response['message'] = 'User not found'
                response['response'] = 410
                responses[time.time()] = response
            except KeyError:
                response['message'] = 'User not found'
                response['response'] = 410
                self.__server_responses[socket] = {time.time(): response}
        self.__clients_requests[socket].pop(request_id)

    def __get_online_users(self, request: dict, request_id, socket):
        response: dict = {
            'response': 200,
            'time': time.time(),
            'from': request['from'],
            'action': 'contacts',
            'message': [i for i in self.__to_write.values()]
        }
        try:
            responses = self.__server_responses[socket]
            responses[time.time()] = response
        except KeyError:
            self.__server_responses[socket] = {time.time(): response}
            print('DONE')
        self.__clients_requests[socket].pop(request_id)

    __server_actions: dict = {
        'msg': __msg,
        'presence': __presence,
        'users_online': __get_online_users,
    }

    def to_read(self):
        return self.__to_read

    def to_write(self):
        return self.__to_write


class ClientSocket(Socket):

    def __init__(self, ip_address: str, port: int):
        super().__init__(ip_address=ip_address, port=port)
        self._status = False
        self._ip = ip_address
        self._port = port
        self.username = None

    def connect(self):
        self.socket.connect((self._ip, self._port))

    def read_mass(self):
        response = self.decode_message(self.socket.recv(Socket.q_bites))
        return response

    def send_mass(self, text: dict):
        self.socket.send(self.encode_message(text))

    def presence(self, user_name):
        if not user_name:
            raise ValueError(f'Username cant be type: None')
        request = {
            "action": "presence",
            "time": time.time(),
            "type": "status",
            "user": user_name
        }
        self.send_mass(request)

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status: bool):
        self._status = status

    @property
    def ip(self):
        return self.ip

    @ip.setter
    def ip(self, ip: str):
        self._ip = ip

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, port: int):
        self._port = port


class Storage:
    def __init__(self, db_path):
        import sqlite3
        self.storage = sqlite3.connect(f'{db_path}.db')
        self._cursor = self.storage.cursor()

    def new_table(self, table_name: str, columns_and_types: dict):
        """
        :param table_name: users,
        :param columns_and_types: integer unique,  string
        """
        data = ', '.join([f'{i} {columns_and_types[i]}' for i in columns_and_types])
        self._cursor.execute(f"""CREATE TABLE IF NOT EXISTS {table_name} ({data})""")

    def insert_into(self, table_name: str, *args):
        self._cursor.execute(f"""INSERT INTO {table_name} VALUES {args};""")
        self.storage.commit()

    def get_data_from_table(self, columns: tuple, table_name: str, where: list = ''):
        if where and len(where) == 2:
            where = f'{where[0]} = {where[1]}'
        return self._cursor.execute(
            f"""SELECT {', '.join([i for i in columns])} FROM {table_name} {where};""").fetchall()


# storage = Storage('users')
# storage.new_table('client', {'login': 'string unique', 'info': 'string'})
# storage.new_table('history', {'ip': 'string unique', 'time': 'string'})
# storage.insert_into('client', 'test', 'test_info')
# storage.insert_into('history', '127.0.0.12', time.time())
# print(storage.get_data_from_table(columns=('*',), table_name='client'))
# print(storage.get_data_from_table(columns=('*',), table_name='history'))

# ======================================================== GUI ========================================================
media_f = os.path.abspath(r'C:\Users\Vadym\OneDrive\Documents\CODE_LEARN\Client-server\chat\media')


class MainTab(QtWidgets.QTabWidget):

    def __init__(self, window):
        super().__init__()
        self.window_obj = window
        # general window layout
        self.general_layout = QtWidgets.QHBoxLayout(self)
        # vertical layout for contacts at the left side and rights side for messages and typing screen
        self.messages_read_write_layout = QtWidgets.QVBoxLayout(self)
        # typing area and send button layout
        self.type_and_send_layout = QtWidgets.QHBoxLayout(self)
        # contacts side
        self.contacts_screen = QtWidgets.QListWidget()
        self.contacts_screen.setViewMode(QtWidgets.QListView.IconMode.ListMode)
        self.contacts_screen.setMaximumWidth(300)
        self.contacts_screen.itemClicked.connect(self.selection_changed)
        # typing side
        self.message_screen = QtWidgets.QListWidget()
        self.write_window = QtWidgets.QTextEdit()
        self.write_window.setFixedHeight(100)
        # self.write_window.setFocus()
        # send button
        self.send_button = QtWidgets.QPushButton(icon=QtGui.QIcon(media_f + '/telegram.png'))
        self.send_button.setIconSize(QtCore.QSize(61, 57))
        # ====
        self.general_layout.addWidget(self.contacts_screen)
        self.general_layout.addLayout(self.messages_read_write_layout)
        self.messages_read_write_layout.addWidget(self.message_screen)
        self.messages_read_write_layout.addLayout(self.type_and_send_layout)
        self.type_and_send_layout.addWidget(self.write_window)
        self.type_and_send_layout.addWidget(self.send_button)
        self.send_button.clicked.connect(self.preparation_data_for_send)

    def preparation_data_for_send(self):
        try:
            to = self.contacts_screen.currentItem()
            te_text = to.text()
        except AttributeError:
            self.window_obj.status_bar.help_text.setText('You have to select recipient')
            return
        text = self.write_window.toPlainText()
        if not text:
            self.window_obj.status_bar.help_text.setText('You have to type something')
            return
        response = {'from': self.window_obj.window_socket.username,
                    'action': 'msg',
                    'to': te_text,
                    'message': text}
        self.window_obj.send_message(response)
        self.write_window.clear()
        data = self.window_obj.messages.get(te_text)
        if data:
            data.append([time.time(), text, 0])
        else:
            self.window_obj.messages[te_text] = [[time.time(), text, 0]]

        self.selection_changed(to)

    def selection_changed(self, item):
        if isinstance(item, str):
            data = self.window_obj.messages.get(item)
        else:
            data = self.window_obj.messages.get(item.text())
        if data:
            self.message_screen.clear()
            for stime, text, address in data:
                if address == 0:
                    sender = QtWidgets.QListWidgetItem(f'{text}\n You: {time.strftime("%H:%M", time.gmtime(stime))}')
                    self.message_screen.addItem(sender)
                    sender.setTextAlignment(0x0002)
                else:
                    sender = QtWidgets.QListWidgetItem(f'{text}\n{item.text().capitalize()}: {time.strftime("%H:%M", time.gmtime(stime))}')
                    self.message_screen.addItem(sender)
                    sender.setTextAlignment(0x0001)
        else:
            self.message_screen.clear()
        if item.statusTip() == 'new':
            image = QtGui.QPixmap(media_f + '/success.png')
            item.setIcon(image)
            item.setStatusTip('on')
        elif item.statusTip() == 'off':
            image = QtGui.QPixmap(media_f + '/error.png')
            item.setIcon(image)
            item.setStatusTip('off')


class TabWidget(QtWidgets.QTabWidget):
    def __init__(self, window):
        icon_size = QtCore.QSize(32, 32)
        super().__init__()
        self.main_tab = MainTab(window)
        self.settings_tab = SettingsTab(window)
        self.main = self.addTab(self.main_tab, 'Chats')
        self.settings = self.addTab(self.settings_tab, 'Settings')
        # #  =======  tabs settings  =======
        # #  main tab
        self.setTabIcon(self.main, QtGui.QIcon(media_f + '/message.png'))
        self.setIconSize(icon_size)
        # # settings tab
        self.setTabIcon(self.settings, QtGui.QIcon(media_f + '/cloud-storage.png'))
        self.setIconSize(icon_size)


class Window(QtWidgets.QWidget):

    def __init__(self):
        super().__init__()
        self.messages = {}
        # window settings
        self._login = ''
        self._ip = ''
        self._port = 0
        self.window_socket = ClientSocket(self._ip, self._port)
        self.setWindowTitle('Work Chat')
        self.setWindowIcon(QtGui.QIcon(media_f + '/chat-box.png'))
        #  =======  stat treads  =======
        self.__reconnect = threading.Thread(target=self.__check_connection)
        self.__reconnect.daemon = True
        self.__reconnect.start()
        #  +++
        self.__contacts_update = threading.Thread(target=self.__request_contacts_update)
        self.__contacts_update.daemon = True
        self.__contacts_update.start()
        #  ===
        self.layout = QtWidgets.QVBoxLayout(self)
        self.tab_widget = TabWidget(self)
        self.status_bar = StatusBar(self)
        self.layout.addWidget(self.tab_widget)
        self.layout.addWidget(self.status_bar)
        #  +++
        self.__server_response = threading.Thread(target=self.__parse_server_resp)
        self.__server_response.daemon = True
        self.__server_response.start()

    def __request_contacts_update(self):
        while True:
            if self._login:
                text = {'from': self._login, 'action': 'users_online'}
                self.send_message(text)
                time.sleep(5)

    def contacts_update(self, response):
        added = []
        try:
            response['message'].remove(self._login)
        except ValueError:
            pass
        for x in range(self.tab_widget.main_tab.contacts_screen.count()):
            item = self.tab_widget.main_tab.contacts_screen.item(x)
            added.append(item.text())
            if item.statusTip() == 'new':
                pass
            else:
                if item.text() not in response['message']:
                    image = QtGui.QPixmap(media_f + '/error.png')
                    item.setIcon(image)
                    item.setStatusTip('off')
                else:
                    image = QtGui.QPixmap(media_f + '/success.png')
                    item.setIcon(image)
                    item.setStatusTip('on')

        item = QtWidgets.QListWidgetItem()
        for k, i in enumerate(response['message']):
            if i in added:
                pass
            else:
                image = QtGui.QPixmap(media_f + '/success.png')
                item.setText(i)
                item.setIcon(image)
                item.setStatusTip('on')
                self.tab_widget.main_tab.contacts_screen.addItem(item)

    def set_username(self, response):
        if response['response'] == 200:
            self.window_socket.status = True
        else:
            self.window_socket.status = False
            self._login = ''

    def __parse_server_resp(self):
        while True:
            try:
                response = self.window_socket.read_mass()
            except WindowsError as error:
                self.window_socket.status = False
                time.sleep(1)
                continue
            if response:
                try:
                    action = self.__actions[response['action']]
                except KeyError:
                    print('Action ERROR')
                    continue
                action(self, response)

    def send_message(self, data: dict):
        try:
            self.window_socket.send_mass(data)
        except ConnectionResetError as error:
            print('Disconnected')
            self.window_socket.status = False
            self.window_socket.socket.close()
        except WindowsError as es:
            print('Disconnected')
            self.window_socket.status = False
            self.window_socket.socket.close()

    def __check_connection(self):
        while True:
            if not self.window_socket.status:

                try:
                    self.window_socket.connect()
                except OSError as error:
                    if error.winerror == 10056:
                        pass
                    elif error.winerror == 10049:
                        self.window_socket.ip = self._ip
                        self.window_socket.port = self._port
                        continue
                    else:
                        self.status_bar.help_text.setText(str(error))

                try:
                    self.window_socket.presence(self._login)
                except ValueError:
                    continue
                except ConnectionResetError:
                    self.window_socket = ClientSocket(self._ip, self._port)
                except OSError:
                    self.window_socket = ClientSocket(self._ip, self._port)
            self.status_bar.set_status(self.window_socket.status)
            time.sleep(2)
            # if not self.window_socket.status:
            #     try:
            #         self.window_socket.connect()
            #         print(self.window_socket.username)
            #         self.window_socket.presence(self.window_socket.username)
            #         print(self.window_socket.username)
            #         self.window_socket.status = True
            #     except ConnectionRefusedError:
            #         self.window_socket.status = False
            #     except WindowsError as error:
            #         print(self._ip, self._port, error)
            #         if error.winerror == 10038 or error.winerror == 10049:
            #             self.window_socket.status = False
            #             self.window_socket = ClientSocket(self._ip, self._port)
            #             self.window_socket.username = self._login
            #             print(self.window_socket.status)
            # self.contacts_update({'message': []})

            # self.status_bar.set_status(self.window_socket.status)

    def get_new_message(self, response):
        data = self.messages.get(response['from'])
        if data:
            data.append([response['time'], response['message'], 1])
        else:
            self.messages[response['from']] = [[response['time'], response['message'], 1]]
#====================
        try:
            current_item = self.tab_widget.main_tab.contacts_screen.currentItem()
            if current_item.text() == response['from']:
                self.tab_widget.main_tab.selection_changed(current_item)
        except AttributeError as error:
            print(error, 8)
        image = QtGui.QPixmap(media_f + '/bell.png')
        item = self.tab_widget.main_tab.contacts_screen.findItems(response['from'], QtCore.Qt.MatchFlags())[0]
        item.setStatusTip('new')
        item.setIcon(image)
        winsound.PlaySound(media_f + '/alert.wav', winsound.SND_FILENAME)

    __actions: dict = {
        'presence': set_username,
        'contacts': contacts_update,
        'message': get_new_message,
    }


class StatusBar(QtWidgets.QStatusBar):
    def __init__(self, window: Window):
        super().__init__()
        self.status_connection_widget = QtWidgets.QLabel()
        self.status_text = QtWidgets.QLabel()
        self.help_text = QtWidgets.QLabel()
        self.addWidget(self.status_connection_widget)
        self.addWidget(self.status_text)
        self.addWidget(self.help_text)
        self.set_status(window.window_socket.status)

    def set_status(self, connection_status: bool):
        self.image = media_f + '/error.png'
        self.text = 'Disconnected'
        if connection_status:
            self.image = media_f + '/success.png'
            self.text = 'Connected'
        self.status_connection_widget.setPixmap(QtGui.QPixmap(self.image))
        self.status_text.setText(self.text)
        # self.status_connection_widget.setWindowIconText(self.text)
        self.status_connection_widget.setMaximumSize(QtCore.QSize(16, 16))
        self.status_connection_widget.setScaledContents(True)


class SettingsTab(QtWidgets.QTabWidget):
    def __init__(self, window):
        super().__init__()
        self.window_obj = window
        self.general_layout = QtWidgets.QVBoxLayout(self)
        self.general_layout.setStretch(1, 1)
        self.login_label = QtWidgets.QLabel('Login:')
        self.login_label.setMaximumHeight(25)
        self.login_edit = QtWidgets.QLineEdit('vadym')
        self.ip_label = QtWidgets.QLabel('IP:')
        self.ip_label.setMaximumHeight(25)
        self.ip_edit = QtWidgets.QLineEdit('127.0.0.1')
        self.port_label = QtWidgets.QLabel('Port:')
        self.port_label.setMaximumHeight(25)
        self.port_edit = QtWidgets.QLineEdit('9090')
        self.send_button = QtWidgets.QPushButton(icon=QtGui.QIcon(media_f + '/telegram.png'))
        self.send_button.setIconSize(QtCore.QSize(48, 48))
        self.space = QtWidgets.QLabel()
        self.space.setMinimumHeight(200)
        self.general_layout.addWidget(self.login_label)
        self.general_layout.addWidget(self.login_edit)
        self.general_layout.addWidget(self.ip_label)
        self.general_layout.addWidget(self.ip_edit)
        self.general_layout.addWidget(self.port_label)
        self.general_layout.addWidget(self.port_edit)
        self.general_layout.addWidget(self.send_button)
        self.general_layout.addWidget(self.space)
        self.send_button.clicked.connect(self.get_login_data)

    def get_login_data(self):
        login, ip, port = None, None, None
        if self.login_edit.text():
            self.window_obj._login = self.login_edit.text()
            login = self.login_edit.text()
        if self.ip_edit.text():
            self.window_obj._ip = self.ip_edit.text()
            ip = self.ip_edit.text()
        if self.port_edit.text():
            self.window_obj._port = int(self.port_edit.text())
            port = self.port_edit.text()
        return ip, port


class Client:
    root_folder = str(Path(__file__).parent.parent)

    def __init__(self):
        self.app = QtWidgets.QApplication(sys.argv)
        self.widget = Window()
        self.widget.resize(1200, 800)
        self.widget.show()
        with open(self.root_folder + "/media/style.qss", "r") as f:
            _style = f.read()
            self.app.setStyleSheet(_style)
        sys.exit(self.app.exec())
