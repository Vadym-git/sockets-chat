from select import select
import json
from json import JSONDecodeError
import time
import re
import sys
import datetime
from sys import _getframe
from common.server_log_config import server_logger
from common.client_log_config import client_logger
from .variables import to_read, clients_requests, server_responses, to_write, q_bites

users = []

# decorators
"""
Я решил не выносить декораторы в отдельный модель. Так как мы завели специальный модель для функций.
А декоратор это и есть функция которая меняет поведение другой функции класа.
Так-же мне не удалось добиться того, чтобы декоратор возращал имя функции которая вызывает нашу функцию.
Точнее это работает, но отображается инфармация внутри работы самого декоратора.
"""


def log(function):
    def doing():
        sys.stderr.write(f"""Time: {datetime.datetime.now()}, \
        function: {function.__name__.upper()}, \
        called by function: {_getframe(0).f_code.co_name}\n""".replace('    ', ''))
        # я пробовал сделать это через sys так как через inspect делают все, можно просто скопировать.
        return function()

    return doing


# end decorators


def accept_connection(server_socket):
    client, addr = server_socket.accept()
    print(f'Connected with {client.getpeername()}')
    to_read[client] = time.time()


def get_client_request(socket):
    """
    1.Получаем запрос клиента. Декодируем запрос
    2. Добавляем запрос в словарь запросов от этого сокета
    """
    try:
        request = socket.recv(q_bites)
        request = decode_message(request)
        previous_requests = clients_requests[socket]
        previous_requests[time.time()] = request  # Добавляем запрос клиента в словарь запросов
    except KeyError:
        if request:
            clients_requests[socket] = {time.time(): request}
    except ConnectionResetError:
        print(f'Disconnected: {socket.getpeername()}')
        socket.close()
        to_read.pop(socket)
        name = to_write[socket]
        to_write.pop(socket)
        broadcast(f'{name.capitalize()} left chat!')
        return
    try:
        to_write[socket] = request['from']  # Добавляем сокет для отслеживание на запись(отправку данных)
    except KeyError:
        to_write[socket] = request['user']  # Добавляем сокет для отслеживание на запись(отправку данных)


def send_server_answer(ready_to_write_list):
    try:
        for i in server_responses:
            if i in ready_to_write_list:
                responses = server_responses[i]
                for response in responses:
                    response = responses[response]
                    i.send(encode_message(response))
            server_responses.pop(i)
    except RuntimeError:
        pass


def make_server_answer():
    """
    В этом месте наш месенджер будет делать полезную работу.
    В будущем эта функция будет переписана и скорее всего розделена на несколько.
    """
    for clint_socket in clients_requests:
        requests_from_socket = clients_requests[clint_socket]
        try:
            for request in requests_from_socket:
                id = request
                request = requests_from_socket[request]
                action = server_actions[request['action']]
                action(request, id, socket=clint_socket)
        except RuntimeError:
            pass
        except KeyError:
            pass


def encode_message(message: dict) -> bytes:
    return json.dumps(message).encode()


def decode_message(message: bytes) -> dict:
    try:
        return json.loads(message.decode())
    except JSONDecodeError:
        print(message)


def check_user_online(name: str):
    for i in to_write:
        if to_write[i] == name:
            return i
    return False


def msg(request: dict, request_id, socket):
    """Функция будет переписываться"""
    response: dict = {
        'response': 200,
        'time': time.time(),
        'from': request['from'],
        'message': request['message']
    }
    # проверяем готов готов ли сокет получателя для записи
    recipient = check_user_online(request['to'])
    if recipient:
        try:
            responses = server_responses[recipient]
            responses[time.time()] = response
        except KeyError:
            server_responses[recipient] = {time.time(): response}
    else:
        try:
            responses = server_responses[socket]
            response['message'] = 'User not found'
            response['response'] = 410
            responses[time.time()] = response
        except KeyError:
            response['message'] = 'User not found'
            response['response'] = 410
            server_responses[socket] = {time.time(): response}
    clients_requests[socket].pop(request_id)


def presence(request: dict, request_id, socket):
    response: dict = {
        'response': 200,
        'time': time.time(),
        'alert': f'Your login is: {request["user"]}'
    }
    login = request['user']
    for i in to_write:
        if to_write[i] == request['user'] and i != socket:
            response['response'] = 409
            response['alert'] = 'Login was already taken'
            login = False
            break
    try:
        responses = server_responses[socket]
        responses[time.time()] = response
    except KeyError:
        server_responses[socket] = {time.time(): response}
    if login:
        to_write[socket] = request['user'].lower()
    clients_requests[socket].pop(request_id)


def broadcast(message: str):
    message = {
        'time': time.time(),
        'from': 'server',
        'message': message
    }
    for i in to_write:
        try:
            responses = server_responses[i]
            responses[time.time()] = message
        except KeyError:
            server_responses[i] = {time.time(): message}


def event_loop(server_socket):
    """
    Принцип работы с асинхронностью в этом лупе:
    Перед нырянием в эту функцию мы добавляем серверный сокет в проверку на чтение.
    Заходим в этот цикл, смотрим готовые к чтению сокеты(впервый раз у нас будет только серверный)
    Если серверу что-то написали, мы берем сообщение, обрабатываем, а сокет клиента добавляем на проверку чтения
    """
    while True:
        ready_to_read, ready_to_write, _ = select(to_read, to_write, [])
        for sock in ready_to_read:
            if sock is server_socket:
                accept_connection(sock)
            else:
                get_client_request(sock)
        # берем наши готовые ответы от сервера и отправляем
        send_server_answer(ready_to_write)
        # наполняем ответами от сервара наш словарь
        make_server_answer()


def get_ip_port(*args):
    """
    Пишу логи в клиент и в сервер так как эта функция одна на двоих.
    Пока нет возможности разделить запись в замисимости от вызываемого файла
    """
    _, ip_address, port = args[0]
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


server_actions: dict = {
    'msg': msg,
    'presence': presence,
}
