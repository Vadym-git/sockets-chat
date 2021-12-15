from select import select
from sys import argv
from common.classes import Socket, Server


if __name__ == "__main__":
    IP_ADDRESS = Socket.IP_ADDRESS
    PORT = Socket.PORT
    if argv and len(argv) == 3:  # IP and PORT check
        IP_ADDRESS, PORT = Socket.get_ip_port(argv)
    server = Server(IP_ADDRESS, PORT)
    server.set_up()
    """
    Принцип работы с асинхронностью в этом лупе:
    Перед нырянием в эту функцию мы добавляем серверный сокет в проверку на чтение.
    Заходим в этот цикл, смотрим готовые к чтению сокеты(впервый раз у нас будет только серверный)
    Если серверу что-то написали, мы берем сообщение, обрабатываем, а сокет клиента добавляем на проверку чтения
    """
    while True:
        ready_to_read, ready_to_write, _ = select(server.to_read(), server.to_write(), [])
        for sock in ready_to_read:
            if sock is server.socket:
                server.accept_connection()
            else:
                server.get_client_request(sock)
        # берем наши готовые ответы от сервера и отправляем
        server.send_server_answer(ready_to_write)
        # наполняем ответами от сервара наш словарь
        server.make_server_answer()
