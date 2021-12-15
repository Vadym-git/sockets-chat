import logging
import logging.handlers
import pathlib
import sys
from pathlib import Path
import os

#  ----------------------------------------  settings for server  ----------------------------------------

server_logger = logging.getLogger('server_logs')  # Создаем регистратор
server_logger.setLevel(logging.INFO)

#  ----------  Создаем и настраиваем обработчик  ----------
to_stderr = logging.StreamHandler(sys.stderr)  # Поток вывода
to_stderr.setLevel(logging.CRITICAL)
std_format = logging.Formatter("%(levelname)-10s %(asctime)s %(message)s")  # Настройка формата записи сообщения
to_stderr.setFormatter(std_format)

#  ----------  Создаем и настраиваем обработчик  ----------
log_file_path = os.path.join(Path(__file__).parent.parent.absolute(), r'logs/server.log')
to_file = logging.handlers.TimedRotatingFileHandler(log_file_path, encoding='utf-8', interval=1, when='midnight')  # Поток вывода
std_format = logging.Formatter("%(levelname)-10s %(asctime)s %(message)s")  # Настройка формата записи сообщения
to_file.setFormatter(std_format)

#  ----------  Добавляем обработчики к регистратору
server_logger.addHandler(to_stderr)
server_logger.addHandler(to_file)

if __name__ == "__main__":
    # server_logger.info('working')
    pass