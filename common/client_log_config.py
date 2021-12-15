import logging
import logging.handlers
import pathlib
import sys
from pathlib import Path
import os

#  ----------------------------------------  settings for client  ----------------------------------------

client_logger = logging.getLogger('client_logs')  # Создаем регистратор
client_logger.setLevel(logging.INFO)

#  ----------  Создаем и настраиваем обработчик  ----------
to_stderr = logging.StreamHandler(sys.stderr)  # Поток вывода
to_stderr.setLevel(logging.CRITICAL)
std_format = logging.Formatter("%(levelname)-10s %(asctime)s %(message)s")  # Настройка формата записи сообщения
to_stderr.setFormatter(std_format)

#  ----------  Создаем и настраиваем обработчик  ----------
log_file_path = os.path.join(Path(__file__).parent.parent.absolute(), r'logs/client.log')
to_file = logging.FileHandler(log_file_path)  # Поток вывода
std_format = logging.Formatter("%(levelname)-10s %(asctime)s %(message)s")  # Настройка формата записи сообщения
to_file.setFormatter(std_format)

#  ----------  Добавляем обработчики к регистратору
client_logger.addHandler(to_stderr)
client_logger.addHandler(to_file)

if __name__ == "__main__":
    # client_logger.info('working')
    pass
