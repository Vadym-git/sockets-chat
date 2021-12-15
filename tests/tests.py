import json
import unittest
import datetime
from common.functions import get_ip_port, get_raw_data


class TestServer(unittest.TestCase):
    """
    В этом классе будут выолнятся проверки для модуля сервера.
    """

    def test_ip(self):  # благодаря этому тесту нашел ошибку коде.
        self.assertEqual(get_ip_port(['', '192.168.0.1', 8080])[0], '192.168.0.1')

    def test_port(self):
        self.assertEqual(get_ip_port(['', '192.168.0.1', 8080])[1], 8080)

    def test_raw_data(self):
        time = datetime.datetime.now().timestamp()
        example = {
            "action": "msg",
            "time": time,
            "to": "#room_name",
            "from": "account_name",
            "message": 'Hello world'
        }
        self.assertEqual(get_raw_data(json.dumps(example).encode()), example)

