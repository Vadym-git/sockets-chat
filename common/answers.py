import datetime

answers: dict = {
    'client_presence': {
            "action": "presence",
            "time": datetime.datetime.now().timestamp(),
            "type": "status",
            "user": {
                    "account_name":  "vadym",
                    "status": "online"
                    }
    },

    'server_response': {
        "response": 200,
        "alert": ''
    }
}