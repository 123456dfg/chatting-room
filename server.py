import socket
import threading
import queue
import ssl
import os
import json
import time
import uuid
import hashlib
from datetime import datetime
from typing import List

msg_queue = queue.Queue()
msg_queue_lock = threading.Lock()


def getHashPassword(password):
    return hashlib.sha256(password.encode()).hexdigest()


class userClient:
    def __init__(self, username, nickname, user_socket: ssl.SSLSocket):
        self.msg_queue: queue.Queue[str] = queue.Queue(maxsize=100)
        self.connect_status = True
        self.user_socket: ssl.SSLSocket = user_socket
        self.username = username
        self.nickname = nickname
        self.user_socket.settimeout(10)
        threading.Thread(target=self.listenLoop).start()

    def listenLoop(self):
        try:
            while True:
                data = self.user_socket.recv(1024).decode('utf-8')
                if not data:  # 客户端断开连接
                    self.connect_status = False
                    break
                data_dict = json.loads(data)
                method = data_dict["type"]
                if method == "heartbeat":
                    self.connect_status = True
                if method == "msg":
                    with msg_queue_lock:
                        msg_queue.put(data_dict)

        except socket.timeout:
            print("No data received within 10 seconds, assuming the peer is offline.")
            self.connect_status = False

        except Exception as e:
            print(f"Error handling client: {e}")
            self.connect_status = False
        finally:
            print("Client to credit connection closed: {}".format(self.user_socket.getpeername()))
            self.connect_status = False

    def send(self, data: str):
        if self.connect_status:
            self.user_socket.sendall(data.encode('utf-8'))
        else:
            self.msg_queue.put(data)

    def reOnline(self, client_socket: ssl.SSLSocket):
        self.connect_status = True
        self.user_socket = client_socket
        threading.Thread(target=self.listenLoop).start()
        while not self.msg_queue.empty():
            self.user_socket.sendall(self.msg_queue.get().encode('utf-8'))

    def sendHeartbeat(self):
        if self.connect_status:
            heartbeat = json.dumps({"type": "heartbeat", "data": "hello"})
            try:
                self.user_socket.sendall(heartbeat.encode('utf-8'))
            except ssl.SSLZeroReturnError:
                self.connect_status = False


class chatServer:
    def __init__(self, ip_addr, port):
        # address configure
        self.chat_addr = (ip_addr, port)

        # ssl socket configure
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile='certificate.pem', keyfile='private_key.pem', password='a13664938755')
        self.chat_server_socket = self.context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))

        # user data
        self.user_data = "database.json"
        self.users: List[userClient] = []

    def run(self):
        self.chat_server_socket.bind(self.chat_addr)
        self.chat_server_socket.listen(100)
        threading.Thread(target=self.sendHeartbeat).start()
        print(f"Chat Server listening on {self.chat_addr}")
        while True:
            client_socket, addr = self.chat_server_socket.accept()
            print(f"Connection from {addr}")
            self.responseInit(client_socket)

    def sendMsg(self):
        """
        用于发送来自一个客户端的消息到其他客户端
        :return:
        """
        while True:
            if not msg_queue.empty():
                with msg_queue_lock:
                    while not msg_queue.empty():
                        data_dict = msg_queue.get()
                        for user in self.users:
                            if user.user_socket != data_dict["username"]:
                                timestamp = datetime.now().strftime('%H:%M')
                                data = json.dumps({"type": "msg", "msg": data_dict["msg"],
                                                   "timestamp": timestamp, "nickname": user.nickname})
                                user.send(data)

    def responseInit(self, client_socket):
        """
        初始化用户，若用户列表不存在则加入，若存在则设置其为在线刷新消息
        :param client_socket: 客户端的连接
        :return:
        """
        init_data = client_socket.recv(1024).decode('utf-8')
        if init_data:
            data_dict = json.loads(init_data)
            method = data_dict["type"]
            if method == "init":
                username = data_dict["username"]
                for user_client in self.users:
                    if user_client.username == username and not user_client.connect_status:
                        user_client.reOnline(client_socket)
                        return
                try:
                    with open(self.user_data, 'r') as file:
                        data: dict = json.load(file)
                        if data.__len__() != 0:
                            for user in data.values():
                                if username == user["username"]:
                                    nickname = user["nickname"]
                                    self.users.append(userClient(username, nickname, client_socket))
                                    response = json.dumps({"type": "init", "code": "success", "nickname": nickname})
                                    client_socket.sendall(response.encode('utf-8'))
                except json.JSONDecodeError:
                    return
        else:
            response = json.dumps({"type": "init", "code": "failed"})
            client_socket.sendall(response)
            return

    def sendHeartbeat(self):
        while True:
            for user in self.users:
                threading.Thread(target=user.sendHeartbeat).start()
            time.sleep(5)


class creditServer:
    def register(self, data_dict, client_socket: ssl.SSLSocket):
        nickname = data_dict["nickname"]
        username = data_dict["username"]
        password = data_dict["password"]
        success = self.addUser(username, nickname, getHashPassword(password))
        if success:
            response_data = json.dumps({"type": "register", "code": "success", "msg": "注册成功"})
        else:
            response_data = json.dumps({"type": "register", "code": "fail", "msg": "注册失败，用户名已存在"})
        client_socket.sendall(response_data.encode('utf-8'))
        print(response_data)

    def login(self, data_dict, client_socket: ssl.SSLSocket):
        username = data_dict["username"]
        password = data_dict["password"]
        if self.credit(username, password):
            response_data = json.dumps({"type": "login", "code": "success", "msg": "登录成功"})
        else:
            response_data = json.dumps({"type": "login", "code": "failed", "msg": "登录失败，用户名或密码错误"})
        client_socket.sendall(response_data.encode('utf-8'))

    def addUser(self, username, nickname, password) -> bool:
        with self.lock:
            try:
                with open(self.user_data, 'r') as file:
                    data: dict = json.load(file)
                    if data.__len__() != 0:
                        for user in data.values():
                            if username == user["username"]:
                                return False
            except json.JSONDecodeError:
                data = {}

            with open(self.user_data, 'w', encoding='utf-8') as file:
                user_uuid = str(uuid.uuid1())
                data[user_uuid] = ({"username": username, "password": password, "nickname": nickname})
                json.dump(data, file, ensure_ascii=False, indent=4)

        return True

    def forgetPassword(self, data_dict, client_socket: ssl.SSLSocket):
        username = data_dict["username"]
        new_password = (getHashPassword(data_dict["password"]))
        success = False
        with self.lock:
            try:
                with open(self.user_data, 'r') as file:
                    data: dict = json.load(file)
                    if data.__len__() != 0:
                        for user in data.values():
                            if username == user["username"]:
                                user["password"] = new_password
                                success = True
            except json.JSONDecodeError:
                data = {}

        with open(self.user_data, 'w', encoding='utf-8') as file:
            json.dump(data, file, ensure_ascii=False, indent=4)

        if success:
            response_data = json.dumps({"type": "forget", "code": "success", "msg": "修改密码成功"})
        else:
            response_data = json.dumps({"type": "forget", "code": "fail", "msg": "修改密码失败，该用户可能不存在"})
        client_socket.sendall(response_data.encode('utf-8'))
        print(response_data)

    def credit(self, username, password) -> bool:
        try:
            with open(self.user_data, 'r') as file:
                data: dict = json.load(file)
                if data.__len__() != 0:
                    for user in data.values():
                        if username == user["username"]:
                            if getHashPassword(password) == user["password"]:
                                return True
                            else:
                                break
        except json.JSONDecodeError:
            pass
        return False

    def run(self):
        self.credit_server_socket.bind(self.credit_addr)
        self.credit_server_socket.listen(10)
        print(f"Credit Server listening on {self.credit_addr}")
        while True:
            client_socket, addr = self.credit_server_socket.accept()
            print(f"Connection from {addr}")
            threading.Thread(target=self.creditServerListen, args=(client_socket,)).start()

    def __init__(self, ip_addr, port):
        # address configure
        self.credit_addr = (ip_addr, port)

        # ssl socket configure
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile='certificate.pem', keyfile='private_key.pem', password='a13664938755')
        self.credit_server_socket = self.context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))

        # user data
        self.clients = []
        self.user_data = "database.json"
        if not os.path.exists(self.user_data):
            with open(self.user_data, 'w', encoding='utf-8') as file:
                json.dump({}, file)

        # thread configure
        self.lock = threading.Lock()

    def creditServerListen(self, client: ssl.SSLSocket):
        try:
            while True:
                data = client.recv(1024).decode('utf-8')
                if not data:  # 客户端断开连接
                    break
                data_dict = json.loads(data)
                method = data_dict["type"]
                # register
                if method == "register":
                    self.register(data_dict, client)
                # login
                elif method == "login":
                    self.login(data_dict, client)
                # forget password
                elif method == "forget":
                    self.forgetPassword(data_dict, client)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            print("Client to credit connection closed: {}".format(client.getpeername()))
            client.close()


if __name__ == '__main__':
    credit_server = creditServer('127.0.0.1', 25566)
    chat_server = chatServer('127.0.0.1', 25567)
    threading.Thread(target=credit_server.run).start()
    threading.Thread(target=chat_server.run).start()
