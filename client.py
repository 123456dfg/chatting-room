import os
import socket
import ssl
import threading
import time
import tkinter as tk
import uuid
from datetime import datetime
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import json
import queue


class socketClient:
    def __init__(self):
        self.secure_socket: ssl.SSLSocket = None
        self.ip_addr = ('127.0.0.1', 25566)
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.connet_status = "未连接"
        self.is_connect = False

    def disConnect(self):
        if self.is_connect:
            self.secure_socket.close()
            self.is_connect = False
            self.secure_socket = None

    def connect(self, ip_addr, port) -> bool:
        """
        连接到服务器，如果连接失败返回False并设置连接错误信息,如果连接成功或重复连接则返回True
        :return: bool
        """
        if self.secure_socket is None:
            self.secure_socket = self.context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            try:
                self.secure_socket.connect((ip_addr, port))
                self.is_connect = True

            except socket.timeout:
                self.connet_status = "连接服务器超时"
                print("连接服务器超时")
                self.is_connect = False
                return False
            except ConnectionRefusedError:
                self.connet_status = "服务器未开启"
                print("服务器未开启")
                self.is_connect = False
                return False
            except Exception as e:
                self.connet_status = str(e)
                self.is_connect = False
                print(f"发生错误: {str(e)}")

            return self.is_connect

    def getConnectStatus(self):
        return self.connet_status


def _remove_from_listbox(listbox, username):
    """Helper function to remove a user from a specific Listbox."""
    users = list(listbox.get(0, tk.END))
    if username in users:
        index = users.index(username)
        listbox.delete(index)


class clientGui:

    def __init__(self):
        self.offline_listbox: tk.Listbox = None
        self.online_listbox: tk.Listbox = None
        self.receive_msg_loop: threading.Thread = None
        self.text_area: ScrolledText = None
        self.entry_nickname = None
        self.message_entry: tk.Entry = None
        self.socket_client = socketClient()
        self.entry_username = None
        self.entry_password = None
        self.root: tk.Tk = None
        self.register_sub_window: tk.Toplevel = None
        self.forget_sub_window: tk.Toplevel = None
        self.is_login = False
        self.nickname = None
        self.username = None
        self.timestamp_font = ('Arial', 8, 'normal')
        self.message_font = ('Arial', 12, 'normal')
        self.msg_queue = queue.Queue(maxsize=100)
        self.msg_path = "msg.json"
        self.online_users = set()
        self.users = set()

    def loginInit(self, username):
        self.socket_client.secure_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.socket_client.secure_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        self.username = username
        init_data = json.dumps({"type": "init", "username": self.username})
        self.socket_client.secure_socket.sendall(init_data.encode('utf-8'))
        # 等待服务器发送相关用户信息
        response_data = self.socket_client.secure_socket.recv(1024).decode('utf-8')
        response_data = json.loads(response_data)
        if response_data["code"] == "success":
            self.is_login = True
            self.nickname = response_data["nickname"]
            self.msg_path = self.username + '_' + self.msg_path
            if not os.path.exists(self.msg_path):
                with open(self.msg_path, 'w', encoding='utf-8') as file:
                    json.dump({}, file)
            threading.Thread(target=self.loadLocalMsg, args=[self.msg_path]).start()
        else:
            self.is_login = False
            messagebox.showerror("服务器响应", "加载用户信息失败,请重新登录")
            return
        self.receive_msg_loop = threading.Thread(target=self.receiveMsgLoop)
        self.receive_msg_loop.start()

    def recvEventResponse(self):
        data = self.socket_client.secure_socket.recv(1024).decode("utf-8")
        try:
            data_dict = json.loads(data)
            return data_dict["msg"], data_dict["code"]

        except (ConnectionAbortedError, ConnectionResetError):
            # 将连接对象从监听列表去掉
            print("客户端发生连接异常，与服务器端断开连接")
            self.socket_client.disConnect()
        except Exception as e:
            print(f"客户端发生了其它异常:{e} ")
            self.socket_client.disConnect()

    def sendLoginRequest(self, username, password):
        try:
            login_data = {"type": "login", "username": username, "password": password}
            data = json.dumps(login_data)
            self.socket_client.secure_socket.sendall(data.encode("utf-8"))

        except ConnectionResetError:
            self.socket_client.disConnect()

    def sendRegisterRequest(self, nickname, username, password):
        try:
            register_data = {"type": "register", "username": username, "password": password, "nickname": nickname}
            data = json.dumps(register_data)
            self.socket_client.secure_socket.sendall(data.encode("utf-8"))

        except ConnectionResetError:
            self.socket_client.disConnect()

    def sendForgetRequest(self, username, password):
        try:
            forget_data = {"type": "forget", "username": username, "password": password}
            data = json.dumps(forget_data)
            self.socket_client.secure_socket.sendall(data.encode("utf-8"))
        except ConnectionResetError:
            self.socket_client.disConnect()

    def onForgetClick(self, username, new_password):
        if not username or not new_password:
            messagebox.showwarning("Input Error", "Please enter username and new password")
            return
        if not self.socket_client.connect(ip_addr='127.0.0.1', port=25566):
            messagebox.showerror("忘记密码", self.socket_client.getConnectStatus())
            return
        self.sendForgetRequest(username, new_password)
        self.forget_sub_window.lift()
        messagebox.showinfo("忘记密码", self.recvEventResponse()[0])

    def onRegisterClick(self, username, password, nickname):
        if not username or not password or not nickname:
            messagebox.showwarning("Input Error", "Please enter username and password and nickname")
            return
        if not self.socket_client.connect(ip_addr='127.0.0.1', port=25566):
            messagebox.showerror(self.socket_client.getConnectStatus())
            return
        # 连接成功
        self.sendRegisterRequest(nickname, username, password)
        self.register_sub_window.lift()
        messagebox.showinfo("注册", self.recvEventResponse()[0])

    def onLoginClick(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password.")
            return
        if not self.socket_client.connect(ip_addr='127.0.0.1', port=25566):
            messagebox.showerror("登录", self.socket_client.getConnectStatus())
            self.socket_client.disConnect()
            return
        self.sendLoginRequest(username, password)
        msg, code = self.recvEventResponse()
        messagebox.showinfo("登录", msg)
        if code == "success":
            self.createMainWindow(username)
            self.socket_client.disConnect()
            # 更换连接到聊天服务器
            if not self.socket_client.connect(ip_addr='127.0.0.1', port=25567):
                messagebox.showerror("聊天服务器", self.socket_client.getConnectStatus())
            self.loginInit(username)
        else:
            self.socket_client.disConnect()

    def windowCloseEvent(self, window):
        self.socket_client.disConnect()
        window.destroy()

    def createRegisterGui(self):
        if self.register_sub_window is None or not self.register_sub_window.winfo_exists():
            self.register_sub_window = tk.Toplevel(self.root)
            self.register_sub_window.title("Register")
            self.register_sub_window.geometry("400x200")

            # 用户名布局
            label_nickname = tk.Label(self.register_sub_window, text="用户名:")
            label_nickname.grid(row=0, column=0, padx=10, pady=10)
            entry_nickname = tk.Entry(self.register_sub_window, width=30)  # 增加宽度
            entry_nickname.grid(row=0, column=1, padx=10, pady=10)  # 增加外边距

            # 账号布局
            label_username = tk.Label(self.register_sub_window, text="账号:")
            label_username.grid(row=1, column=0, padx=10, pady=10)
            entry_username = tk.Entry(self.register_sub_window, width=30)
            entry_username.grid(row=1, column=1, padx=10, pady=10)

            # 密码布局
            label_password = tk.Label(self.register_sub_window, text="密码:")
            label_password.grid(row=2, column=0, padx=10, pady=10)
            entry_password = tk.Entry(self.register_sub_window, show="*", width=30)
            entry_password.grid(row=2, column=1, padx=10, pady=10)

            # 按钮事件
            button_register = tk.Button(self.register_sub_window, text="注册",
                                        command=lambda: self.onRegisterClick(
                                            username=entry_username.get(),
                                            password=entry_password.get(),
                                            nickname=entry_nickname.get()))

            button_register.grid(row=3, column=2, padx=10, pady=10)

            self.register_sub_window.protocol("WM_DELETE_WINDOW",
                                              lambda: self.windowCloseEvent(self.register_sub_window))
        else:
            self.register_sub_window.lift()

    def createForgetGui(self):
        if self.forget_sub_window is None or not self.forget_sub_window.winfo_exists():
            self.forget_sub_window = tk.Toplevel(self.root)
            self.forget_sub_window.title("忘记密码")
            self.forget_sub_window.geometry("400x200")

            # 账号布局
            label_username = tk.Label(self.forget_sub_window, text="账号:")
            label_username.grid(row=1, column=0, padx=10, pady=10)
            entry_username = tk.Entry(self.forget_sub_window, width=30)
            entry_username.grid(row=1, column=1, padx=10, pady=10)

            # 密码布局
            label_password = tk.Label(self.forget_sub_window, text="新密码:")
            label_password.grid(row=2, column=0, padx=10, pady=10)
            entry_password = tk.Entry(self.forget_sub_window, show="*", width=30)
            entry_password.grid(row=2, column=1, padx=10, pady=10)

            button_register = tk.Button(self.forget_sub_window, text="修改密码",
                                        command=lambda: self.onForgetClick(username=entry_username.get(),
                                                                           new_password=entry_password.get()))
            button_register.grid(row=3, column=2, padx=10, pady=10)

            self.forget_sub_window.protocol("WM_DELETE_WINDOW", lambda: self.windowCloseEvent(self.forget_sub_window))
        else:
            self.forget_sub_window.lift()

    def createLoginGui(self):
        self.root.title("Login")
        self.root.geometry("300x150")

        # 设置用户名标签和更大的输入框
        label_username = tk.Label(self.root, text="账号:")
        label_username.grid(row=0, column=0, padx=10, pady=10)  # 增加外边距
        self.entry_username = tk.Entry(self.root, width=30)  # 增加宽度
        self.entry_username.grid(row=0, column=1, padx=10, pady=10)  # 增加外边距

        # 设置密码标签和更大的输入框
        label_password = tk.Label(self.root, text="密码:")
        label_password.grid(row=1, column=0, padx=10, pady=10)  # 增加外边距
        self.entry_password = tk.Entry(self.root, show="*", width=30)  # 增加宽度
        self.entry_password.grid(row=1, column=1, padx=10, pady=10)  # 增加外边距

        # 创建一个框架来放置按钮
        button_frame = tk.Frame(self.root)
        button_frame.grid(row=2, column=0, columnspan=2, sticky='e', padx=10, pady=10)

        # 登录按钮
        button_login = tk.Button(button_frame, text="登录", command=self.onLoginClick)
        button_login.pack(side=tk.LEFT, padx=5, pady=5)  # 增加外边距

        # 注册按钮
        button_register = tk.Button(button_frame, text="注册", command=self.createRegisterGui)  # 修改了命令函数
        button_register.pack(side=tk.LEFT, padx=5, pady=5)  # 增加外边距

        # 忘记密码按钮
        button_forget = tk.Button(button_frame, text="忘记密码", command=self.createForgetGui)  # 修改了命令函数
        button_forget.pack(side=tk.LEFT, padx=5, pady=5)  # 增加外边距

        self.root.protocol("WM_DELETE_WINDOW", lambda: self.root.quit())

    def onSendClick(self):
        msg = self.message_entry.get()
        if not msg:
            return
        timestamp = datetime.now().strftime('%H:%M')
        data_dict = {"type": "msg", "msg": msg, "username": self.username, "timestamp": timestamp}
        self.message_entry.delete(0, tk.END)
        self.showSelfMessage(data_dict)
        self.sendMessage(data_dict)

    def onSentEvent(self, event=None):
        self.onSendClick()

    def run(self):
        if self.root is None:
            self.root = tk.Tk()
        self.createLoginGui()
        self.root.mainloop()

    def createMainWindow(self, username):
        self.closeAllWindows()
        self.root.title(f"chatting room - {username}")
        self.root.geometry("580x380")
        self.text_area = ScrolledText(self.root, state='disabled', wrap=tk.WORD)
        self.text_area.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        self.message_entry = tk.Entry(self.root, width=60)
        self.message_entry.bind("<Return>", self.onSentEvent)
        self.message_entry.grid(row=1, column=0, padx=5, pady=5)

        send_button = tk.Button(self.root, text="Send", command=self.onSendClick, width=10)
        send_button.grid(row=1, column=1, padx=5, pady=5)

        # 用户列表容器
        user_list_frame = tk.Frame(self.root)
        user_list_frame.grid(row=0, column=2, rowspan=2, padx=5, pady=5, sticky='ns')

        # 创建在线用户列表框及其滚动条
        online_user_frame = tk.Frame(user_list_frame)
        online_user_frame.pack(side="top", fill="both", expand=True)

        online_label = tk.Label(online_user_frame, text="Online Users")
        online_label.pack(side="top", anchor="nw")

        online_scrollbar = tk.Scrollbar(online_user_frame, orient="vertical")
        self.online_listbox = tk.Listbox(online_user_frame, yscrollcommand=online_scrollbar.set)
        online_scrollbar.config(command=self.online_listbox.yview)
        online_scrollbar.pack(side="right", fill="y")
        self.online_listbox.pack(side="left", fill="both", expand=True)

        # 创建离线用户列表框及其滚动条
        offline_user_frame = tk.Frame(user_list_frame)
        offline_user_frame.pack(side="top", fill="both", expand=True)

        offline_label = tk.Label(offline_user_frame, text="Offline Users")
        offline_label.pack(side="top", anchor="nw")

        offline_scrollbar = tk.Scrollbar(offline_user_frame, orient="vertical")
        self.offline_listbox = tk.Listbox(offline_user_frame, yscrollcommand=offline_scrollbar.set)
        offline_scrollbar.config(command=self.offline_listbox.yview)
        offline_scrollbar.pack(side="right", fill="y")
        self.offline_listbox.pack(side="left", fill="both", expand=True)

        # 设置行和列的权重，使得文本区域能够扩展
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.root.protocol("WM_DELETE_WINDOW", self.backToLoginGui)

    def backToLoginGui(self):
        if self.root is not None:
            for widget in self.root.winfo_children():
                widget.destroy()
            self.socket_client.disConnect()
            if self.receive_msg_loop is not None:
                self.receive_msg_loop.join()
            self.createLoginGui()

    def closeAllWindows(self):
        if self.root is not None:
            for widget in self.root.winfo_children():
                widget.destroy()
        # 关闭子窗口（如果存在）
        if self.register_sub_window and self.register_sub_window.winfo_exists():
            self.register_sub_window.destroy()
            self.register_sub_window = None
        if self.forget_sub_window and self.forget_sub_window.winfo_exists():
            self.forget_sub_window.destroy()
            self.forget_sub_window = None

    def receiveMsgLoop(self):
        if self.is_login and self.socket_client.is_connect:
            while True:
                data = self.socket_client.secure_socket.recv(1024).decode("utf-8")
                try:
                    data_dict = json.loads(data)
                    method = data_dict["type"]
                    if method == "msg":
                        self.showOthersMessage(data_dict)
                        self.storeMsg(data, False)
                    if method == "heartbeat":
                        self.heartbeatResponse()
                    if method == "online":
                        self.showOnline(data_dict)

                except (ConnectionAbortedError, ConnectionResetError):
                    # 将连接对象从监听列表去掉
                    print("客户端发生连接异常，与服务器端断开连接")
                    self.socket_client.disConnect()
                except Exception as e:
                    print(f"客户端发生了其它异常: {e}")
                    self.socket_client.disConnect()

    def showOthersMessage(self, data_dict):
        msg = data_dict["msg"]
        nickname = data_dict["nickname"]
        timestamp = data_dict["timestamp"]
        timestamp_message = f"{nickname} : {timestamp}\n"
        message_text = f"{msg}\n"
        self.text_area.tag_config('others_timestamp', font=self.timestamp_font, justify='left')
        self.text_area.tag_config('others_message', font=self.message_font, lmargin1='10p',
                                  lmargin2='10p', justify='left')
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, timestamp_message, 'others_timestamp')  # 插入时间戳
        self.text_area.insert(tk.END, message_text, 'others_message')  # 插入消息
        self.text_area.yview(tk.END)  # 滚动到底部
        self.text_area.config(state='disabled')

    def showSelfMessage(self, data):
        timestamp = data["timestamp"]
        msg = data["msg"]
        timestamp_message = f"{self.nickname} : {timestamp}\n"
        message_text = f"{msg}\n"
        self.text_area.tag_config('self_timestamp', font=self.timestamp_font, justify='right')
        self.text_area.tag_config('self_message', font=self.message_font, lmargin1='10p',
                                  lmargin2='10p', justify='right')
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, timestamp_message, 'self_timestamp')  # 插入时间戳
        self.text_area.insert(tk.END, message_text, 'self_message')  # 插入消息
        self.text_area.yview(tk.END)  # 滚动到底部
        self.text_area.config(state='disabled')

    def sendMessage(self, data: dict):
        if self.socket_client.is_connect:

            self.socket_client.secure_socket.sendall(json.dumps(data).encode('utf-8'))
            self.storeMsg(data, True)
        else:
            messagebox.showerror("消息发送", "与聊天服务器断开连接\n尝试重连ing")
            self.msg_queue.put(data)
            self.reConnect()

    def heartbeatResponse(self):
        if self.is_login and self.socket_client.is_connect:
            heartbeat_data = json.dumps({"type": "heartbeat", "data": "hello"})
            self.socket_client.secure_socket.sendall(heartbeat_data.encode('utf-8'))

    def reConnect(self):
        if self.socket_client.connect(ip_addr='127.0.0.1', port=25567):
            messagebox.showinfo("重新连接", "重新连接服务器成功")
            while not self.msg_queue.empty():
                msg = self.msg_queue.get()
                self.sendMessage(msg)

        else:
            messagebox.showinfo("重新连接", "重新连接服务器失败")
        return

    def storeMsg(self, new_msg: dict, is_me: bool):
        try:
            with open(self.msg_path, 'r') as file:
                chat_data = json.load(file)
        except FileNotFoundError:
            chat_data = {}
        chat_data[str(uuid.uuid1())] = {"is_me": is_me, "msg": new_msg}
        with open(self.msg_path, 'w') as f:
            json.dump(chat_data, f, indent=4)

    def loadLocalMsg(self, msg_path):
        try:
            with open(msg_path, 'r') as file:
                chat_data: dict = json.load(file)
        except FileNotFoundError:
            chat_data = {}

        for msg in chat_data.values():
            if msg["is_me"]:
                self.showSelfMessage(msg["msg"])
            else:
                self.showOthersMessage(msg["msg"])

    def showOnline(self, data_dict):
        nickname = data_dict["nickname"]
        if data_dict["is_online"]:
            if nickname in self.offline_listbox.get(0, tk.END):
                _remove_from_listbox(self.offline_listbox, nickname)
            self.online_listbox.insert(tk.END, nickname)
        else:
            if nickname in self.online_listbox.get(0, tk.END):
                _remove_from_listbox(self.online_listbox, nickname)
            self.offline_listbox.insert(tk.END, nickname)
        self.users.add(nickname)


if __name__ == '__main__':
    chat_client1 = clientGui()
    # chat_client2 = clientGui()
    # chat_client=[chat_client2,chat_client1]
    # for client in chat_client:
    #     threading.Thread(target=client.run).start()
    #     time.sleep(0.5)

    chat_client1.run()
