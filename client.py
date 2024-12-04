import json
import os
import queue
import socket
import ssl
import threading
import tkinter as tk
import uuid
from datetime import datetime
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from typing import Callable, Dict


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
    class PrivateGui:
        def __init__(self, send_user, recv_name: str, gui: tk.Toplevel):
            self.sendMessage: Callable[[Dict], None] = None
            self.text_area = None
            self.send_button = None
            self.message_entry = None
            self.send_user = send_user
            self.recv_name = recv_name
            self.gui = gui
            self.showSelfMessage: Callable[[Dict, tk.scrolledtext], None] = None
            self.showGui()

        def setSendMsgFunc(self, func):
            if self.sendMessage is None:
                self.sendMessage = func

        def setShowMsgFunc(self, func):
            if self.showSelfMessage is None:
                self.showSelfMessage = func

        def showGui(self):
            self.text_area = ScrolledText(self.gui, state='disabled', wrap=tk.WORD)
            self.text_area.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

            self.message_entry = tk.Entry(self.gui, width=60)
            self.message_entry.bind("<Return>", self.onSentPrivateEvent)
            self.message_entry.grid(row=1, column=0, padx=5, pady=5)

            self.send_button = tk.Button(self.gui, text="Send",
                                         command=self.onPrivateSendClick, width=10)
            self.send_button.grid(row=1, column=1, padx=5, pady=5)

        def onPrivateSendClick(self):
            msg = self.message_entry.get()
            if not msg:
                return
            timestamp = datetime.now().strftime('%H:%M')
            data_dict = {"type": "msg_private", "msg": msg, "send_username": self.send_user, "msg_type": "private",
                         "recv_username": self.recv_name, "timestamp": timestamp}
            self.message_entry.delete(0, tk.END)
            if self.showSelfMessage is not None:
                self.showSelfMessage(data_dict, self.text_area)
            if self.sendMessage is not None:
                self.sendMessage(data_dict)

        def onSentPrivateEvent(self, event=None):
            self.onPrivateSendClick()

    def __init__(self):
        self.recv_user = None
        self.right_click_menu = None
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
        self.private_windows: Dict[str, clientGui.PrivateGui] = {}

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
        self.entry_password.bind("<Return>", self.onLoginEvent)

    def onSendClick(self):
        msg = self.message_entry.get()
        if not msg:
            return
        timestamp = datetime.now().strftime('%H:%M')
        data_dict = {"type": "msg", "msg_type": "public", "msg": msg, "username": self.username, "timestamp": timestamp}
        self.message_entry.delete(0, tk.END)
        self.showSelfMessage(data_dict, self.text_area)
        self.sendMessage(data_dict)

    def onSentEvent(self, event=None):
        self.onSendClick()

    def onLoginEvent(self, event=None):
        self.onLoginClick()

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

        self.create_right_click_menu()

    def closePrivateWinEvent(self, private_window: tk.Toplevel, recv_user):
        private_window.destroy()
        del self.private_windows[recv_user]

    def createPrivateWindow(self, send_user):
        private_window = tk.Toplevel(self.root)
        private_window.title(send_user + "->" + self.recv_user)
        private_window.geometry("580x380")
        private_window.protocol("WM_DELETE_WINDOW", lambda: self.closePrivateWinEvent(private_window, self.recv_user))

        private_gui = self.PrivateGui(send_user, self.recv_user, private_window)
        private_gui.setShowMsgFunc(self.showSelfMessage)
        private_gui.setSendMsgFunc(self.sendMessage)
        self.private_windows[self.recv_user] = private_gui

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
                try:
                    data = self.socket_client.secure_socket.recv(1024).decode("utf-8")
                    try:
                        data_dict = json.loads(data)
                        method = data_dict["type"]
                        if method == "msg":
                            if data_dict["msg_type"] == "public":
                                self.showOthersMessage(data_dict, self.text_area)
                            else:
                                self.showOthersMessage(data_dict, self.findPrivateWindow(data_dict["username"]))
                            self.storeMsg(new_msg=data_dict, is_me=False, msg_type=data_dict["msg_type"])
                        if method == "heartbeat":
                            self.heartbeatResponse()
                        if method == "online":
                            self.showOnline(data_dict)
                    except json.JSONDecodeError:
                        continue

                except socket.error as e:
                    if e.errno == 10053:
                        print("连接中断")
                        self.socket_client.disConnect()
                    return
                except (ConnectionAbortedError, ConnectionResetError):
                    # 将连接对象从监听列表去掉
                    print("客户端发生连接异常，与服务器端断开连接")
                    self.socket_client.disConnect()
                    return
                except Exception as e:
                    print(f"客户端发生了其它异常: {e}")
                    self.socket_client.disConnect()
                    return

    def showOthersMessage(self, data_dict, text_area: tk.scrolledtext):
        msg = data_dict["msg"]
        nickname = data_dict["nickname"]
        timestamp = data_dict["timestamp"]
        timestamp_message = f"{nickname} : {timestamp}\n"
        message_text = f"{msg}\n"
        text_area.tag_config('others_timestamp', font=self.timestamp_font, justify='left')
        text_area.tag_config('others_message', font=self.message_font, lmargin1='10p',
                             lmargin2='10p', justify='left')
        text_area.config(state='normal')
        text_area.insert(tk.END, timestamp_message, 'others_timestamp')  # 插入时间戳
        text_area.insert(tk.END, message_text, 'others_message')  # 插入消息
        text_area.yview(tk.END)  # 滚动到底部
        text_area.config(state='disabled')

    def showSelfMessage(self, data, text_area: tk.scrolledtext):
        timestamp = data["timestamp"]
        msg = data["msg"]
        timestamp_message = f"{self.nickname} : {timestamp}\n"
        message_text = f"{msg}\n"
        text_area.tag_config('self_timestamp', font=self.timestamp_font, justify='right')
        text_area.tag_config('self_message', font=self.message_font, lmargin1='10p',
                             lmargin2='10p', justify='right')
        text_area.config(state='normal')
        text_area.insert(tk.END, timestamp_message, 'self_timestamp')  # 插入时间戳
        text_area.insert(tk.END, message_text, 'self_message')  # 插入消息
        text_area.yview(tk.END)  # 滚动到底部
        text_area.config(state='disabled')

    def sendMessage(self, data: dict):
        if self.socket_client.is_connect:
            self.socket_client.secure_socket.sendall(json.dumps(data).encode('utf-8'))
            self.storeMsg(new_msg=data, is_me=True, msg_type=data["msg_type"])
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

    def storeMsg(self, new_msg: dict, is_me: bool, msg_type: str):
        try:
            with open(self.msg_path, 'r') as file:
                chat_data = json.load(file)
        except FileNotFoundError:
            chat_data = {}
        chat_data[str(uuid.uuid1())] = {"is_me": is_me, "msg_type": msg_type, "msg": new_msg}
        with open(self.msg_path, 'w') as f:
            json.dump(chat_data, f, indent=4)

    def loadLocalMsg(self, msg_path):
        try:
            with open(msg_path, 'r') as file:
                chat_data: dict = json.load(file)
        except FileNotFoundError:
            chat_data = {}

        for msg in chat_data.values():
            if msg["msg_type"] == "public":
                if msg["is_me"]:
                    self.showSelfMessage(msg["msg"], self.text_area)
                else:
                    self.showOthersMessage(msg["msg"], self.text_area)

    def showOnline(self, data_dict):
        nickname = data_dict["nickname"]
        online_lists = self.online_listbox.get(0, tk.END)
        offline_lists = self.offline_listbox.get(0, tk.END)
        if data_dict["is_online"]:
            if nickname in offline_lists:
                _remove_from_listbox(self.offline_listbox, nickname)
            if nickname not in online_lists:
                self.online_listbox.insert(tk.END, nickname)
        else:
            if nickname in online_lists:
                _remove_from_listbox(self.online_listbox, nickname)
            if nickname not in offline_lists:
                self.offline_listbox.insert(tk.END, nickname)

    def create_right_click_menu(self):
        # 创建右键菜单
        if self.right_click_menu is None:
            self.right_click_menu = tk.Menu(self.root, tearoff=0)
            self.right_click_menu.add_command(
                label="私聊", command=lambda: self.createPrivateWindow(self.username))

        self.online_listbox.bind("<Button-3>", self.show_right_click_menu)  # Right mouse button on Windows/Linux
        self.offline_listbox.bind("<Button-3>", self.show_right_click_menu)

    def show_right_click_menu(self, event):
        widget = event.widget
        selected_indices = widget.curselection()  # 获取当前选中的项

        if selected_indices:  # 如果有项被选中
            index = selected_indices[0]  # 假设只选择了一项
            self.recv_user = widget.get(index)
            try:
                self.right_click_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.right_click_menu.grab_release()

    def findPrivateWindow(self, username) -> tk.scrolledtext:
        return self.private_windows[username].text_area


if __name__ == '__main__':
    chat_client1 = clientGui()
    # chat_client2 = clientGui()
    # chat_client=[chat_client2,chat_client1]
    # for client in chat_client:
    #     threading.Thread(target=client.run).start()
    #     time.sleep(0.5)

    chat_client1.run()
