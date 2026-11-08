import winreg
import ctypes
import sys
import os
import traceback
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import socket
import threading
import queue
import datetime
#pyinstaller --onefile --noconsole 网络控制9.3.py
# ================= 配置区 =================
# 基础白名单（内置，稳定不变）
BASE_WHITELIST = [
    "*stem86.com",
    "*stem100.cn",
    "*onlinegit.com",
    "*vuejs.org",
    "*jsdelivr.net",
    "*ioicode.com",
    "*dj.com",
    "*djservice.org",
    "192.168.0.*",
]
LOG_PROXY_PORT = 65535  # 日志代理监听端口（与黑洞代理相同）
# 注册表存储路径（HKLM）
REG_PATH = r"SOFTWARE\HSControl"
REG_VALUE_NAME = "ExtraWhitelist"
# ==========================================

def is_admin():
    """检查是否拥有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_all_usernames():
    """枚举本地所有可登录用户名（排除系统内置账户和禁用账户）"""
    ps_cmd = r"""
    Get-LocalUser | Where-Object {
        $_.Enabled -eq $true -and
        $_.Name -notin @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount') -and
        $_.Description -notlike '*Built-in*' -and
        (Test-Path "C:\Users\$($_.Name)")
    } | Select-Object -ExpandProperty Name
    """
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True,
            text=True,
            creationflags=0x08000000,
            timeout=10
        )
        users = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return users
    except Exception:
        return []

def get_target_sid(username):
    """获取指定用户名的 SID"""
    ps_cmd = f"(New-Object System.Security.Principal.NTAccount('{username}')).Translate([System.Security.Principal.SecurityIdentifier]).Value"
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True,
            text=True,
            creationflags=0x08000000,
            timeout=10
        )
        sid = result.stdout.strip()
        if sid.startswith("S-1-5"):
            return sid
    except Exception:
        pass
    return None

def refresh_network():
    """广播系统刷新网络设置信号"""
    internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
    internet_set_option(0, 39, 0, 0)
    internet_set_option(0, 37, 0, 0)

def force_init_registry_tree(sid):
    """确保目标用户的 Internet Settings 注册表项存在"""
    target_path = rf"{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_USERS, target_path, 0, winreg.KEY_WRITE)
        winreg.CloseKey(key)
    except Exception:
        pass

def lock_student_tools(sid, enable):
    """下发策略，锁定/解锁学生的修改工具"""
    policies = [
        (rf"{sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
         "SettingsPageVisibility", winreg.REG_SZ, "hide:network-proxy"),
        (rf"{sid}\Software\Microsoft\Windows\CurrentVersion\Policies\System",
         "DisableRegistryTools", winreg.REG_DWORD, 1),
        (rf"{sid}\Software\Policies\Microsoft\Internet Explorer\Control Panel",
         "Proxy", winreg.REG_DWORD, 1)
    ]

    for path, name, reg_type, val in policies:
        try:
            key = winreg.CreateKeyEx(winreg.HKEY_USERS, path, 0, winreg.KEY_WRITE)
            if enable:
                winreg.SetValueEx(key, name, 0, reg_type, val)
            else:
                try:
                    winreg.DeleteValue(key, name)
                except Exception:
                    pass
            winreg.CloseKey(key)
        except Exception:
            pass

def get_proxy_state(sid):
    """读取目标账号的代理启用状态"""
    try:
        path = rf"{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKeyEx(winreg.HKEY_USERS, path, 0, winreg.KEY_READ)
        state, _ = winreg.QueryValueEx(key, "ProxyEnable")
        winreg.CloseKey(key)
        return state == 1
    except:
        return False

def load_extra_whitelist_from_reg():
    """从注册表读取额外白名单"""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, REG_VALUE_NAME)
        winreg.CloseKey(key)
        if value:
            domains = [d.strip() for d in value.split(',') if d.strip()]
            return domains
    except FileNotFoundError:
        # 键不存在时返回空列表
        pass
    except Exception:
        pass
    return []

def save_extra_whitelist_to_reg(domains):
    """将额外白名单保存到注册表"""
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
        winreg.SetValueEx(key, REG_VALUE_NAME, 0, winreg.REG_SZ, ', '.join(domains))
        winreg.CloseKey(key)
        return True
    except Exception as e:
        return False

def get_combined_whitelist():
    """合并基础白名单和额外白名单，去重并保持顺序"""
    extra = load_extra_whitelist_from_reg()
    combined = list(dict.fromkeys(BASE_WHITELIST + extra))
    return combined

def set_proxy_state(sid, enable):
    """跨账号注入代理配置（使用合并后的白名单）"""
    path = rf"{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_USERS, path, 0, winreg.KEY_WRITE)
        if enable:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{LOG_PROXY_PORT}")
            whitelist = get_combined_whitelist()
            override_str = ";".join(whitelist) + ";<local>"
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override_str)
        else:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)
        refresh_network()
    except Exception:
        pass
    finally:
        lock_student_tools(sid, enable)

class LogProxy:
    # ... 与之前相同，省略以节省篇幅 ...
    def __init__(self, port=LOG_PROXY_PORT, log_queue=None):
        self.port = port
        self.log_queue = log_queue
        self.server_socket = None
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return False
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        self.running = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', self.port))
            s.close()
        except:
            pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _run(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('127.0.0.1', self.port))
        self.server_socket.listen(50)
        self.server_socket.settimeout(0.5)
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(client_socket,), daemon=True).start()
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

    def _handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096)
            if not request:
                return
            try:
                request_text = request.decode('utf-8', errors='ignore')
            except:
                request_text = request.decode('latin-1', errors='ignore')
            domain = self._extract_domain(request_text)
            if domain and self.log_queue:
                timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                self.log_queue.put((timestamp, domain))
            response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            client_socket.sendall(response)
        except Exception:
            pass
        finally:
            client_socket.close()

    def _extract_domain(self, request_text):
        lines = request_text.split('\r\n')
        if not lines:
            return None
        first_line = lines[0]
        parts = first_line.split(' ')
        if len(parts) < 2:
            return None
        method = parts[0].upper()
        target = parts[1]
        if method == 'CONNECT':
            domain_port = target.split(':')
            return domain_port[0] if domain_port else None
        if target.startswith('http://') or target.startswith('https://'):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            return parsed.hostname
        for line in lines[1:]:
            if line.lower().startswith('host:'):
                host_value = line.split(':', 1)[1].strip()
                return host_value.split(':')[0]
        return None

class StudentGUIApp:
    def __init__(self, root):
        self.root = root
        self.sid = None
        self.current_user = None
        self.is_locked = False

        self.root.title("网络控制系统")
        self.root.geometry("400x320")
        self.root.resizable(False, False)

        # 居中显示
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - self.root.winfo_reqwidth()) // 2
        y = (self.root.winfo_screenheight() - self.root.winfo_reqheight()) // 2
        self.root.geometry(f"+{x}+{y}")

        # 创建 Notebook（选项卡）
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ================= 控制选项卡 =================
        self.control_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.control_frame, text="控制")

        top_frame = tk.Frame(self.control_frame)
        top_frame.pack(pady=10)

        tk.Label(top_frame, text="目标用户：", font=("微软雅黑", 10)).pack(side=tk.LEFT)
        self.user_combo = ttk.Combobox(top_frame, state="readonly", width=20, font=("微软雅黑", 10))
        self.user_combo.pack(side=tk.LEFT, padx=5)
        self.user_combo.bind("<<ComboboxSelected>>", self.on_user_selected)

        self.refresh_btn = tk.Button(top_frame, text="刷新", command=self.refresh_users, font=("微软雅黑", 9))
        self.refresh_btn.pack(side=tk.LEFT)

        self.status_label = tk.Label(self.control_frame, text="正在加载用户列表...", font=("微软雅黑", 14, "bold"))
        self.status_label.pack(pady=15)

        self.toggle_btn = tk.Button(self.control_frame, text="点击启动控制", font=("微软雅黑", 12, "bold"),
                                    width=15, height=2, command=self.toggle, state=tk.DISABLED)
        self.toggle_btn.pack(pady=5)

        # ================= 日志选项卡 =================
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="日志")

        log_btn_frame = tk.Frame(self.log_frame)
        log_btn_frame.pack(pady=5)

        self.log_start_btn = tk.Button(log_btn_frame, text="启动日志", command=self.start_log, font=("微软雅黑", 10))
        self.log_start_btn.pack(side=tk.LEFT, padx=5)

        self.log_stop_btn = tk.Button(log_btn_frame, text="停止日志", command=self.stop_log, font=("微软雅黑", 10), state=tk.DISABLED)
        self.log_stop_btn.pack(side=tk.LEFT, padx=5)

        self.log_clear_btn = tk.Button(log_btn_frame, text="清空列表", command=self.clear_log, font=("微软雅黑", 10))
        self.log_clear_btn.pack(side=tk.LEFT, padx=5)

        list_frame = tk.Frame(self.log_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=("Consolas", 9))
        self.log_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.log_listbox.yview)

        # 存储每个日志条目对应的域名（与 Listbox 索引同步）
        self.log_domains = []

        # 右键菜单
        self.log_context_menu = tk.Menu(self.root, tearoff=0)
        self.log_context_menu.add_command(label="复制域名", command=self.copy_selected_domain)
        self.log_listbox.bind("<Button-3>", self.show_log_context_menu)

        self.log_queue = queue.Queue()
        self.log_proxy = LogProxy(port=LOG_PROXY_PORT, log_queue=self.log_queue)
        self.is_log_running = False

        self.root.after(100, self.process_log_queue)

        # ================= 白名单选项卡 =================
        self.whitelist_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.whitelist_frame, text="白名单")

        # 从注册表加载额外白名单到内存
        self.extra_whitelist = load_extra_whitelist_from_reg()
        # 用于显示合并后的白名单及标记
        self.display_whitelist = []
        self.display_is_base = []

        # 输入框和添加按钮
        add_frame = tk.Frame(self.whitelist_frame)
        add_frame.pack(pady=5)

        tk.Label(add_frame, text="新域名：", font=("微软雅黑", 10)).pack(side=tk.LEFT)
        self.domain_entry = tk.Entry(add_frame, width=25, font=("微软雅黑", 10))
        self.domain_entry.pack(side=tk.LEFT, padx=5)
        self.add_btn = tk.Button(add_frame, text="添加", command=self.add_domain, font=("微软雅黑", 10))
        self.add_btn.pack(side=tk.LEFT)

        # 操作按钮
        btn_frame = tk.Frame(self.whitelist_frame)
        btn_frame.pack(pady=5)

        self.delete_btn = tk.Button(btn_frame, text="删除选中", command=self.delete_selected_domain, font=("微软雅黑", 10))
        self.delete_btn.pack(side=tk.LEFT, padx=5)

        # 显示白名单的列表框
        wl_list_frame = tk.Frame(self.whitelist_frame)
        wl_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        wl_scrollbar = tk.Scrollbar(wl_list_frame)
        wl_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.whitelist_listbox = tk.Listbox(wl_list_frame, yscrollcommand=wl_scrollbar.set, font=("Consolas", 10))
        self.whitelist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        wl_scrollbar.config(command=self.whitelist_listbox.yview)

        # 右键删除菜单
        self.whitelist_context_menu = tk.Menu(self.root, tearoff=0)
        self.whitelist_context_menu.add_command(label="删除", command=self.delete_selected_domain)
        self.whitelist_listbox.bind("<Button-3>", self.show_whitelist_context_menu)

        # 刷新显示白名单
        self.refresh_whitelist_display()

        # 初始加载用户列表（延迟）
        self.root.after(100, self.refresh_users)

    def refresh_users(self):
        users = get_all_usernames()
        if not users:
            messagebox.showerror("错误", "无法枚举本地用户，请确认以管理员身份运行且 PowerShell 可用。")
            self.status_label.config(text="加载用户列表失败", fg="red")
            return

        self.user_combo['values'] = users
        self.user_combo.current(0)
        self.on_user_selected(None)

    def on_user_selected(self, event):
        username = self.user_combo.get()
        if not username:
            self.sid = None
            self.current_user = None
            self.status_label.config(text="请选择目标用户", fg="black")
            self.toggle_btn.config(state=tk.DISABLED)
            return

        sid = get_target_sid(username)
        if not sid:
            messagebox.showerror("错误", f"无法获取用户 '{username}' 的 SID，请确认该用户存在。")
            self.sid = None
            self.current_user = None
            self.toggle_btn.config(state=tk.DISABLED)
            return

        self.sid = sid
        self.current_user = username
        force_init_registry_tree(self.sid)
        self.is_locked = get_proxy_state(self.sid)
        self.toggle_btn.config(state=tk.NORMAL)
        self.update_ui()

    def update_ui(self):
        if self.is_locked:
            self.status_label.config(text=f"用户 {self.current_user}：控制中 + 工具禁用", fg="#e74c3c")
            self.toggle_btn.config(text="点击解除控制", bg="#2ecc71", fg="white",
                                   activebackground="#27ae60", activeforeground="white")
        else:
            self.status_label.config(text=f"用户 {self.current_user}：已解除 (自由上网)", fg="#2ecc71")
            self.toggle_btn.config(text="点击启动控制", bg="#e74c3c", fg="white",
                                   activebackground="#c0392b", activeforeground="white")

    def toggle(self):
        if not self.sid:
            messagebox.showwarning("提示", "请先选择目标用户。")
            return
        self.is_locked = not self.is_locked
        set_proxy_state(self.sid, self.is_locked)
        self.update_ui()

    # ================= 日志功能 =================
    def start_log(self):
        if self.is_log_running:
            messagebox.showinfo("提示", "日志已在运行中。")
            return
        if self.log_proxy.start():
            self.is_log_running = True
            self.log_start_btn.config(state=tk.DISABLED)
            self.log_stop_btn.config(state=tk.NORMAL)
            self.log_listbox.insert(tk.END, "=== 日志已启动 ===")
            self.log_domains.append(None)
            self.log_listbox.see(tk.END)
        else:
            messagebox.showerror("错误", "日志代理启动失败。")

    def stop_log(self):
        if not self.is_log_running:
            messagebox.showinfo("提示", "日志未在运行。")
            return
        self.log_proxy.stop()
        self.is_log_running = False
        self.log_start_btn.config(state=tk.NORMAL)
        self.log_stop_btn.config(state=tk.DISABLED)
        self.log_listbox.insert(tk.END, "=== 日志已停止 ===")
        self.log_domains.append(None)
        self.log_listbox.see(tk.END)

    def clear_log(self):
        self.log_listbox.delete(0, tk.END)
        self.log_domains.clear()

    def process_log_queue(self):
        try:
            while True:
                timestamp, domain = self.log_queue.get_nowait()
                self.log_listbox.insert(tk.END, f"{timestamp}  {domain}")
                self.log_domains.append(domain)
                self.log_listbox.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.process_log_queue)

    def show_log_context_menu(self, event):
        try:
            index = self.log_listbox.nearest(event.y)
            if index >= 0:
                self.log_listbox.selection_clear(0, tk.END)
                self.log_listbox.selection_set(index)
                self.log_listbox.activate(index)
                self.log_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.log_context_menu.grab_release()

    def copy_selected_domain(self):
        selection = self.log_listbox.curselection()
        if not selection:
            messagebox.showinfo("提示", "请先选中一条日志。")
            return
        index = selection[0]
        domain = self.log_domains[index]
        if domain:
            self.root.clipboard_clear()
            self.root.clipboard_append(domain)
        else:
            messagebox.showinfo("提示", "该条目没有可复制的域名。")

    # ================= 白名单功能 =================
    def refresh_whitelist_display(self):
        """刷新白名单显示：基础白名单（灰色，不可删除）+ 额外白名单（黑色，可删除）"""
        self.whitelist_listbox.delete(0, tk.END)
        self.display_whitelist = []
        self.display_is_base = []
        
        # 添加基础白名单
        for domain in BASE_WHITELIST:
            self.display_whitelist.append(domain)
            self.display_is_base.append(True)
        
        # 添加额外白名单
        for domain in self.extra_whitelist:
            self.display_whitelist.append(domain)
            self.display_is_base.append(False)
        
        # 插入列表框并设置颜色
        for idx, domain in enumerate(self.display_whitelist):
            self.whitelist_listbox.insert(tk.END, domain)
            if self.display_is_base[idx]:
                self.whitelist_listbox.itemconfig(idx, {'fg': 'gray'})  # 基础条目灰色

    def add_domain(self):
        """添加新域名到额外白名单（自动保存到注册表）"""
        domain = self.domain_entry.get().strip()
        if not domain:
            return
        # 简单验证：包含点号，不含非法字符
        if '.' not in domain or any(c in domain for c in ['/', '\\', ':', '?']):
            messagebox.showerror("错误", "域名格式不正确，请只输入域名（例如 *.example.com）")
            return
        if domain in self.extra_whitelist:
            messagebox.showinfo("提示", "该域名已存在。")
            return

        # 构建新列表副本
        new_list = self.extra_whitelist + [domain]
        # 尝试保存到注册表
        if save_extra_whitelist_to_reg(new_list):
            self.extra_whitelist = new_list
            self.domain_entry.delete(0, tk.END)
            self.refresh_whitelist_display()
        else:
            messagebox.showerror("错误", "保存白名单失败，请检查管理员权限。")

    def delete_selected_domain(self):
        """删除选中的额外白名单条目（自动保存到注册表）"""
        selection = self.whitelist_listbox.curselection()
        if not selection:
            messagebox.showinfo("提示", "请先选中要删除的域名。")
            return

        index = selection[0]
        # 检查是否为基础白名单
        if self.display_is_base[index]:
            messagebox.showwarning("警告", "基础白名单不可删除！")
            return

        # 计算在 extra_whitelist 中的实际索引（显示列表中基础白名单在前）
        extra_index = index - len(BASE_WHITELIST)
        if not (0 <= extra_index < len(self.extra_whitelist)):
            messagebox.showerror("错误", "索引错误，无法删除。")
            return

        # 构建删除后的新列表
        new_list = self.extra_whitelist.copy()
        del new_list[extra_index]
        # 尝试保存到注册表
        if save_extra_whitelist_to_reg(new_list):
            self.extra_whitelist = new_list
            self.refresh_whitelist_display()
        else:
            messagebox.showerror("错误", "保存白名单失败，请检查管理员权限。")
        def save_extra_whitelist(self):
            """将额外白名单保存到注册表"""
            if save_extra_whitelist_to_reg(self.extra_whitelist):
                messagebox.showinfo("成功", "白名单已保存到注册表。")
            else:
                messagebox.showerror("错误", "保存白名单失败，请检查管理员权限。")

    def show_whitelist_context_menu(self, event):
        """显示白名单右键菜单"""
        try:
            index = self.whitelist_listbox.nearest(event.y)
            if index >= 0:
                self.whitelist_listbox.selection_clear(0, tk.END)
                self.whitelist_listbox.selection_set(index)
                self.whitelist_listbox.activate(index)
                self.whitelist_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.whitelist_context_menu.grab_release()
            
def add_defender_exclusion():
    """自动将当前程序添加到 Windows Defender 排除列表（静默执行，失败时提示）"""
    try:
        # 获取可执行文件真实路径（兼容打包后）
        if getattr(sys, 'frozen', False):
            exe_path = os.path.abspath(sys.executable)
        else:
            exe_path = os.path.abspath(sys.argv[0])

        # 调用 PowerShell 添加排除项
        cmd = f'Add-MpPreference -ExclusionPath "{exe_path}"'
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True,
            text=True,
            creationflags=0x08000000,  # 隐藏 PowerShell 窗口
            timeout=15
        )

        if result.returncode != 0:
            # 失败时仅弹窗提示，不影响程序继续运行
            messagebox.showwarning("提示", f"自动添加 Defender 排除项失败：\n{result.stderr.strip()}")
    except Exception:
        # 完全静默，避免因添加排除项失败影响主程序
        pass
    
if __name__ == "__main__":
    try:
        if not is_admin():
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{script}" {params}', None, 1
            )
            sys.exit()

        root = tk.Tk()
        app = StudentGUIApp(root)
        root.mainloop()

    except Exception as e:
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("程序异常", f"发生错误：{e}\n\n{traceback.format_exc()}")
        except:
            pass
        sys.exit(1)
