import sys
import os
import requests
import json
from typing import Optional
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QMessageBox, QDialog,
    QFormLayout, QLineEdit, QComboBox, QLabel, QGroupBox, QTextEdit
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QSize, Qt
from key_store import KeyStore
from key_object import KeyStatus, KeyType, KeyUsage, KeyObject
import crypto_utils as cu
import copy
from kms_service import start_kms_service, stop_kms_service


def resource_path(relative_path: str) -> str:
    """获取资源文件路径，兼容 PyInstaller 打包"""
    base_path = getattr(sys, "_MEIPASS", None)
    if base_path is None:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


class CreateKeyDialog(QDialog):
    """创建新密钥对话框（owner 自动使用当前登录用户）"""
    def __init__(self, current_user: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("创建新密钥")
        self.setWindowIcon(QIcon(resource_path("./icon/circle-plus.png")))
        layout = QFormLayout()

        # owner is fixed to current_user (read-only)
        self.owner_label = QLabel(current_user)
        layout.addRow("拥有者:", self.owner_label)

        self.type_combo = QComboBox()
        self.type_combo.addItems([kt.value for kt in KeyType])
        layout.addRow("类型:", self.type_combo)

        self.usage_combo = QComboBox()
        self.usage_combo.addItems([ku.value for ku in KeyUsage])
        layout.addRow("用途:", self.usage_combo)

        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("确定")
        cancel_btn = QPushButton("取消")
        ok_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addRow(btn_layout)
        self.setLayout(layout)

    def get_data(self):
        return (
            self.owner_label.text(),
            self.type_combo.currentText(),
            self.usage_combo.currentText(),
        )


class LoginDialog(QDialog):
    """登录对话框"""
    def __init__(self, store: KeyStore, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("登录以开启密钥管理系统")
        self.setWindowIcon(QIcon(resource_path("./icon/user.png")))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        layout = QFormLayout()
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addRow("用户名:", self.username)
        layout.addRow("密码:", self.password)

        btn_layout = QHBoxLayout()
        login_btn = QPushButton("登录")
        reg_btn = QPushButton("注册新账号")
        cancel_btn = QPushButton("取消")
        login_btn.clicked.connect(self.try_login)
        reg_btn.clicked.connect(self.open_register)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(login_btn)
        btn_layout.addWidget(reg_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addRow(btn_layout)
        self.setLayout(layout)

    def try_login(self):
        user = self.username.text().strip()
        pwd = self.password.text()
        if not user or not pwd:
            QMessageBox.warning(self, "错误", "请输入用户名和密码")
            return
        try:
            ok = self.store.login_user(user, pwd)
            if ok:
                # <<< 登录成功后启动 KMS 服务并更新状态栏
                try:
                    start_kms_service(self.store)
                    parent = self.parent()
                    if parent and hasattr(parent, "status_label"):
                        parent.status_label.setText("KMS服务已启动")
                except Exception as e:
                    QMessageBox.warning(self, "服务错误", f"无法启动本地KMS服务: {e}")
                self.accept()
                return
        except Exception as e:
            QMessageBox.critical(self, "登录失败", f"{e}")
            return

    def open_register(self):
        dlg = RegisterDialog(self.store, self)
        if dlg.exec_() == QDialog.Accepted:
            self.accept()

class ApiClientDialog(QDialog):
    def __init__(self, store, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("API 客户端")
        self.setWindowIcon(QIcon(resource_path("./icon/monitor.png")))
        self.resize(700, 500)
        layout = QVBoxLayout()

        # API 选择
        self.api_combo = QComboBox()
        self.api_combo.addItems([
            "列出密钥",
            "获取公钥",
            "获取原始密钥",
            "包装密钥",
        ])
        layout.addWidget(QLabel("选择 API:"))
        layout.addWidget(self.api_combo)

        # 调用按钮
        self.call_btn = QPushButton("调用 API")
        layout.addWidget(self.call_btn)

        # 输出框
        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        layout.addWidget(QLabel("返回结果:"))
        layout.addWidget(self.output_edit)

        self.setLayout(layout)

        self.call_btn.clicked.connect(self.call_api)

    def call_api(self):
        if not self.store.current_user:
            QMessageBox.warning(self, "错误", "请先登录")
            return

        base_url = "http://127.0.0.1:5050"

        # --- 获取 token ---
        try:
            resp = requests.post(
                f"{base_url}/auth/login",
                json={"username": self.store.current_user}
            )
            if resp.status_code != 200:
                self.output_edit.setText(f"获取 token 失败: {resp.status_code} {resp.text}")
                return
            token = resp.json().get("token")
            if not token:
                self.output_edit.setText("token 获取失败，返回数据不包含 token")
                return
        except Exception as e:
            self.output_edit.setText(f"获取 token 出错: {e}")
            return

        headers = {"Authorization": f"Bearer {token}"}

        # --- 获取密钥 ---
        try:
            keys = self.store.list_keys()
            if not keys:
                self.output_edit.setText("当前用户没有密钥，请先创建密钥")
                return
            key_id = keys[0].key_id
        except Exception as e:
            self.output_edit.setText(f"获取密钥列表失败: {e}")
            return

        api = self.api_combo.currentText()

        try:
            if api == "列出密钥":
                r = requests.get(f"{base_url}/keys", headers=headers)

            elif api == "获取公钥":
                r = requests.get(f"{base_url}/keys/{key_id}/public", headers=headers)

            elif api == "获取原始密钥":
                try:
                    r = requests.get(f"{base_url}/keys/{key_id}/raw", headers=headers)
                except Exception as e:
                    self.output_edit.setText(f"获取原始密钥失败: {e}")
                    return

            elif api == "包装密钥":
                try:
                    pub_pem = self.store.export_public_key(key_id)
                    if not pub_pem:
                        self.output_edit.setText("公钥未生成，无法包装密钥")
                        return
                    r = requests.post(
                        f"{base_url}/keys/{key_id}/wrap",
                        headers=headers,
                        json={"recipient_pub_pem": pub_pem.decode()}
                    )
                except Exception as e:
                    self.output_edit.setText(f"包装密钥失败: {e}")
                    return

            else:
                self.output_edit.setText("未知 API")
                return

            # --- 输出结果 ---
            try:
                self.output_edit.setText(json.dumps(r.json(), indent=2, ensure_ascii=False))
            except Exception:
                self.output_edit.setText(r.text)

        except requests.exceptions.RequestException as e:
            self.output_edit.setText(f"请求失败: {e}")
        except Exception as e:
            self.output_edit.setText(f"调用失败: {e}")


class RegisterDialog(QDialog):
    """注册对话框"""
    def __init__(self, store: KeyStore, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("注册新用户")
        self.setWindowIcon(QIcon(resource_path("./icon/user.png")))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        layout = QFormLayout()
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password2 = QLineEdit()
        self.password2.setEchoMode(QLineEdit.Password)
        layout.addRow("用户名:", self.username)
        layout.addRow("密码:", self.password)
        layout.addRow("确认密码:", self.password2)

        btn_layout = QHBoxLayout()
        reg_btn = QPushButton("注册并生成主密钥")
        cancel_btn = QPushButton("取消")
        reg_btn.clicked.connect(self.try_register)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(reg_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addRow(btn_layout)
        self.setLayout(layout)

    def try_register(self):
        user = self.username.text().strip()
        p1 = self.password.text()
        p2 = self.password2.text()
        if not user or not p1:
            QMessageBox.warning(self, "错误", "用户名/密码不能为空")
            return
        if p1 != p2:
            QMessageBox.warning(self, "错误", "两次密码不一致")
            return
        ok, msg = cu.validate_password(p1, user)
        if not ok:
            QMessageBox.warning(self, "密码不合规", msg)
            return

        try:
            if self.store.user_count() == 0:
                self.store.register_first_user(user, p1)
                QMessageBox.information(self, "完成", "注册成功，主密钥已生成并受账号保护。")
            else:
                self.store.register_user(user, p1)
                QMessageBox.information(self, "完成", "注册成功，主密钥已生成并受账号保护。")

            # <<< 在这里加：注册成功后启动 KMS 服务并更新状态栏
            try:
                start_kms_service(self.store)
                parent = self.parent()
                if parent and hasattr(parent, "status_label"):
                    parent.status_label.setText("KMS服务已启动")
            except Exception as e:
                QMessageBox.warning(self, "服务错误", f"无法启动本地KMS服务: {e}")

            self.accept()
            return

        except Exception as e:
            QMessageBox.critical(self, "注册失败", f"{e}")
            return


class KeyManagementGUI(QWidget):
    def __init__(self, store: KeyStore):
        super().__init__()
        self.store = store
        self.setWindowTitle("密钥管理系统")
        self.setWindowIcon(QIcon(resource_path("./icon/icon.png")))
        self.resize(1180, 620)
        # 去掉标题栏右上角默认问号
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.init_ui()

    def open_api_client(self):
        if not hasattr(self, "_api_client_dlg"):
            self._api_client_dlg = ApiClientDialog(self.store, self)
        self._api_client_dlg.show()
        self._api_client_dlg.raise_()
        self._api_client_dlg.activateWindow()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # --- 顶部信息栏 ---
        top_bar = QHBoxLayout()
        self.user_label = QLabel(f"当前用户: {self.store.current_user or '未登录'}")
        top_bar.addWidget(self.user_label)
        top_bar.addStretch(1)

        icon_size = QSize(20, 20)
        self.help_btn = QPushButton(QIcon(resource_path("./icon/help.png")), "获取帮助")
        self.help_btn.setMinimumWidth(100)
        self.help_btn.setIconSize(icon_size)
        self.help_btn.clicked.connect(self.show_help)
        top_bar.addWidget(self.help_btn)

        self.logout_btn = QPushButton(QIcon(resource_path("./icon/promotion.png")), "退出登录")
        self.logout_btn.setMinimumWidth(100)
        self.logout_btn.setIconSize(icon_size)
        self.logout_btn.clicked.connect(self.logout)
        top_bar.addWidget(self.logout_btn)

        main_layout.addLayout(top_bar)

        # --- 中间分栏：左表格 + 右按钮区 ---
        middle_layout = QHBoxLayout()

        # 左侧表格
        table_group = QGroupBox("密钥列表")
        table_layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Owner", "Type", "Usage", "Status"])
        self.table.cellClicked.connect(self.update_button_states)
        table_layout.addWidget(self.table)
        table_group.setLayout(table_layout)
        middle_layout.addWidget(table_group, stretch=3)  # 左侧占更多空间

        # 右侧操作区
        right_group = QGroupBox("操作")
        right_layout = QVBoxLayout()

        # API 客户端按钮
        self.api_client_btn = QPushButton(QIcon(resource_path("./icon/monitor.png")), "API客户端")
        self.api_client_btn.setMinimumWidth(120)
        self.api_client_btn.setIconSize(icon_size)
        right_layout.addWidget(self.api_client_btn)

        # 生命周期操作按钮
        self.create_btn = QPushButton(QIcon(resource_path("./icon/circle-plus.png")), "创建密钥")
        self.activate_btn = QPushButton(QIcon(resource_path("./icon/circle-check.png")), "密钥激活")
        self.suspend_btn = QPushButton(QIcon(resource_path("./icon/circle-close.png")), "密钥停用")
        self.deactivate_btn = QPushButton(QIcon(resource_path("./icon/upload.png")), "密钥挂起")
        self.revoke_btn = QPushButton(QIcon(resource_path("./icon/back.png")), "密钥撤销")
        self.compromise_btn = QPushButton(QIcon(resource_path("./icon/close.png")), "标记泄露")
        self.rotate_btn = QPushButton(QIcon(resource_path("./icon/switch.png")), "密钥轮换")
        self.destroy_btn = QPushButton(QIcon(resource_path("./icon/delete.png")), "密钥销毁")
        self.refresh_btn = QPushButton(QIcon(resource_path("./icon/refresh.png")), "密钥刷新")
        self.view_log_btn = QPushButton(QIcon(resource_path("./icon/document.png")), "查看日志")
        self.view_details_btn = QPushButton(QIcon(resource_path("./icon/search.png")), "查看详情")

        buttons = [
            self.create_btn, self.activate_btn, self.suspend_btn, self.deactivate_btn,
            self.revoke_btn, self.compromise_btn, self.rotate_btn, self.destroy_btn,
            self.refresh_btn, self.view_log_btn, self.view_details_btn
        ]

        for btn in buttons:
            btn.setMinimumWidth(120)
            btn.setIconSize(icon_size)
            right_layout.addWidget(btn)

        # 状态栏放在最底部
        self.status_label = QLabel("准备就绪")
        right_layout.addStretch(1)  # 占位，把状态栏推到最底部
        right_layout.addWidget(self.status_label)

        right_group.setLayout(right_layout)
        middle_layout.addWidget(right_group, stretch=1)  # 右侧窄一些

        main_layout.addLayout(middle_layout)
        self.setLayout(main_layout)

        # --- 信号绑定 ---
        self.api_client_btn.clicked.connect(self.open_api_client)
        self.create_btn.clicked.connect(self.create_key)
        self.activate_btn.clicked.connect(lambda: self.change_status(KeyStatus.ACTIVE))
        self.suspend_btn.clicked.connect(lambda: self.change_status(KeyStatus.SUSPENDED))
        self.deactivate_btn.clicked.connect(lambda: self.change_status(KeyStatus.DEACTIVATED))
        self.revoke_btn.clicked.connect(lambda: self.change_status(KeyStatus.REVOKED))
        self.compromise_btn.clicked.connect(lambda: self.change_status(KeyStatus.COMPROMISED))
        self.rotate_btn.clicked.connect(self.rotate_selected_key)
        self.destroy_btn.clicked.connect(lambda: self.change_status(KeyStatus.DESTROYED))
        self.refresh_btn.clicked.connect(self.load_keys)
        self.view_log_btn.clicked.connect(self.view_logs)
        self.view_details_btn.clicked.connect(self.view_details)

        # --- 加载密钥数据 ---
        self.load_keys()


    def logout(self):
        """退出当前用户，返回登录界面"""
        from PyQt5.QtWidgets import QApplication

        self.store.current_user = None

        # <<< 在这里加：退出登录时停止 KMS 服务
        try:
            stop_kms_service()
            self.status_label.setText("KMS服务已停止")
        except Exception:
            pass

        QMessageBox.information(self, "提示", "您已退出登录")

        self.close()
        dlg = LoginDialog(self.store)
        if dlg.exec_() == QDialog.Accepted:
            new_gui = KeyManagementGUI(self.store)
            new_gui.show()
        else:
            QApplication.quit()

    def _enum_to_str(self, v):
        try:
            return v.value
        except Exception:
            return str(v)

    def load_keys(self):
        self.table.setRowCount(0)
        keys = self.store.list_keys()
        for row, key in enumerate(keys):
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(key.key_id)))
            self.table.setItem(row, 1, QTableWidgetItem(str(key.owner)))
            self.table.setItem(row, 2, QTableWidgetItem(self._enum_to_str(key.key_type)))
            self.table.setItem(row, 3, QTableWidgetItem(self._enum_to_str(key.key_usage)))
            self.table.setItem(row, 4, QTableWidgetItem(self._enum_to_str(key.status)))
        self.update_button_states()
        self.user_label.setText(f"当前用户: {self.store.current_user or '未登录'}")

    def get_selected_key_id(self) -> Optional[str]:
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        if item is None:
            return None
        return item.text()

    def create_key(self):
        if not self.store.current_user:
            QMessageBox.warning(self, "错误", "请先登录")
            return
        dialog = CreateKeyDialog(self.store.current_user, self)
        if dialog.exec_() == QDialog.Accepted:
            owner, key_type_str, key_usage_str = dialog.get_data()
            try:
                key = self.store.create_key(owner, KeyType(key_type_str), KeyUsage(key_usage_str))
                self.status_label.setText(f"创建成功: {key.key_id}")
                self.load_keys()
            except Exception as e:
                QMessageBox.critical(self, "错误", f"创建密钥失败: {e}")

    def change_status(self, new_status: KeyStatus):
        key_id = self.get_selected_key_id()
        if not key_id:
            QMessageBox.warning(self, "错误", "请先选择一个密钥")
            return

        # destructive actions confirmation
        if new_status == KeyStatus.DESTROYED:
            ans = QMessageBox.question(self, "确认销毁", "销毁会删除密钥材料且不可恢复，确定继续？", QMessageBox.Yes | QMessageBox.No)
            if ans != QMessageBox.Yes:
                return
        elif new_status == KeyStatus.COMPROMISED:
            ans = QMessageBox.question(self, "标记泄露", "标记为泄露会立即清除本地密钥材料并记入审计，确定继续？", QMessageBox.Yes | QMessageBox.No)
            if ans != QMessageBox.Yes:
                return
        elif new_status == KeyStatus.REVOKED:
            ans = QMessageBox.question(self, "撤销密钥", "撤销后密钥将被视为不可用并清除本地材料，确定继续？", QMessageBox.Yes | QMessageBox.No)
            if ans != QMessageBox.Yes:
                return

        try:
            ok = self.store.update_key_status(key_id, new_status)
            if ok:
                self.status_label.setText(f"状态更新成功: {self._enum_to_str(new_status)}")
                self.load_keys()
                # user-friendly feedback
                if new_status in (KeyStatus.DESTROYED, KeyStatus.COMPROMISED, KeyStatus.REVOKED):
                    QMessageBox.information(self, "完成", f"密钥已标记为 {self._enum_to_str(new_status)}，密钥材料已失效/清除。")
            else:
                QMessageBox.warning(self, "错误", "状态更新失败")
        except Exception as e:
            # show friendly error
            QMessageBox.critical(self, "错误", f"操作失败: {e}")

    def can_transition(self, kobj: KeyObject, target: KeyStatus) -> bool:
        """Test whether kobj can transition to target by trying on a deepcopy."""
        try:
            tmp = copy.deepcopy(kobj)
            tmp.transition(target)
            return True
        except Exception:
            return False

    def update_button_states(self):
        # default disable all lifecycle buttons
        for b in [self.activate_btn, self.suspend_btn, self.deactivate_btn, self.revoke_btn, self.compromise_btn, self.rotate_btn, self.destroy_btn]:
            b.setEnabled(False)

        key_id = self.get_selected_key_id()
        if not key_id:
            return

        try:
            kobj = self.store.get_key(key_id)
        except Exception:
            return

        # Enable buttons based on allowed transitions in KeyObject.transition
        try:
            self.activate_btn.setEnabled(self.can_transition(kobj, KeyStatus.ACTIVE))
            self.suspend_btn.setEnabled(self.can_transition(kobj, KeyStatus.SUSPENDED))
            self.deactivate_btn.setEnabled(self.can_transition(kobj, KeyStatus.DEACTIVATED))
            self.revoke_btn.setEnabled(self.can_transition(kobj, KeyStatus.REVOKED))
            self.compromise_btn.setEnabled(self.can_transition(kobj, KeyStatus.COMPROMISED))
            # rotation allowed only from ACTIVE or DEACTIVATED per KeyStore.rotate_key policy
            self.rotate_btn.setEnabled(kobj.status in (KeyStatus.ACTIVE, KeyStatus.DEACTIVATED))
            self.destroy_btn.setEnabled(self.can_transition(kobj, KeyStatus.DESTROYED))
        except Exception:
            pass

    def rotate_selected_key(self):
        key_id = self.get_selected_key_id()
        if not key_id:
            QMessageBox.warning(self, "错误", "请先选择一个密钥")
            return
        try:
            new = self.store.rotate_key(key_id)
            QMessageBox.information(self, "轮换", f"密钥已轮换，新的 Key ID: {new.key_id}")
            self.load_keys()
        except Exception as e:
            QMessageBox.critical(self, "错误", f"轮换失败: {e}")

    def view_logs(self):
        if not self.store.current_user:
            QMessageBox.information(self, "提示", "请先登录以查看日志。")
            return

        cur = self.store.conn.cursor()
        # ---- 修改：只显示当前用户的日志 ----
        cur.execute(
            "SELECT timestamp, action, key_id, details FROM audit WHERE user = ? ORDER BY id DESC",
            (self.store.current_user,),
        )
        rows = cur.fetchall()

        dlg = QDialog(self)
        dlg.setWindowTitle("审计日志")
        dlg.setWindowIcon(QIcon(resource_path("./icon/document.png")))
        layout = QVBoxLayout()

        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["时间", "操作", "Key ID", "详情"])
        table.setRowCount(len(rows))

        for i, (ts, action, kid, details) in enumerate(rows):
            table.setItem(i, 0, QTableWidgetItem(ts))
            table.setItem(i, 1, QTableWidgetItem(action))
            table.setItem(i, 2, QTableWidgetItem(kid))
            table.setItem(i, 3, QTableWidgetItem(details))

        layout.addWidget(table)
        dlg.setLayout(layout)
        dlg.resize(800, 480)
        dlg.exec_()

    def view_details(self):
        key_id = self.get_selected_key_id()
        if not key_id:
            QMessageBox.warning(self, "错误", "请先选择一个密钥")
            return
        try:
            key = self.store.get_key(key_id)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"查看详情失败: {e}")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("密钥详情")
        dlg.setWindowIcon(QIcon(resource_path("./icon/search.png")))
        layout = QVBoxLayout()

        text = QTextEdit()
        text.setReadOnly(True)
        text.setText(
            f"Key ID: {key.key_id}\n"
            f"Owner: {key.owner}\n"
            f"Type: {self._enum_to_str(key.key_type)}\n"
            f"Usage: {self._enum_to_str(key.key_usage)}\n"
            f"Status: {self._enum_to_str(key.status)}\n"
            f"Created At: {key.created_at}\n"
            f"Updated At: {key.updated_at}\n"
        )
        layout.addWidget(text)

        dlg.setLayout(layout)
        dlg.resize(700, 420)
        dlg.exec_()


    def show_help(self):
        """显示帮助说明（内部 + API 使用说明）"""
        internal_help = """密钥管理系统使用说明

1. 登录/注册
- 首次启动需注册首个用户，系统会自动生成主密钥。
- 之后可通过已有账户登录。

2. 主界面
- 上方显示当前登录用户。
- 中间表格展示当前用户创建的密钥信息：ID、类型、用途、状态。
- 下方按钮区提供操作，如创建、激活、停用、撤销、销毁等。

3. 密钥生命周期
- 创建：新建密钥并存储。
- 激活：启用密钥以便使用。
- 停用/挂起：暂时禁止使用。
- 撤销/标记泄露：立即作废密钥并删除材料。
- 销毁：彻底删除，不可恢复。
- 轮换：生成新版本密钥，旧版本作废。

4. 审计日志
- 点击“查看日志”可查看本用户的密钥操作记录。

5. 其他
- “退出登录”按钮可切换用户。
- 日志和密钥只对当前账户可见，确保隔离性。
"""

        api_help = api_help = """
API 使用说明（当前版本）

基础地址: http://127.0.0.1:5050

1. 登录
   POST /api/login
   Body: { "username": "your_name" }
   Response: { "token": "xxx" }

2. 列出所有密钥
   GET /api/keys
   Headers: { "Authorization": "Bearer <token>" }
   Response: [ "key1", "key2", ... ]

3. 获取密钥的公钥
   GET /api/keys/<key_name>/public
   Headers: { "Authorization": "Bearer <token>" }
   Response: { "public_key": "..." }

4. 获取原始密钥
   GET /api/keys/<key_name>/raw
   Headers: { "Authorization": "Bearer <token>" }
   Response: { "raw_key": "..." }

5. 包装密钥
   POST /api/keys/<key_name>/wrap
   Headers: { "Authorization": "Bearer <token>" }
   Body: { "wrapping_key": "..." }
   Response: { "wrapped_key": "..." }

注意事项:
- 所有需要鉴权的接口都必须在请求头加上 Bearer Token。
- 登录返回的 token 有效期由服务端决定，请妥善保存。
"""


        dlg = QDialog(self)
        dlg.setWindowTitle("帮助")
        dlg.setWindowIcon(QIcon(resource_path("./icon/help.png")))
        layout = QVBoxLayout()

        from PyQt5.QtWidgets import QTabWidget
        tabs = QTabWidget()

        text1 = QTextEdit()
        text1.setReadOnly(True)
        text1.setText(internal_help)
        tabs.addTab(text1, "系统使用说明")

        text2 = QTextEdit()
        text2.setReadOnly(True)
        text2.setText(api_help)
        tabs.addTab(text2, "API 使用说明")

        layout.addWidget(tabs)
        dlg.setLayout(layout)
        dlg.resize(900, 700)
        dlg.exec_()




if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(resource_path("./icon/user.png")))

    store = KeyStore()

    if store.user_count() == 0:
        dlg = RegisterDialog(store)
        if dlg.exec_() != QDialog.Accepted:
            QMessageBox.critical(None, "错误", "必须注册首个用户以启动系统。")
            sys.exit(1)
    else:
        dlg = LoginDialog(store)
        if dlg.exec_() != QDialog.Accepted:
            QMessageBox.critical(None, "错误", "必须登录以启动系统。")
            sys.exit(1)

    gui = KeyManagementGUI(store)
    gui.show()

    # <<< 修改：绑定退出信号，而不是一开始就执行
    def on_exit():
        try:
            stop_kms_service()
            if hasattr(gui, "status_label"):
                gui.status_label.setText("KMS服务已停止")
        except Exception:
            pass

    app.aboutToQuit.connect(on_exit)

    sys.exit(app.exec_())

