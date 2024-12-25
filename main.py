import os
import sqlite3
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QFileDialog, QWidget, QMessageBox, QSpinBox, QTabWidget,
    QInputDialog, QDialog, QFormLayout, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt
import random
import string


def encrypt_text(text, key, rounds=1):
    key_len = len(key)
    for _ in range(rounds):
        text = ''.join(chr(ord(char) + ord(key[i % key_len])) for i, char in enumerate(text))
    return text


def decrypt_text(text, key, rounds=1):
    key_len = len(key)
    for _ in range(rounds):
        text = ''.join(chr(ord(char) - ord(key[i % key_len])) for i, char in enumerate(text))
    return text


def encrypt_file(input_file, output_file, key, rounds=1):
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        data = infile.read()
        for _ in range(rounds):
            data = bytearray(byte ^ key_bytes[i % key_len] for i, byte in enumerate(data))
        outfile.write(data)


def decrypt_file(input_file, output_file, key, rounds=1):
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        data = infile.read()
        for _ in range(rounds):
            data = bytearray(byte ^ key_bytes[i % key_len] for i, byte in enumerate(data))
        outfile.write(data)


class LoginDialog(QDialog):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Вход или регистрация")
        self.username = None
        self.init_ui()

    def init_ui(self):
        layout = QFormLayout()

        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Войти")
        self.register_button = QPushButton("Зарегистрироваться")

        layout.addRow("Имя пользователя:", self.username_input)
        layout.addRow("Пароль:", self.password_input)
        layout.addRow(self.login_button, self.register_button)

        self.setLayout(layout)

        self.login_button.clicked.connect(self.login)
        self.register_button.clicked.connect(self.register)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if self.db.check_user(username, password):
            self.username = username
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка", "Неправильное имя пользователя или пароль")

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if self.db.add_user(username, password):
            QMessageBox.information(self, "Успех", "Пользователь зарегистрирован")
        else:
            QMessageBox.warning(self, "Ошибка", "Имя пользователя уже занято")


class Database:
    def __init__(self, db_name="users.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                username TEXT,
                key_name TEXT,
                key_value TEXT,
                FOREIGN KEY(username) REFERENCES users(username)
            )
        """)
        self.conn.commit()

    def add_user(self, username, password):
        try:
            self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def check_user(self, username, password):
        self.cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        return self.cursor.fetchone() is not None

    def save_key(self, username, key_name, key_value):
        try:
            self.cursor.execute("INSERT INTO keys (username, key_name, key_value) VALUES (?, ?, ?)", (username, key_name, key_value))
            self.conn.commit()
            print(f"Key {key_name} saved for user {username}")
        except sqlite3.Error as e:
            print(f"Error saving key: {e}")

    def get_keys(self, username):
        self.cursor.execute("SELECT key_name, key_value FROM keys WHERE username = ?", (username,))
        return self.cursor.fetchall()


class EncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.username = None
        self.init_login()
        self.init_ui()

    def init_login(self):
        login_dialog = LoginDialog(self.db)
        if login_dialog.exec_() == QDialog.Accepted:
            self.username = login_dialog.username
        else:
            exit()

    def init_ui(self):
        self.setWindowTitle("Шифрование и расшифровка")
        self.setGeometry(100, 100, 800, 600)

        self.tabs = QTabWidget(self)
        self.text_tab = QWidget()
        self.file_tab = QWidget()
        self.keys_tab = QWidget()
        self.tabs.addTab(self.text_tab, "Текст")
        self.tabs.addTab(self.file_tab, "Файлы")
        self.tabs.addTab(self.keys_tab, "Ключи")

        self.init_text_tab()
        self.init_file_tab()
        self.init_keys_tab()

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def init_text_tab(self):
        layout = QVBoxLayout()

        self.input_text = QTextEdit()
        self.output_text = QTextEdit()
        self.rounds_input = QSpinBox()
        self.rounds_input.setMinimum(1)
        self.rounds_input.setMaximum(10)
        self.rounds_input.setValue(1)

        encrypt_button = QPushButton("Зашифровать текст")
        decrypt_button = QPushButton("Расшифровать текст")

        layout.addWidget(QLabel("Введите текст:"))
        layout.addWidget(self.input_text)
        layout.addWidget(QLabel("Количество кругов шифрования:"))
        layout.addWidget(self.rounds_input)
        layout.addWidget(encrypt_button)
        layout.addWidget(decrypt_button)
        layout.addWidget(QLabel("Результат:"))
        layout.addWidget(self.output_text)

        self.text_tab.setLayout(layout)

        encrypt_button.clicked.connect(self.encrypt_text_action)
        decrypt_button.clicked.connect(self.decrypt_text_action)

    def init_file_tab(self):
        layout = QVBoxLayout()

        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Выберите файл для шифрования")
        self.rounds_file_input = QSpinBox()
        self.rounds_file_input.setMinimum(1)
        self.rounds_file_input.setMaximum(10)
        self.rounds_file_input.setValue(1)

        browse_button = QPushButton("Обзор")
        encrypt_button = QPushButton("Зашифровать файл")
        decrypt_button = QPushButton("Расшифровать файл")

        layout.addWidget(QLabel("Файл:"))
        layout.addWidget(self.file_input)
        layout.addWidget(browse_button)
        layout.addWidget(QLabel("Количество кругов шифрования:"))
        layout.addWidget(self.rounds_file_input)
        layout.addWidget(encrypt_button)
        layout.addWidget(decrypt_button)

        self.file_tab.setLayout(layout)

        browse_button.clicked.connect(self.browse_file)
        encrypt_button.clicked.connect(self.encrypt_file_action)
        decrypt_button.clicked.connect(self.decrypt_file_action)

    def init_keys_tab(self):
        layout = QVBoxLayout()

        self.keys_table = QTableWidget()
        self.keys_table.setColumnCount(2)
        self.keys_table.setHorizontalHeaderLabels(["Название ключа", "Ключ"])

        self.load_keys_button = QPushButton("Загрузить ключи")
        self.generate_key_button = QPushButton("Сгенерировать ключ")
        self.save_key_button = QPushButton("Сохранить ключ")

        layout.addWidget(self.keys_table)
        layout.addWidget(self.load_keys_button)
        layout.addWidget(self.generate_key_button)
        layout.addWidget(self.save_key_button)

        self.keys_tab.setLayout(layout)

        self.load_keys_button.clicked.connect(self.load_keys_action)
        self.generate_key_button.clicked.connect(self.generate_key_action)
        self.save_key_button.clicked.connect(self.save_key_action)

    def load_keys_action(self):
        if self.username:
            keys = self.db.get_keys(self.username)
            self.keys_table.setRowCount(0)
            for key_name, key_value in keys:
                row_position = self.keys_table.rowCount()
                self.keys_table.insertRow(row_position)
                self.keys_table.setItem(row_position, 0, QTableWidgetItem(key_name))
                self.keys_table.setItem(row_position, 1, QTableWidgetItem(key_value))

    def generate_key_action(self):
        key_name, ok = QInputDialog.getText(self, "Название ключа", "Введите название ключа:")
        if ok:
            key_value = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            self.keys_table.insertRow(self.keys_table.rowCount())
            self.keys_table.setItem(self.keys_table.rowCount() - 1, 0, QTableWidgetItem(key_name))
            self.keys_table.setItem(self.keys_table.rowCount() - 1, 1, QTableWidgetItem(key_value))

    def save_key_action(self):
        key_name = self.keys_table.item(self.keys_table.currentRow(), 0).text()
        key_value = self.keys_table.item(self.keys_table.currentRow(), 1).text()
        if key_name and key_value and self.username:
            self.db.save_key(self.username, key_name, key_value)

    def encrypt_text_action(self):
        text = self.input_text.toPlainText()
        key, ok = QInputDialog.getText(self, "Введите ключ", "Введите ключ для шифрования:")
        if ok:
            rounds = self.rounds_input.value()
            encrypted_text = encrypt_text(text, key, rounds)
            self.output_text.setPlainText(encrypted_text)

    def decrypt_text_action(self):
        text = self.input_text.toPlainText()
        key, ok = QInputDialog.getText(self, "Введите ключ", "Введите ключ для расшифровки:")
        if ok:
            rounds = self.rounds_input.value()
            decrypted_text = decrypt_text(text, key, rounds)
            self.output_text.setPlainText(decrypted_text)

    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Выбрать файл", "", "Все файлы (*)")
        if filename:
            self.file_input.setText(filename)

    def encrypt_file_action(self):
        file = self.file_input.text()
        key, ok = QInputDialog.getText(self, "Введите ключ", "Введите ключ для шифрования:")
        if ok:
            rounds = self.rounds_file_input.value()
            output_file = file + ".encrypted"
            encrypt_file(file, output_file, key, rounds)
            QMessageBox.information(self, "Успех", f"Файл зашифрован и сохранен как {output_file}")

    def decrypt_file_action(self):
        file = self.file_input.text()
        key, ok = QInputDialog.getText(self, "Введите ключ", "Введите ключ для расшифровки:")
        if ok:
            rounds = self.rounds_file_input.value()
            output_file = file + ".decrypted"
            decrypt_file(file, output_file, key, rounds)
            QMessageBox.information(self, "Успех", f"Файл расшифрован и сохранен как {output_file}")


def main():
    app = QApplication([])
    window = EncryptionApp()
    window.show()
    app.exec_()


if __name__ == "__main__":
    main()
