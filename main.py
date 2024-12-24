import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QFileDialog, QWidget, QMessageBox, QSpinBox, QTabWidget
)
from PyQt5.QtCore import Qt

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

class EncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Шифрование и расшифровка")
        self.setGeometry(100, 100, 700, 600)

        self.tabs = QTabWidget(self)
        self.text_tab = QWidget()
        self.file_tab = QWidget()
        self.tabs.addTab(self.text_tab, "Текст")
        self.tabs.addTab(self.file_tab, "Файлы")

        self.init_text_tab()
        self.init_file_tab()

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def init_text_tab(self):
        layout = QVBoxLayout()

        # Поля для работы с текстом
        self.text_input_label = QLabel("Введите текст:")
        self.text_input = QTextEdit()
        self.key_label = QLabel("Введите ключ:")
        self.key_input = QLineEdit()
        self.rounds_label = QLabel("Количество кругов шифрования:")
        self.rounds_input = QSpinBox()
        self.rounds_input.setMinimum(1)
        self.rounds_input.setValue(1)
        self.text_result = QTextEdit()
        self.text_result.setReadOnly(True)

        # Кнопки
        self.encrypt_text_btn = QPushButton("Зашифровать текст")
        self.decrypt_text_btn = QPushButton("Расшифровать текст")

        # Добавление элементов в макет
        layout.addWidget(self.text_input_label)
        layout.addWidget(self.text_input)
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)
        layout.addWidget(self.rounds_label)
        layout.addWidget(self.rounds_input)
        layout.addWidget(self.encrypt_text_btn)
        layout.addWidget(self.decrypt_text_btn)
        layout.addWidget(QLabel("Результат:"))
        layout.addWidget(self.text_result)

        self.text_tab.setLayout(layout)

        # Подключение сигналов
        self.encrypt_text_btn.clicked.connect(self.encrypt_text)
        self.decrypt_text_btn.clicked.connect(self.decrypt_text)

    def init_file_tab(self):
        layout = QVBoxLayout()

        # Поля для работы с файлами
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Выберите файл")
        self.select_file_btn = QPushButton("Выбрать файл")
        self.file_key_input = QLineEdit()
        self.file_key_input.setPlaceholderText("Введите ключ")
        self.rounds_label_file = QLabel("Количество кругов шифрования:")
        self.rounds_input_file = QSpinBox()
        self.rounds_input_file.setMinimum(1)
        self.rounds_input_file.setValue(1)

        # Кнопки
        self.encrypt_file_btn = QPushButton("Зашифровать файл")
        self.decrypt_file_btn = QPushButton("Расшифровать файл")

        # Добавление элементов в макет
        layout.addWidget(QLabel("Выберите файл:"))
        layout.addWidget(self.file_path_input)
        layout.addWidget(self.select_file_btn)
        layout.addWidget(self.file_key_input)
        layout.addWidget(self.rounds_label_file)
        layout.addWidget(self.rounds_input_file)
        layout.addWidget(self.encrypt_file_btn)
        layout.addWidget(self.decrypt_file_btn)

        self.file_tab.setLayout(layout)

        # Подключение сигналов
        self.select_file_btn.clicked.connect(self.select_file)
        self.encrypt_file_btn.clicked.connect(self.encrypt_file)
        self.decrypt_file_btn.clicked.connect(self.decrypt_file)

    def encrypt_text(self):
        text = self.text_input.toPlainText()
        key = self.key_input.text()
        rounds = self.rounds_input.value()
        if not text or not key:
            QMessageBox.warning(self, "Ошибка", "Введите текст и ключ!")
            return
        encrypted = encrypt_text(text, key, rounds)
        self.text_result.setText(encrypted)

    def decrypt_text(self):
        text = self.text_input.toPlainText()
        key = self.key_input.text()
        rounds = self.rounds_input.value()
        if not text or not key:
            QMessageBox.warning(self, "Ошибка", "Введите текст и ключ!")
            return
        decrypted = decrypt_text(text, key, rounds)
        self.text_result.setText(decrypted)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Все файлы (*)")
        if file_path:
            self.file_path_input.setText(file_path)

    def encrypt_file(self):
        file_path = self.file_path_input.text()
        key = self.file_key_input.text()
        rounds = self.rounds_input_file.value()
        if not file_path or not key:
            QMessageBox.warning(self, "Ошибка", "Выберите файл и введите ключ!")
            return
        output_file = file_path + ".enc"
        try:
            encrypt_file(file_path, output_file, key, rounds)
            QMessageBox.information(self, "Успех", f"Файл зашифрован и сохранён как {output_file}.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать файл: {e}")

    def decrypt_file(self):
        file_path = self.file_path_input.text()
        key = self.file_key_input.text()
        rounds = self.rounds_input_file.value()
        if not file_path or not key:
            QMessageBox.warning(self, "Ошибка", "Выберите файл и введите ключ!")
            return
        output_file = file_path + ".dec"
        try:
            decrypt_file(file_path, output_file, key, rounds)
            QMessageBox.information(self, "Успех", f"Файл расшифрован и сохранён как {output_file}.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать файл: {e}")

if __name__ == "__main__":
    app = QApplication([])
    window = EncryptionApp()
    window.show()
    app.exec()
