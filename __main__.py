import sys
import json
from PySide6.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
                              QPushButton, QVBoxLayout, QWidget, QDialog, QFormLayout,
                              QLineEdit, QTextEdit, QMessageBox, QDialogButtonBox,
                              QCheckBox, QInputDialog, QLabel, QHBoxLayout)
from PySide6.QtCore import Qt
from pydantic import ValidationError
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from keylocklib import *
import base64
import uuid

# Your existing backend code here...

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unlock Password Manager")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your master password")

        self.btn_unlock = QPushButton("Unlock")
        self.btn_unlock.clicked.connect(self.accept)

        layout.addWidget(QLabel("Master Password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.btn_unlock)

        self.setLayout(layout)

    def get_password(self):
        return self.password_input.text()


class EntryDialog(QDialog):
    def __init__(self, entry: Optional[KeyLockEntry] = None):
        super().__init__()
        self.entry = entry
        self.setWindowTitle("Edit Entry" if entry else "New Entry")
        self.setup_ui()

    def setup_ui(self):
        layout = QFormLayout()

        self.id_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.services_input = QLineEdit()
        self.notes_input = QTextEdit()

        # Show password checkbox
        self.show_password = QCheckBox("Show password")
        self.show_password.toggled.connect(self.toggle_password_visibility)

        if self.entry:
            self.id_input.setText(self.entry.id)
            self.username_input.setText(self.entry.username)
            self.password_input.setText(self.entry.password)
            self.services_input.setText(", ".join(self.entry.services))
            self.notes_input.setText(self.entry.notes or "")

        layout.addRow("ID:", self.id_input)
        layout.addRow("Username:", self.username_input)
        layout.addRow("Password:", self.password_input)
        layout.addRow(self.show_password)
        layout.addRow("Services (comma-separated):", self.services_input)
        layout.addRow("Notes:", self.notes_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.validate)
        buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(buttons)
        self.setLayout(main_layout)

    def toggle_password_visibility(self, checked):
        self.password_input.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    def validate(self):
        try:
            KeyLockEntry(
                id=self.id_input.text(),
                username=self.username_input.text(),
                password=self.password_input.text(),
                services=[s.strip() for s in self.services_input.text().split(",") if s.strip()],
                notes=self.notes_input.toPlainText() or None
            )
            self.accept()
        except ValidationError as e:
            QMessageBox.warning(self, "Validation Error", str(e))

    def get_entry_data(self):
        return {
            "id": self.id_input.text(),
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "services": [s.strip() for s in self.services_input.text().split(",") if s.strip()],
            "notes": self.notes_input.toPlainText() or None
        }


class PasswordManagerUI(QMainWindow):
    def __init__(self, key_lock_file: KeyLockFile):
        super().__init__()
        self.key_lock_file = key_lock_file
        self.setWindowTitle("Password Manager")
        self.setMinimumSize(800, 600)
        self.setup_ui()
        self.load_entries()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Entry Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Username", "Services", "Notes"])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.doubleClicked.connect(self.edit_entry)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_add = QPushButton("Add Entry")
        self.btn_add.clicked.connect(self.add_entry)
        self.btn_edit = QPushButton("Edit Entry")
        self.btn_edit.clicked.connect(self.edit_entry)
        self.btn_delete = QPushButton("Delete Entry")
        self.btn_delete.clicked.connect(self.delete_entry)
        self.btn_save = QPushButton("Save Changes")
        self.btn_save.clicked.connect(self.save_changes)

        btn_layout.addWidget(self.btn_add)
        btn_layout.addWidget(self.btn_edit)
        btn_layout.addWidget(self.btn_delete)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_save)

        layout.addWidget(self.table)
        layout.addLayout(btn_layout)

    def load_entries(self):
        self.table.setRowCount(0)
        for entry in self.key_lock_file.data.entries_list:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(entry.id))
            self.table.setItem(row, 1, QTableWidgetItem(entry.username))
            self.table.setItem(row, 2, QTableWidgetItem(", ".join(entry.services)))
            self.table.setItem(row, 3, QTableWidgetItem(entry.notes or ""))

    def add_entry(self):
        dialog = EntryDialog()
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_entry_data()
            try:
                new_entry = KeyLockEntry(**data)
                self.key_lock_file.add_entry(new_entry)
                self.load_entries()
            except ValidationError as e:
                QMessageBox.critical(self, "Error", str(e))

    def edit_entry(self):
        selected = self.table.currentRow()
        if selected == -1:
            QMessageBox.warning(self, "No Selection", "Please select an entry to edit")
            return

        original_entry = self.key_lock_file.data.entries_list[selected]
        dialog = EntryDialog(original_entry)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_entry_data()
            try:
                updated_entry = KeyLockEntry(
                    **data,
                    internal_id=original_entry.internal_id  # Preserve internal ID
                )
                self.key_lock_file.set_entry(original_entry.internal_id, updated_entry)
                self.load_entries()
            except ValidationError as e:
                QMessageBox.critical(self, "Error", str(e))

    def delete_entry(self):
        selected = self.table.currentRow()
        if selected == -1:
            QMessageBox.warning(self, "No Selection", "Please select an entry to delete")
            return

        entry = self.key_lock_file.data.entries_list[selected]
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Delete entry '{entry.id}' for {entry.username}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.key_lock_file.delete_entry(entry.internal_id)
            self.load_entries()

    def save_changes(self):
        try:
            with open("passwords.json", "w") as f:
                json_data = json.loads(self.key_lock_file.export_data())
                json.dump(json_data, f, indent=2)
            QMessageBox.information(self, "Success", "Changes saved successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save changes: {str(e)}")


def main():
    app = QApplication(sys.argv)

    # Show login dialog
    login = LoginDialog()
    if not login.exec_():
        sys.exit()

    # Load or create password database
    try:
        with open("passwords.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    except json.JSONDecodeError:
        QMessageBox.critical(None, "Error", "Corrupted data file")
        sys.exit(1)

    try:
        key_lock = KeyLockFile(data, login.get_password())
        window = PasswordManagerUI(key_lock)
        window.show()
        sys.exit(app.exec())
    except ValidationError as e:
        QMessageBox.critical(None, "Validation Error", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()