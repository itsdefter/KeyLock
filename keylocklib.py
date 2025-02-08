from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from uuid import uuid4

class Metadata(BaseModel):
    created_at: str
    updated_at: str
    version: str

class KeyLockEntry(BaseModel):
    internal_id: str = Field(default_factory=lambda: str(uuid4()), exclude=True)  # Internal tracking ID
    id: str
    username: str
    password: str
    services: List[str] = Field(default_factory=list)
    notes: Optional[str] = None

class KeyLockData(BaseModel):
    metadata: Metadata
    entries_list: List[KeyLockEntry]

class KeyLockPrimitives:
    @staticmethod
    def derive_key_argon2(password: str, salt: bytes) -> bytes:
        """Derive a key from the password using Argon2id."""
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=4,
            lanes=4,
            memory_cost=64 * 1024,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

class KeyLockFile:
    def __init__(self, raw_data: dict, password: str):
        if raw_data in (None, "", {}):
            print("Creating new data.")
            raw_data = {
                "metadata": {
                    "created_at": "2023-01-01",
                    "updated_at": "2023-01-02",
                    "version": "1.0"
                },
                "entries_list": []
            }
        json_data = raw_data
        self.data = KeyLockData(**json_data)  # Validation happens here
        self.password = password
        self._generate_uuids()

    def _generate_uuids(self):
        for entry in self.data.entries_list:
            if not entry.internal_id:
                entry.internal_id = KeyLockEntry.__fields__['internal_id'].default_factory()

    def export_data(self) -> str:
        """Export the data as a JSON string."""
        return self.data.model_dump_json()

    def add_entry(self, entry: KeyLockEntry):
        if entry.internal_id in [entry.internal_id for entry in self.data.entries_list]:
            raise ValueError("Entry already exists.")
        self.data.entries_list.append(entry)

    def delete_entry(self, entry_id: str):
        if entry_id in [entry.internal_id for entry in self.data.entries_list]:
            del self.data.entries_list[entry_id]
        else:
            raise ValueError("Entry does not exist.")

    def set_entry(self, old_id: str, new_entry: KeyLockEntry):
        for i, entry in enumerate(self.data.entries_list):
            if entry.internal_id == old_id:
                self.data.entries_list[i] = new_entry
                return
        self.add_entry(new_entry)

if __name__ == "__main__":
    try:
        with open("passwords.json", "r") as f:
            data = json.load(f)
            print(data)
        key_lock_file = KeyLockFile(data, "password")
        new_entry = KeyLockEntry(id="5", username="newuser@hehe.su", password="newpass123")
        key_lock_file.add_entry(new_entry)
        print(key_lock_file.export_data())
    except (json.JSONDecodeError, ValidationError) as e:
        print(f"Error: {e}")
