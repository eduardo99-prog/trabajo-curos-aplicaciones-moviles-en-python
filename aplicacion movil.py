"""Aplicación móvil de gestión de tareas con Kivy y SQLite."""

import os
import sqlite3
import hashlib
import hmac
import secrets

from kivy.app import App
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import NoTransition, Screen, ScreenManager
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput


NAVY = (0.07, 0.13, 0.24, 1)
BLUE = (0.16, 0.38, 0.72, 1)
LIGHT = (0.95, 0.97, 0.99, 1)
WHITE = (1, 1, 1, 1)
GREEN = (0.12, 0.52, 0.34, 1)
RED = (0.72, 0.20, 0.20, 1)
GRAY = (0.35, 0.39, 0.45, 1)


class TaskDatabase:

    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self):
        with self.connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                )
            """)

    @staticmethod
    def hash_password(password, salt):
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            200000
        ).hex()

    def register(self, username, password):
        username = username.strip()

        if not 3 <= len(username) <= 30:
            raise ValueError(
                "El usuario debe tener entre 3 y 30 caracteres."
            )

        if not password or len(password) < 8:
            raise ValueError(
                "La contraseña debe tener al menos 8 caracteres."
            )

        salt = secrets.token_hex(16)
        password_hash = self.hash_password(password, salt)

        try:
            with self.connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO users (username, password_hash, salt)
                    VALUES (?, ?, ?)
                    """,
                    (username, password_hash, salt)
                )
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError("Ese nombre de usuario ya existe.")

    def authenticate(self, username, password):
        with self.connect() as conn:
            user = conn.execute(
                """
                SELECT id, username, password_hash, salt
                FROM users
                WHERE username = ?
                """,
                (username.strip(),)
            ).fetchone()

        if user is None:
            return None

        password_hash = self.hash_password(password, user["salt"])

        if not hmac.compare_digest(
            password_hash, user["password_hash"]
        ):
            return None

        return {
            "id": user["id"],
            "username": user["username"]
        }

    def add_task(self, user_id, title):
        title = title.strip()

        if not title:
            raise ValueError("Escribe el nombre de la tarea.")

        if len(title) > 250:
            raise ValueError(
                "La tarea no puede superar los 250 caracteres."
            )

        with self.connect() as conn:
            conn.execute(
                "INSERT INTO tasks (user_id, title) VALUES (?, ?)",
                (user_id, title)
            )

    def list_tasks(self, user_id, status="all"):
        query = """
            SELECT id, title, completed, created_at
            FROM tasks
            WHERE user_id = ?
        """
        params = [user_id]

        if status == "pending":
            query += " AND completed = 0"
        elif status == "completed":
            query += " AND completed = 1"

        query += " ORDER BY id DESC"

        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]

    def toggle_task(self, user_id, task_id):
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET completed = CASE
                    WHEN completed = 0 THEN 1 ELSE 0
                END
                WHERE id = ? AND user_id = ?
                """,
                (task_id, user_id)
            )

    def update_task(self, user_id, task_id, title):
        title = title.strip()

        if not title:
            raise ValueError("El nombre de la tarea es obligatorio.")

        if len(title) > 250:
            raise ValueError(
                "La tarea no puede superar los 250 caracteres."
            )

        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE tasks
                SET title = ?
                WHERE id = ? AND user_id = ?
                """,
                (title, task_id, user_id)
            )
            return cursor.rowcount > 0

    def delete_task(self, user_id, task_id):
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id)
            )


class TareasMovilesApp(App):
    title = "Tareas Móviles"

    def build(self):
        self.db = TaskDatabase(
            os.path.join(self.user_data_dir, "tareas.db")
        )
        self.current_user = None

        self.manager = ScreenManager(
            transition=NoTransition()
        )
        self.manager.add_widget(LoginScreen(name="login", app=self))
        self.manager.add_widget(RegisterScreen(name="register", app=self))
        self.manager.add_widget(TasksScreen(name="tasks", app=self))

        Window.clearcolor = LIGHT
        return self.manager

    def notify(self, message, title="Tareas Móviles"):
        content = BoxLayout(
            orientation="vertical",
            padding=dp(16),
            spacing=dp(12)
        )
        content.add_widget(
            Label(
                text=message,
                color=NAVY,
                halign="center",
                valign="middle"
            )
        )

        close_button = Button(
            text="Aceptar",
            size_hint_y=None,
            height=dp(46),
            background_normal="",
            background_color=BLUE,
            color=WHITE
        )
        content.add_widget(close_button)

        popup = Popup(
            title=title,
            content=content,
            size_hint=(0.88, None),
            height=dp(210),
            auto_dismiss=False
        )
        close_button.bind(on_release=popup.dismiss)
        popup.open()

    def sign_in(self, username, password):
        if not username.strip() or not password:
            self.notify("Completa el usuario y la contraseña.")
            return

        user = self.db.authenticate(username, password)

        if user is None:
            self.notify("Usuario o contraseña incorrectos.")
            return

        self.current_user = user
        self.manager.current = "tasks"
        self.manager.get_screen("tasks").refresh_tasks()

    def sign_up(self, username, password, confirmation):
        if password != confirmation:
            self.notify("Las contraseñas no coinciden.")
            return

        try:
            user_id = self.db.register(username, password)
        except ValueError as error:
            self.notify(str(error))
            return

        self.current_user = {
            "id": user_id,
            "username": username.strip()
        }

        self.manager.current = "tasks"
        self.manager.get_screen("tasks").refresh_tasks()
        self.notify("Tu cuenta se creó correctamente.")

    def sign_out(self):
        self.current_user = None
        self.manager.current = "login"


def styled_button(text, callback, color=BLUE, height=46):
    button = Button(
        text=text,
        size_hint_y=None,
        height=dp(height),
        background_normal="",
        background_down="",
        background_color=color,
        color=WHITE,
        bold=True
    )
    button.bind(on_release=lambda *_: callback())
    return button


def make_text_input(hint, password=False, multiline=False):
    return TextInput(
        hint_text=hint,
        password=password,
        multiline=multiline,
        size_hint_y=None,
        height=dp(48),
        padding=(dp(12), dp(12)),
        background_normal="",
        background_active="",
        background_color=WHITE,
        foreground_color=NAVY,
        cursor_color=BLUE,
        font_size="16sp"
    )


class LoginScreen(Screen):

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app

        layout = BoxLayout(
            orientation="vertical",
            padding=[dp(24), dp(30)],
            spacing=dp(14)
        )

        layout.add_widget(Label(
            text="Tareas Móviles",
            font_size="30sp",
            bold=True,
            color=NAVY,
            size_hint_y=None,
            height=dp(58)
        ))

        layout.add_widget(Label(
            text="Organiza tus actividades",
            font_size="16sp",
            color=GRAY,
            size_hint_y=None,
            height=dp(32)
        ))

        self.username = make_text_input("Usuario")
        self.password = make_text_input("Contraseña", password=True)

        layout.add_widget(self.username)
        layout.add_widget(self.password)
        layout.add_widget(
            styled_button("Iniciar sesión", self.submit_login, GREEN)
        )
        layout.add_widget(
            styled_button("Crear una cuenta", self.open_register, BLUE)
        )
        layout.add_widget(Label(
            text="Tus tareas se guardan en este dispositivo.",
            color=GRAY,
            font_size="13sp",
            halign="center"
        ))

        self.add_widget(layout)

    def submit_login(self):
        self.app.sign_in(
            self.username.text,
            self.password.text
        )

    def open_register(self):
        self.app.manager.current = "register"


class RegisterScreen(Screen):

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app

        layout = BoxLayout(
            orientation="vertical",
            padding=[dp(24), dp(28)],
            spacing=dp(12)
        )

        layout.add_widget(Label(
            text="Crear cuenta",
            font_size="27sp",
            bold=True,
            color=NAVY,
            size_hint_y=None,
            height=dp(54)
        ))

        layout.add_widget(Label(
            text="Usuario: 3 a 30 caracteres. Contraseña: mínimo 8.",
            font_size="13sp",
            color=GRAY,
            halign="center",
            size_hint_y=None,
            height=dp(42)
        ))

        self.username = make_text_input("Usuario")
        self.password = make_text_input("Contraseña", password=True)
        self.confirmation = make_text_input(
            "Repite la contraseña",
            password=True
        )

        layout.add_widget(self.username)
        layout.add_widget(self.password)
        layout.add_widget(self.confirmation)
        layout.add_widget(
            styled_button("Registrarme", self.submit_registration, GREEN)
        )
        layout.add_widget(
            styled_button(
                "Volver al inicio de sesión",
                self.back_to_login,
                GRAY
            )
        )

        self.add_widget(layout)

    def submit_registration(self):
        self.app.sign_up(
            self.username.text,
            self.password.text,
            self.confirmation.text
        )

    def back_to_login(self):
        self.app.manager.current = "login"


class TasksScreen(Screen):

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.filter_status = "all"

        root = BoxLayout(
            orientation="vertical",
            padding=dp(14),
            spacing=dp(10)
        )

        header = BoxLayout(
            size_hint_y=None,
            height=dp(48),
            spacing=dp(8)
        )

        self.heading = Label(
            text="Mis tareas",
            font_size="24sp",
            bold=True,
            color=NAVY,
            halign="left",
            valign="middle"
        )
        header.add_widget(self.heading)
        header.add_widget(
            styled_button("Salir", self.app.sign_out, GRAY, 42)
        )
        root.add_widget(header)

        add_row = BoxLayout(
            size_hint_y=None,
            height=dp(50),
            spacing=dp(8)
        )

        self.new_task_input = make_text_input("Escribe una tarea")
        self.new_task_input.bind(
            on_text=lambda *_: self.refresh_tasks()
        )

        add_row.add_widget(self.new_task_input)
        add_row.add_widget(
            styled_button("Agregar", self.open_add_popup, GREEN, 48)
        )
        root.add_widget(add_row)

        filters = BoxLayout(
            size_hint_y=None,
            height=dp(42),
            spacing=dp(6)
        )

        filters.add_widget(
            styled_button("Todas", lambda: self.set_filter("all"), BLUE, 40)
        )
        filters.add_widget(
            styled_button(
                "Pendientes",
                lambda: self.set_filter("pending"),
                BLUE,
                40
            )
        )
        filters.add_widget(
            styled_button(
                "Completadas",
                lambda: self.set_filter("completed"),
                BLUE,
                40
            )
        )
        root.add_widget(filters)

        self.summary = Label(
            text="",
            color=GRAY,
            size_hint_y=None,
            height=dp(28),
            halign="left",
            valign="middle"
        )
        root.add_widget(self.summary)

        self.scroll = ScrollView(
            do_scroll_x=False,
            bar_width=dp(4)
        )

        self.task_list = BoxLayout(
            orientation="vertical",
            size_hint_y=None,
            spacing=dp(8),
            padding=[0, dp(2), 0, dp(10)]
        )
        self.task_list.bind(
            minimum_height=self.task_list.setter("height")
        )

        self.scroll.add_widget(self.task_list)
        root.add_widget(self.scroll)
        self.add_widget(root)

    def on_pre_enter(self, *_):
        if self.app.current_user:
            self.heading.text = (
                f"Tareas de {self.app.current_user['username']}"
            )
            self.refresh_tasks()

    def set_filter(self, status):
        self.filter_status = status
        self.refresh_tasks()

    def open_add_popup(self):
        if not self.app.current_user:
            return

        body = BoxLayout(
            orientation="vertical",
            padding=dp(12),
            spacing=dp(10)
        )

        task_input = make_text_input("Nombre de la tarea")
        body.add_widget(task_input)

        actions = BoxLayout(
            size_hint_y=None,
            height=dp(46),
            spacing=dp(8)
        )

        popup = Popup(
            title="Agregar tarea",
            content=body,
            size_hint=(0.9, None),
            height=dp(190),
            auto_dismiss=False
        )

        def save_task():
            try:
                self.app.db.add_task(
                    self.app.current_user["id"],
                    task_input.text
                )
            except ValueError as error:
                self.app.notify(str(error))
            else:
                popup.dismiss()
                self.new_task_input.text = ""
                self.refresh_tasks()

        actions.add_widget(
            styled_button("Guardar", save_task, GREEN, 44)
        )
        actions.add_widget(
            styled_button("Cancelar", popup.dismiss, GRAY, 44)
        )

        body.add_widget(actions)
        popup.open()

    def refresh_tasks(self):
        self.task_list.clear_widgets()

        if self.app.current_user:
            user_id = self.app.current_user["id"]

            all_tasks = self.app.db.list_tasks(user_id, "all")

            completed = sum(
                1 for task in all_tasks if task["completed"]
            )

            self.summary.text = (
                f"{completed} completadas de {len(all_tasks)} tareas"
            )

            search_query = self.new_task_input.text.strip().lower()

            if search_query:
                tasks = self.app.db.list_tasks(
                    user_id,
                    self.filter_status
                )

                tasks = [
                    task for task in tasks
                    if search_query in task["title"].lower()
                ]

                if tasks:
                    for task in tasks:
                        self.task_list.add_widget(
                            self._task_row(task)
                        )
                else:
                    self.task_list.add_widget(Label(
                        text="No se encontraron tareas.",
                        color=GRAY,
                        size_hint_y=None,
                        height=dp(64),
                        halign="center",
                        valign="middle"
                    ))

    def _task_row(self, task):
        row = BoxLayout(
            orientation="vertical",
            size_hint_y=None,
            height=dp(104),
            spacing=dp(4),
            padding=dp(5)
        )

        title_color = GREEN if task["completed"] else NAVY
        prefix = "✓ " if task["completed"] else "• "

        task_label = Label(
            text=prefix + task["title"],
            color=title_color,
            font_size="15sp",
            halign="left",
            valign="middle"
        )
        task_label.bind(
            size=lambda widget, size: setattr(
                widget, "text_size", (size[0], None)
            )
        )
        row.add_widget(task_label)

        actions = BoxLayout(
            size_hint_y=None,
            height=dp(42),
            spacing=dp(6)
        )

        toggle_text = (
            "Pendiente" if task["completed"] else "Hecha"
        )

        actions.add_widget(styled_button(
            toggle_text,
            lambda task_id=task["id"]: self.toggle_task(task_id),
            GREEN if not task["completed"] else GRAY,
            40
        ))

        actions.add_widget(styled_button(
            "Editar",
            lambda task_id=task["id"], title=task["title"]:
                self.edit_task(task_id, title),
            BLUE,
            40
        ))

        actions.add_widget(styled_button(
            "Eliminar",
            lambda task_id=task["id"]: self.confirm_delete(task_id),
            RED,
            40
        ))

        row.add_widget(actions)
        return row

    def toggle_task(self, task_id):
        user_id = self.app.current_user["id"]
        self.app.db.toggle_task(user_id, task_id)
        self.refresh_tasks()

    def edit_task(self, task_id, current_title):
        body = BoxLayout(
            orientation="vertical",
            padding=dp(12),
            spacing=dp(10)
        )

        edit_input = make_text_input("Nombre de la tarea")
        edit_input.text = current_title
        body.add_widget(edit_input)

        actions = BoxLayout(
            size_hint_y=None,
            height=dp(46),
            spacing=dp(8)
        )

        popup = Popup(
            title="Editar tarea",
            content=body,
            size_hint=(0.9, None),
            height=dp(190),
            auto_dismiss=False
        )

        def save_changes():
            try:
                changed = self.app.db.update_task(
                    self.app.current_user["id"],
                    task_id,
                    edit_input.text
                )
            except ValueError as error:
                self.app.notify(str(error))
                return

            if changed:
                popup.dismiss()
                self.refresh_tasks()
            else:
                popup.dismiss()
                self.app.notify("No se encontró la tarea.")

        actions.add_widget(
            styled_button("Guardar", save_changes, GREEN, 44)
        )
        actions.add_widget(
            styled_button("Cancelar", popup.dismiss, GRAY, 44)
        )

        body.add_widget(actions)
        popup.open()

    def confirm_delete(self, task_id):
        body = BoxLayout(
            orientation="vertical",
            padding=dp(14),
            spacing=dp(12)
        )

        body.add_widget(Label(
            text="¿Eliminar esta tarea? Esta acción no se puede deshacer.",
            color=NAVY,
            halign="center",
            valign="middle"
        ))

        actions = BoxLayout(
            size_hint_y=None,
            height=dp(46),
            spacing=dp(8)
        )

        popup = Popup(
            title="Confirmar eliminación",
            content=body,
            size_hint=(0.9, None),
            height=dp(200),
            auto_dismiss=False
        )

        def delete_now():
            self.app.db.delete_task(
                self.app.current_user["id"],
                task_id
            )
            popup.dismiss()
            self.refresh_tasks()

        actions.add_widget(
            styled_button("Eliminar", delete_now, RED, 44)
        )
        actions.add_widget(
            styled_button("Cancelar", popup.dismiss, GRAY, 44)
        )

        body.add_widget(actions)
        popup.open()


if __name__ == "__main__":
    TareasMovilesApp().run()
