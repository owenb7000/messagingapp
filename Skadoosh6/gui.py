import tkinter
import customtkinter
from tkinter import simpledialog
import logging
from config import Config
from contactsystem import ContactManager
from messagehistory import HistoryManager
from networking import NetworkInfo
import threading
from pathlib import Path


# main GUI
class GUI(customtkinter.CTk):

    def __init__(self, config: Config, contact_manager: ContactManager, message_manager: HistoryManager,
                 net_info: NetworkInfo, bosh) -> None:
        """
        Initialize the GUI.
        """
        self.config = config
        self.contact_manager = contact_manager
        self.message_manager = message_manager
        self.net_info = net_info
        self.bosh = bosh
        self.logger = logging.getLogger(f"{__name__}.GUI")
        self.logger.debug("init GUI")
        super().__init__()

        # setup main window
        self.title("Skadoosh!")
        self.geometry(f"{1000}x{500}")
        customtkinter.set_appearance_mode(config.theme)
        customtkinter.set_widget_scaling(config.scaling)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # configuring grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # sidebar
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        # logo
        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Skadoosh!",
                                                 font=customtkinter.CTkFont(size=30, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Sidebar widgets
        self.contact_label = customtkinter.CTkLabel(self.sidebar_frame, text=("Contacts"),
                                                    font=("Consolas", 18), )
        self.contact_label.grid(row=1, column=0)
        self.contact_selector = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                            values=contact_manager.get_contact_names(),
                                                            command=self.contact_selector_event,
                                                            font=("Consolas", 20), )
        self.contact_selector.grid(row=2, column=0, padx=20, pady=0)

        self.new_contact_input = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text=("Add By IP"),
                                                        font=("Consolas", 16), )
        self.new_contact_input.bind("<Return>", command=self.add_contact_event)
        self.new_contact_input.grid(row=3, column=0, pady=10)

        self.info_panel = customtkinter.CTkFrame(self.sidebar_frame)
        self.info_panel.grid(row=4, column=0, sticky="nesw", padx=(20, 20), pady=(10, 10))

        self.info_log = customtkinter.CTkLabel(self.info_panel, text="", anchor="w", justify="left", font=("Arial", 13),
                                               wraplength=140)
        self.info_log.grid(row=0, column=0, padx=(5, 5), pady=(5, 5))

        self.ip_display = customtkinter.CTkLabel(self.sidebar_frame,
                                                 text=f"🌐 {net_info.public_ipv4}\n🏠 {net_info.private_ipv4}",
                                                 font=("Consolas", 16), )
        self.ip_display.grid(row=5, column=0)

        self.setting_label = customtkinter.CTkLabel(self.sidebar_frame, text=("Settings"),
                                                    font=("Consolas", 18), )
        self.setting_label.grid(row=7, column=0)

        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                                       values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event,
                                                                       font=("Consolas", 16), )
        self.appearance_mode_optionemenu.grid(row=8, column=0, padx=20, pady=0)

        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                               values=["0.8", "0.9", "1.0", "1.1", "1.2", "1.3"],
                                                               command=self.change_scaling_event,
                                                               font=("Consolas", 16), )
        self.scaling_optionemenu.grid(row=10, column=0, padx=20, pady=(10, 20))

        # Message field and send button
        self.message_entry = customtkinter.CTkEntry(self, placeholder_text="....")
        self.message_entry.grid(row=3, column=1, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nesw")
        self.message_entry.bind('<Return>', command=self.send_button_event)
        self.message_entry.bind('<space>', command=self.add_emojis)

        self.upload_button = customtkinter.CTkButton(self, fg_color="transparent", border_width=2,
                                                     text_color=("gray10", "#DCE4EE"), text="➕", width=5,
                                                     command=self.upload_button_event, )
        self.upload_button.grid(row=3, column=2, padx=(5, 5), pady=(20, 20), sticky="nsew")

        self.send_button = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2,
                                                   text_color=("gray10", "#DCE4EE"), font=("Consolas", 16),
                                                   text=("Send"),
                                                   command=self.send_button_event)
        self.send_button.grid(row=3, column=3, padx=(0, 20), pady=(20, 20), sticky="nsew")

        # Message display area
        self.message_display = customtkinter.CTkScrollableFrame(self, width=250)
        self.message_display.grid(row=0, column=1, padx=(20, 20), pady=(20, 0), sticky="nsew", columnspan=3, rowspan=3)

        self.content = customtkinter.CTkLabel(self.message_display, text="", font=("Consolas", 24), anchor="w",
                                              justify="left")
        self.content.grid(row=0, column=0)

        # Default values
        self.appearance_mode_optionemenu.set(f"{config.theme}")
        self.scaling_optionemenu.set(f"{config.scaling}")
        self.contact_selector.set('None')

    def on_close(self) -> None:
        self.destroy()

    def contact_selector_event(self, event) -> None:
        self.update_message_display()

    def update_contact_selector(self) -> None:
        self.contact_selector.configure(values=self.contact_manager.get_contact_names(), require_redraw=True)

    def add_contact_event(self, event) -> None:
        ip = self.new_contact_input.get()
        threading.Thread(target=self.bosh.send_intro, args=(ip,)).start()
        self.new_contact_input.delete(0, tkinter.END)

    def change_appearance_mode_event(self, event) -> None:
        new_theme = self.appearance_mode_optionemenu.get()
        self.config.theme = new_theme
        customtkinter.set_appearance_mode(new_theme)
        pass

    def change_scaling_event(self, event) -> None:
        scaling_factor = float(self.scaling_optionemenu.get())
        self.config.scaling = scaling_factor
        customtkinter.set_widget_scaling(scaling_factor)

    def send_button_event(self, *args) -> None:
        contact_name = self.contact_selector.get()
        message_content = self.message_entry.get()

        threading.Thread(target=self.bosh.send_str_message, args=(contact_name, message_content)).start()
        self.message_entry.delete(0, tkinter.END)

    def upload_button_event(self) -> None:
        contact_name = self.contact_selector.get()
        file_path = Path(tkinter.filedialog.askopenfilename())

        threading.Thread(target=self.bosh.send_file_message, args=(contact_name, file_path)).start()

    def add_emojis(self) -> None:
        pass

    def log(self, message_to_log) -> None:
        old_text = self.info_log.cget("text")
        new_text = message_to_log + "\n" + old_text
        self.info_log.configure(text=new_text, require_redraw=True)

    def update_message_display(self) -> None:
        """
        Update the message display to show latest messags
        """
        contact = self.contact_selector.get()
        self.logger.debug("updating message on GUI")

        text = ""

        # appends message onto text var
        for message in self.message_manager.get_messages(contact):
            if message.sent_by_me:
                text += f"{'☑' if message.confirmed else '☐'}"
            else:
                text += f"☑"
            text += f"{'Me' if message.sent_by_me else contact}: {message.content}\n"

        self.content.configure(text=text, require_redraw=True)  # replaces old message text with updated version
        self.message_display.update_idletasks()  # makes sure it is ready to scroll
        self.message_display._parent_canvas.yview_moveto(1.0)  # scrolls to bottom


def get_username() -> str:
    user_name = simpledialog.askstring("Username", "Enter username:")

    if user_name:
        return user_name
    else:
        return None
