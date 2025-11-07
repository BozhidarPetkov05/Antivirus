import tkinter as tk
from tkinter import filedialog
from tkinter import *
import os
import yara

def choose_folder():
    global folder_selected
    global dir_textbox
    folder = filedialog.askdirectory()
    if folder:
        folder_selected = folder
        # dir_textbox.config(state="normal")  # enable writing
        dir_textbox.delete(0, tk.END)  # clear old text
        dir_textbox.insert(tk.END, folder)  # insert new path
        # dir_textbox.config(state="disabled")
        print("Selected folder:", folder_selected)


def scan_folder():
    global dir_textbox
    global scanned_files
    folder_to_scan = dir_textbox.get()

    scanned_files.insert(tk.END, folder_to_scan + "\n")

    infected_files = []

    rules = ""



root = tk.Tk()

root.geometry("1000x600")
#root.resizable(False, False)

root.title("Window Title")

#icon = tk.PhotoImage(file="icon.png")
#root.iconphoto(False, icon)

folder_selected = ''

dir_label = tk.Label(root, text="Selected Folder:", font=("", 14))
dir_label.pack(pady=15)

dir_textbox = tk.Entry(root, width=100, font=("", 13))
dir_textbox.pack()

select_dir_btn = Button(root,
                        text='Select Folder',
                        width=25, height=3,
                        font=("", 12),
                        command=choose_folder, )
select_dir_btn.pack(pady=10)

scan_btn = Button(root, text='SCAN', font=("", 13), width=25, height=3, command=scan_folder)
scan_btn.pack(pady=30)

frame = tk.Frame(root)
frame.pack(pady=10)

scanned_files = Text(frame, width=100, height=15, font=("", 13))
scanned_files.pack(side=tk.LEFT)

scroll_bar = tk.Scrollbar(frame)
scroll_bar.pack(side=tk.RIGHT, fill=tk.Y)

scanned_files.config(yscrollcommand=scroll_bar.set)
scroll_bar.config(command=scanned_files.yview)

root.mainloop()