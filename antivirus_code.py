import tkinter as tk
from tkinter import filedialog
from tkinter import *
import os
import threading
import yara

def choose_folder():
    global folder_selected
    folder = filedialog.askdirectory()
    if folder:
        folder_selected = folder
        dir_textbox.delete(0, tk.END)
        dir_textbox.insert(tk.END, folder)
        print("Selected folder:", folder_selected)

def scan_folder_thread():
    thread = threading.Thread(target=scan_folder)
    thread.start()

def scan_folder():
    folder_to_scan = dir_textbox.get()
    if not folder_to_scan:
        scanned_files.insert(tk.END, "No folder selected!\n")
        return

    scanned_files.insert(tk.END, f"\nScanning folder: {folder_to_scan}\n")
    scanned_files.see(tk.END)
    scanned_files.update()

    infected_files = []

    rules_path = os.path.abspath(r"C:\Users\XidZ01\Desktop\Software Engineering\2nd Course 1st Semester\Information and communication security\Antivirus\YARA Rules\rules.yara")
    rules = yara.compile(filepath=rules_path)

    scanned_files.tag_config("infected", foreground="red")
    scanned_files.tag_config("clean", foreground="green")

    for dir_name, subdirs, file_names in os.walk(folder_to_scan):
        scanned_files.insert(tk.END, f"Scanning directory: {dir_name}\n")
        scanned_files.see(tk.END)
        scanned_files.update()

        for name in file_names:
            file_path = os.path.abspath(os.path.join(dir_name, name))
            if os.path.normcase(file_path) == os.path.normcase(rules_path):
                try:
                    matches = rules.match(file_path)
                    if matches:
                        result = f"[INFECTED] {file_path}\n"
                        infected_files.append(file_path)
                        scanned_files.insert(tk.END, result, "infected")
                    else:
                        result = f"[OK] {file_path}\n"
                        scanned_files.insert(tk.END, result)

                    scanned_files.see(tk.END)
                    scanned_files.update()

                except yara.Error as e:
                    scanned_files.insert(tk.END, f"[Skipped: {e}] {file_path}\n")
                except PermissionError:
                    scanned_files.insert(tk.END, f"[Permission denied] {file_path}\n")

    scanned_files.insert(tk.END, "\nSCAN COMPLETED\n")
    if  len(infected_files) > 0:
        scanned_files.insert(tk.END, f"Total infected: {len(infected_files)}\n", "infected")
    else:
        scanned_files.insert(tk.END, f"Total infected: {len(infected_files)}\n", "clean")

    scanned_files.insert(tk.END, "\n".join(infected_files) + "\n", "infected")
    scanned_files.see(tk.END)


root = tk.Tk()
root.geometry("1000x600")
root.title("Antivirus")

dir_label = tk.Label(root, text="Selected Folder:", font=("", 14))
dir_label.pack(pady=15)

dir_textbox = tk.Entry(root, width=100, font=("", 13))
dir_textbox.pack()

select_dir_btn = Button(root, text='Select Folder', width=25, height=3, font=("", 12), command=choose_folder)
select_dir_btn.pack(pady=10)

scan_btn = Button(root, text='SCAN', font=("", 13), width=25, height=3, command=scan_folder_thread)
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
