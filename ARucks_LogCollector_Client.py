# Andrew Rucks
# 4/16/2026
# REMOTE WINDOWS SECURITY EVENT LOG COLLECTOR - CLIENT SIDE

# Requests the most recent Windows event logs (security) from a listening server using a socket.
# To use, start the program and fill out the information asked. The server program must already be running.
# Both the client and the server can be ran on the same machine using the loopback address.

import socket
import tkinter as tk
from tkinter import ttk
from tkinter import font
import csv
import io
import getpass
import ARucks_SimpleCrypto as simplecrypto

DEFAULT_HOST = "127.0.0.1"  # loopback
DEFAULT_PORT = 12345  # custom port
BUFFER_SIZE = 102400 # 100kb

symmetric_key = ""
port = DEFAULT_PORT
host = DEFAULT_HOST
logs_gathered = ""

# MAIN FUNCTION
def main():
    port = input("Input the port number to use, or hit Enter to use default (12345): ")
    if port == "":
        port = DEFAULT_PORT
    else:
        port = int(port)

    host = input("Input the IP address of the server, or hit Enter to use default (127.0.0.1): ")
    if host == "":
        host = DEFAULT_HOST

    symmetric_key = getpass.getpass("Input your decryption key (must be the same as the server's key): ")
    logs_gathered = request_logs()
    print("Logs received. Opening window to view...")
    display_csv_table(logs_gathered)
    return


# CONNECTS TO SERVER AND RECIEVES LOGS
def request_logs():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        data = sock.recv(BUFFER_SIZE)

        return simplecrypto.decrypt(data, symmetric_key, 10)


# OPENS GRAPHICAL WINDOW WITH CSV TABLE - MOSTLY VIBECODED
def display_csv_table(csv_text):
    def normalize_cell(text):
        return str(text).replace("\r\n", "\n").replace("\n", " ⏎ ").replace("\t", "  ")

    # Parse CSV
    csv_file = io.StringIO(csv_text.strip())
    reader = csv.reader(csv_file)
    raw_rows = [row for row in reader if any(cell.strip() for cell in row)]

    if not raw_rows:
        raise ValueError("CSV data is empty or invalid")

    columns = [col if col else f"Column{i}" for i, col in enumerate(raw_rows[0])]
    raw_data = raw_rows[1:]

    root = tk.Tk()
    root.title("Most Recent Security Logs from " + host)
    root.geometry("900x450")

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)

    tree = ttk.Treeview(frame, columns=columns, show="headings")

    # scrollbars
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

    vsb.pack(side="right", fill="y")
    hsb.pack(side="bottom", fill="x")
    tree.pack(side="left", fill="both", expand=True)

    # store full (unmodified) data for tooltip lookup
    full_data = []

    # sorting
    sort_directions = {col: False for col in columns}

    def try_float(val):
        try:
            return float(val)
        except:
            return val.lower() if isinstance(val, str) else val

    def sort_column(col):
        sort_directions[col] = not sort_directions[col]
        reverse = sort_directions[col]

        data = [(tree.set(k, col), k) for k in tree.get_children("")]
        data.sort(key=lambda t: try_float(t[0]), reverse=reverse)

        for index, (_, k) in enumerate(data):
            tree.move(k, "", index)

    # setup columns
    for col in columns:
        tree.heading(col, text=col, anchor="w", command=lambda c=col: sort_column(c))
        tree.column(col, anchor="w", width=100, minwidth=80)

    # insert data
    for row in raw_data:
        padded = row + [""] * (len(columns) - len(row))
        full_data.append(padded)

        cleaned = [normalize_cell(cell) for cell in padded]
        tree.insert("", "end", values=cleaned)

    root.update_idletasks()

    # autofit
    tree_font = font.nametofont("TkDefaultFont")

    for col in columns:
        max_width = tree_font.measure(col)

        for row_id in tree.get_children():
            cell = str(tree.set(row_id, col))
            max_width = max(max_width, tree_font.measure(cell))

        tree.column(col, width=max(max_width + 20, 80))

    # TOOLTIPS
    tooltip = tk.Toplevel(root)
    tooltip.withdraw()
    tooltip.overrideredirect(True)

    tooltip_label = tk.Label(
        tooltip,
        text="",
        justify="left",
        background="#ffffe0",
        relief="solid",
        borderwidth=1,
        font=("TkDefaultFont", 10)
    )
    tooltip_label.pack(ipadx=5, ipady=3)

    def show_tooltip(event):
        region = tree.identify("region", event.x, event.y)
        if region != "cell":
            tooltip.withdraw()
            return

        row_id = tree.identify_row(event.y)
        col_id = tree.identify_column(event.x)

        if not row_id or not col_id:
            tooltip.withdraw()
            return

        row_index = tree.index(row_id)
        col_index = int(col_id.replace("#", "")) - 1

        try:
            full_text = full_data[row_index][col_index]
        except IndexError:
            tooltip.withdraw()
            return

        if not full_text or "\n" not in full_text:
            tooltip.withdraw()
            return

        tooltip_label.config(text=full_text)

        # position tooltip near cursor
        x = root.winfo_pointerx() + 10
        y = root.winfo_pointery() + 10
        tooltip.geometry(f"+{x}+{y}")
        tooltip.deiconify()

    def hide_tooltip(event):
        tooltip.withdraw()

    tree.bind("<Motion>", show_tooltip)
    tree.bind("<Leave>", hide_tooltip)

    root.mainloop()


if __name__ == "__main__":
    main() #start
