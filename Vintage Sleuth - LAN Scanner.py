# Python Interpretor - Python 3.10.6 64-Bit 
from mac_vendor_lookup import MacLookup
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import *
import tkinter as tk
import subprocess
import threading
import bluetooth
import ctypes
import socket
import getmac
import os
import re
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

# Create Window, Set Window Title, Set Window Icon, Set Miminize Icon
root = tk.Tk()
root.geometry(f"1067x900")
root.title("Vintage Sleuth")
root.iconbitmap(default='Icon.ico')

# Ask for admin privileges
run_as_admin()

# Enable Resizing Window
root.resizable(width=False, height=True)

# Create a frame that fills the entire window
frame = tk.Frame(root, bg="black")
frame.pack(fill=tk.BOTH, expand=tk.YES)

# Create a scrolled text widget with a height of 25 and width of 80
output_field = scrolledtext.ScrolledText(frame, height=21, width=20, bg="black", fg="green")
output_field.pack(fill=tk.BOTH, expand=tk.YES)

# Disable editing of the text widget
output_field.bind("<Key>", lambda e: "break")

# Allow copying and pasting of text within the text widget
output_field.bind("<Control-c>", lambda e: output_field.clipboard_append(output_field.selection_get()))
output_field.bind("<Control-v>", lambda e: output_field.insert(INSERT, output_field.clipboard_get()))

# Create a grip for dragging the window
grip = tk.Label(root, text="", bg="black", fg="white")
grip.pack(side=tk.TOP, fill=tk.X)

########################################################################

# Initialize a variable to store the previous output
previous_output = ""

def update_output():
    global previous_output

    # Run the arp -a command and get its output
    output = subprocess.check_output(["arp", "-a", "-v"]) 

    # Get vendor information from MAC addresses
    mac = MacLookup()
    output_lines = []
    for line in output.decode('ascii').split('\n'):
        if 'dynamic' in line:
            mac_address = line.split()[1]
            try:
                vendor_name = mac.lookup(mac_address)
                output_lines.append(f"{line} ({vendor_name})")
            except:
                output_lines.append(line)
        else:
            output_lines.append(line)

    # Check if the output has changed
    new_output = "\n".join(output_lines)
    if new_output != previous_output:
        # Update the output field
        output_field.delete("1.0", tk.END)

        # Align the text to the left in the output field
        output_field.tag_configure("left", justify="left")
        output_field.tag_configure("center", justify="center")

        # Add vendor information to each line of the ARP table
        for line in output_lines:
            output_field.insert(tk.END, f"{line}\n", "left")

        # Set the font of the text in the output field to Consolas
        output_field.configure(font=("Consolas", 10))

        # Update the previous output
        previous_output = new_output

    # Constant Update
    root.after(1000, update_output)

# Create a new thread to run the update_output function
thread = threading.Thread(target=update_output)
thread.start()

#######################################################################

def search_text():
    # Get the search term from the search bar
    search_term = search_bar.get()

    # Check if the input is empty
    if not search_term:
        return

    # Search for the term in the text widget
    start_index = "1.0"
    while True:
        # Search for the next occurrence of the search term
        index = output_field.search(search_term, start_index, stopindex=tk.END)

        # If no more occurrences are found, stop searching
        if not index:
            break

        # Highlight the occurrence of the search term
        end_index = f"{index}+{len(search_term)}c"
        output_field.tag_add("search", index, end_index)

        # Update the start index for the next search
        start_index = end_index

def copy_all():
    # Copy all the text in the output field to the clipboard
    output_field.clipboard_clear()
    output_field.clipboard_append(output_field.get("1.0", tk.END))

# Create a search bar with black background and green foreground
search_bar = tk.Entry(frame, bg="black", fg="green")
search_bar.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)

# Create a search button with black background and green foreground
search_button = tk.Button(frame, text="Highlight", bg="black", fg="green", command=search_text)
search_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.NO)

# Create a clear highlight button with black background and green foreground
clear_button = tk.Button(frame, text="Clear", bg="black", fg="green", command=lambda: output_field.tag_remove("search", "1.0", tk.END))
clear_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.NO)

# Create a copy all button with black background and green foreground
copy_button = tk.Button(frame, text="Copy", bg="black", fg="green", command=copy_all)
copy_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.NO)

# Create a tag for highlighting search results
output_field.tag_configure("search", background="green", foreground="black")

#######################################################################

def ping_device(packet_size, ping_count):
    ip_address = ip_entry.get()
    ping_process = subprocess.Popen(f"ping -n {ping_count} -l {packet_size} {ip_address}", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ping_output, ping_error = ping_process.communicate()
    ping_status = ping_output.decode('utf-8') + ping_error.decode('utf-8')

    # Clear the text widget and insert the ping status
    frank.delete("1.0", tk.END)
    frank.insert(tk.END, ping_status, "unique_tag")

def ping_thread(packet_size, ping_count):
    ping_device(packet_size, ping_count)
    button.config(state="normal")

def ping_wrapper():
    packet_size = packet_size_entry.get()
    ping_count = ping_count_entry.get()
    button.config(state="disabled")
    threading.Thread(target=ping_thread, args=(packet_size, ping_count)).start()

# Create a frame to hold the entry widget, button, and text widget
frame = tk.Frame(root, width=200, height=50)
frame.pack(fill=tk.BOTH, expand=False)
frame.configure(bg="black")

###############################################

# Create an entry widget to accept the IP address with a width of 20 characters
ip_entry = tk.Entry(frame, font="Consolas 10", fg="green", bg="black", width=18)
ip_entry.bind("<FocusIn>", lambda args: ip_entry.delete('0', 'end') if ip_entry.get() == "IP Address" else None)
ip_entry.bind("<FocusOut>", lambda args: ip_entry.insert(0, "IP Address") if ip_entry.get() == "" else None)
ip_entry.insert(0, "IP Address")
ip_entry.grid(row=0, column=0, padx=5, pady=0)

# Create an entry widget to accept the packet size
packet_size_entry = tk.Entry(frame, font="Consolas 10", fg="green", bg="black", width=18)
packet_size_entry.insert(0, "Packet Size")
packet_size_entry.bind("<FocusIn>", lambda event: packet_size_entry.delete('0', 'end') if packet_size_entry.get() == "Packet Size" else None)
packet_size_entry.bind("<FocusOut>", lambda event: packet_size_entry.insert(0, "Packet Size") if packet_size_entry.get() == "" else None)
packet_size_entry.grid(row=0, column=1, padx=5, pady=0)

# Create an entry widget to accept the number of pings
ping_count_entry = tk.Entry(frame, font="Consolas 10", fg="green", bg="black", width=18)
ping_count_entry.insert(0, "Packet Amount")
ping_count_entry.bind("<FocusIn>", lambda event: ping_count_entry.delete('0', 'end') if ping_count_entry.get() == "Packet Amount" else None)
ping_count_entry.bind("<FocusOut>", lambda event: ping_count_entry.insert(0, "Packet Amount") if ping_count_entry.get() == "" else None)
ping_count_entry.grid(row=0, column=2, padx=5, pady=0)

###############################################

# Create a button to perform the ping operation
button = tk.Button(frame, text="Ping", font="Consolas 10", fg="green", bg="black", command=ping_wrapper)
button.grid(row=0, column=3, padx=5, pady=0, sticky='e') 

# Create a text widget to display the ping status
frank = tk.Text(frame, font="Consolas 10", fg="green", bg="black", name="frank", height=10, width=50)
frank.grid(row=0, column=4, padx=0, pady=0, sticky="ew")
frank.configure(state='normal')

# Create a scrollbar widget and set its command option to the yview method of the text widget
scroll = tk.Scrollbar(frame, command=frank.yview)
scroll.grid(row=0, column=5, sticky='ns')

# Set the yscrollcommand option of the text widget to the set method of the scrollbar widget
frank['yscrollcommand'] = scroll.set

# Add a unique tag to the text widget
frank.tag_configure("unique_tag", foreground="green")

# Configure the row and column to expand
frame.grid_rowconfigure(0, weight=1)
frame.grid_columnconfigure(3, weight=1)

###############################################

# Create a tag for highlighting search results
output_field.tag_configure("search", background="green", foreground="black")

frame = tk.Frame(root, bg="black")
frame.pack(side=tk.LEFT, pady=0, fill=tk.BOTH, expand=True)

###############################################

# Create an entry widget for the hostname
entry1 = tk.Entry(frame, font="Consolas 10", fg="green", bg="black", width=18)
entry1.pack(side=tk.LEFT, pady=0, padx=5)

# Set the default value of the entry widget to the current hostname
entry1.insert(0, socket.gethostname())

# Create an entry widget for the IP address
entry2 = tk.Entry(frame, font="Consolas 10", fg="green", bg="black", width=18)
entry2.pack(side=tk.LEFT, pady=0, padx=5)

# Set the default value of the entry widget to the current IP address
entry2.insert(0, socket.gethostbyname(socket.gethostname()))

# Create an entry widget for the MAC address
entry3 = tk.Entry(frame, font="Consolas 10", fg="green", bg="black", width=18)
entry3.pack(side=tk.LEFT, pady=0, padx=5)

# Set the default value of the entry widget to the current MAC address
entry3.insert(0, getmac.get_mac_address())

###############################################

frame.configure(bg='black')

def validate_device_name(device_name):
    # Device name should only contain alphanumeric characters and hyphens
    return bool(re.match("^[a-zA-Z0-9-]*$", device_name))

def validate_ip_address(ip_address):
    # IP address should be a valid IPv4 address
    import socket
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

def validate_mac_address(mac_address):
    # MAC address should be a valid MAC address
    return bool(re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address))

def update_device_info():
    # Update the device name
    new_device_name = entry1.get()
    if not validate_device_name(new_device_name):
        messagebox.showerror("Error", "Invalid device name")
        return
    try:
        os.system(f'netdom renamecomputer %computername% /newname:{new_device_name}')
    except Exception as e:
        print(f"Error occurred while updating device name: {e}")

    # Update the IP address
    new_ip_address = entry2.get()
    if not validate_ip_address(new_ip_address):
        messagebox.showerror("Error", "Invalid IP address")
        return
    try:
        os.system(f'netsh interface ipv4 set address name="Ethernet" static {new_ip_address} 255.255.255.0 192.168.1.1')
    except Exception as e:
        print(f"Error occurred while updating IP address: {e}")

    # Update the MAC address
    new_mac_address = entry3.get()
    if not validate_mac_address(new_mac_address):
        messagebox.showerror("Error", "Invalid MAC address")
        return
    try:
        os.system(f'getmac /s localhost /v /fo list | findstr /c:"Physical Address" /r /n > mac.txt')
        with open('mac.txt', 'r') as f:
            mac_list = f.readlines()
        mac_index = int(mac_list[0].split(':')[0]) - 1
        os.system(f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}" /v "NetworkAddress" /d "{new_mac_address}" /f')
        os.system('del mac.txt')
    except Exception as e:
        print(f"Error occurred while updating MAC address: {e}")

# Create a button to update the device information
button1 = tk.Button(frame, text="Modify Information", font="Consolas 10", fg="green", bg="black", command=update_device_info)
button1.pack(side=tk.LEFT, pady=0, padx=10)

###########################################################

def print_devices():
    nearby_devices = bluetooth.discover_devices()
    table_data = []
    for mac_address in nearby_devices:
        device_name = bluetooth.lookup_name(mac_address)
        table_data.append([device_name, mac_address])

    # Create a table to display the device information
    table = tk.Frame(frame)
    table.pack(fill=tk.BOTH, expand=True)
    table.configure(bg="black")

    # Make the table not editable but copyable
    table.bind("<Button-1>", lambda event: table.focus_set())
    table.bind("<Control-c>", lambda event: root.clipboard_append(table.selection_get()))

    # Clear the text widget and insert the device information
    text.delete("1.0", tk.END)
    text.insert(tk.END, f"{'Device Name:':<30}{'MAC Address:':<20}\n")
    for row in table_data:
        text.insert(tk.END, f"{row[0]:<30}{row[1]:<20}\n")

    # Set the text state to disabled
    text.configure(state='disabled')

    # Bind the mouse click to a function that sets the focus on the text
    text.bind("<1>", lambda event: text.focus_set())

    # Enable the Bluetooth button after the scan is complete
    button2.configure(state='normal')

def start_scan():
    # Disable the Bluetooth button before starting the scan thread
    button2.configure(state='disabled')

    # Create a new thread to run the print_devices() function
    scan_thread = threading.Thread(target=print_devices)

    # Start the thread
    scan_thread.start()

# Create a frame to hold the buttons and table
frame = tk.Frame(root)
frame.pack()
frame.configure(bg="black")

button2 = tk.Button(frame, text="Bluetooth Scan", font="Consolas 10", fg="green", bg="black", command=start_scan)
button2.pack(side=tk.LEFT, pady=0, padx=5)

# Create a text widget to display the device information
text = scrolledtext.ScrolledText(frame, font="Consolas 10", fg="green", bg="black")
text.pack(fill=tk.BOTH, expand=True)
text.configure(height=10, width=800)

def search_text():
    global text
    text.tag_remove("found", "1.0", tk.END)
    search_string = search_entry.get()
    if search_string:
        idx = "1.0"
        while True:
            idx = text.search(search_string, idx, nocase=1, stopindex=tk.END)
            if not idx:
                break
            last_idx = f"{idx}+{len(search_string)}c"
            text.tag_add("found", idx, last_idx)
            text.tag_config("found", background="green", foreground="black")
            idx = last_idx
        text.see(idx)

# Create a copy button
copy_button = tk.Button(frame, text="Copy", command=lambda: root.clipboard_append(text.get("1.0", tk.END)), font="Consolas 10", fg="green", bg="black")
copy_button.pack(side=tk.RIGHT)

# Create a clear highlight button
clear_highlight_button = tk.Button(frame, text="Clear", command=lambda: text.tag_remove("found", "1.0", tk.END), font="Consolas 10", fg="green", bg="black")
clear_highlight_button.pack(side=tk.RIGHT)

# Create a highlight button
highlight_button = tk.Button(frame, text="Highlight", command=search_text, font="Consolas 10", fg="green", bg="black")
highlight_button.pack(side=tk.RIGHT)

# Create an entry widget to search for text in the text widget
search_entry = tk.Entry(frame)
search_entry.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
search_entry.configure(bg='black', fg='green', font='Consolas 10')

###########################################################

update_output()
root.mainloop()
