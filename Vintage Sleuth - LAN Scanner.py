from modules import *

root = tk.Tk()
root.geometry(f"1067x900")
root.title("Vintage Sleuth")

# Enable Resizing Window
root.resizable(width=False, height=False)

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

os.system('cls' if os.name == 'nt' else 'clear')
#######################################################################

# Create a label widget
lbl = tk.Label(root, text='')

# Place the label widget in the top right corner of the window
lbl.place(relx=0.96, rely=0.01, anchor='ne')

# Configure the label widget
lbl.config(justify='left', font=('Consolas', 9), fg='green', bg='black')

# Define a function to update the label widget
def update_label():
    output = subprocess.check_output(['netstat', '-e']).decode('utf-8')
    if output != lbl['text']:
        lbl['text'] = output
    root.after(1000, update_label)

# Create a new thread to run the update_label function
t = threading.Thread(target=update_label)
t.daemon = True
t.start()

#######################################################################

jlbl = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=55, height=15, font=('Consolas', 9), fg='green', bg='black', state=tk.DISABLED, highlightbackground='black', borderwidth=0, yscrollcommand=None, xscrollcommand=None)
jlbl.place(relx=1.0, rely=0.35, anchor='ne')
jlbl.insert(tk.END, "")

jlbl.bind("<Control-v>", lambda e: "break")
jlbl.bind("<Button-3><ButtonRelease-3>", lambda e: "break")

def get_arp_table():
    result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def tracert(ip_address, jlbl):
    result = subprocess.run(['tracert', ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    results_text = f"{result.stdout.split('Tracing route to')[1].replace('=', '')}\n"
    results_text = '\n'.join(results_text.split('\n')[:-2])
    jlbl.config(state=tk.NORMAL)
    jlbl.insert(tk.END, results_text)
    jlbl.delete("end-2c", tk.END)
    jlbl.config(state=tk.DISABLED)

def tracert_all(jlbl):
    try:
        arp_table = get_arp_table()
        ip_addresses = [line.split()[0] for line in arp_table.splitlines() if 'dynamic' in line.lower()]

        # Re-enable the scrolled text widget
        jlbl.config(state=tk.NORMAL)

        threads = []
        for ip_address in ip_addresses:
            t = threading.Thread(target=tracert, args=(ip_address, jlbl))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Disable the scrolled text widget after adding text
        jlbl.config(state=tk.DISABLED)
    except Exception as e:
        print(f"An error occurred: {e}")
        jlbl.config(state=tk.DISABLED)
        jlbl.insert(tk.END, f"An error occurred: {e}")

t = threading.Thread(target=tracert_all, args=(jlbl,))
t.start()

#######################################################################

# Initialize a variable to store the previous output
previous_output = ""

def update_output():
    global previous_output

    try:
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
                except Exception as e:
                    output_lines.append(line + f" Error: {e}")
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

            # Disable pasting into the text field
            output_field.bind("<Control-v>", lambda e: "break")

    except Exception as e:
        # Update the output field with the error message
        output_field.delete("1.0", tk.END)
        output_field.insert(tk.END, f"Error: {e}", "left")
        output_field.configure(font=("Consolas", 10, "bold"), foreground="red")

    # Constant Update Every Second
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
copy_button = tk.Button(frame, text="Copy All", bg="black", fg="green", command=copy_all)
copy_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.NO)

# Create a tag for highlighting search results
output_field.tag_configure("search", background="green", foreground="black")

# Create a thread for the search function
search_thread = threading.Thread(target=search_text)

# Start the thread when the search button is clicked
search_button.config(command=search_thread.start)

#######################################################################

ping_process = None

def ping_device(packet_size, ping_count):
    global ping_process
    ip_address = ip_entry.get()
    ping_process = subprocess.Popen(f"ping -n {ping_count} -l {packet_size} {ip_address}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    while True:
        if ping_process.poll() is not None:  
            break
        output = ping_process.stdout.readline().decode('utf-8')
        if output == '':
            break
        frank.config(state="normal")
        frank.insert(tk.END, output, "unique_tag")
        frank.config(state="disabled")
    ping_process = None  

def stop_ping_device():
    global ping_process
    if ping_process:
        ping_process.kill()
        button.config(state="normal")  
        stop_button.config(state="disabled")
        ping_process = None  

def ping_thread(packet_size, ping_count):
    ping_device(packet_size, ping_count)
    button.config(state="normal")

def ping_wrapper():
    packet_size = packet_size_entry.get()
    ping_count = ping_count_entry.get()
    button.config(state="disabled")
    stop_button.config(state="normal")  
    frank.config(state="disabled")
    threading.Thread(target=ping_thread, args=(packet_size, ping_count)).start()

# Create a frame to hold the entry widget, button, and text widget
frame = tk.Frame(root, width=200, height=50)
frame.pack(fill=tk.BOTH, expand=False)
frame.configure(bg="black")

# Create a button to perform the ping operation
button = tk.Button(frame, text="Ping", font="Consolas 10", fg="green", bg="black", command=ping_wrapper)
button.grid(row=0, column=3, padx=5, pady=0, sticky='e')

# Create a button to stop the ping operation
stop_button = tk.Button(frame, text="Stop Ping", font="Consolas 10", fg="green", bg="black", command=stop_ping_device)
stop_button.place(x=565, y=64.47)

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

## Create a text widget to display the ping status
frank = tk.Text(frame, font="Consolas 10", fg="green", bg="black", name="frank", height=10, width=50)
frank.grid(row=0, column=4, padx=0, pady=0, sticky="ew")
frank.configure(state='disable')

# Enable autoscrolling
frank.see("end")

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

def print_devices():
    nearby_devices = bluetooth.discover_devices()
    table_data = []
    for mac_address in nearby_devices:
        device_name = bluetooth.lookup_name(mac_address)
        table_data.append([device_name, mac_address])

    # Clear the text widget and insert the device information
    text.delete("1.0", tk.END)
    text.insert(tk.END, f"{'Device Name:':<30}{'MAC Address:':<20}\n")
    for row in table_data:
        text.insert(tk.END, f"{row[0]:<30}{row[1]:<20}\n")

    # Enable the Bluetooth button after the scan is complete
    button21.configure(state='normal')

def start_scan():
    # Disable the Bluetooth button before starting the scan thread
    button21.configure(state='disabled')

    # Create a new thread to run the print_devices() function
    scan_thread = threading.Thread(target=print_devices)

    # Start the thread
    scan_thread.start()

# Create a frame to hold the buttons and table
root.configure(bg="black")
frame = tk.Frame(root)
frame.pack()
frame.configure(bg="black")

button21 = tk.Button(frame, text="Bluetooth Scan", font="Consolas 10", fg="green", bg="black", command=start_scan)
button21.pack(side=tk.LEFT, pady=4.5, padx=5)

# Create a text widget to display the device information
text = scrolledtext.ScrolledText(frame, font="Consolas 10", fg="green", bg="black")
text.pack(fill=tk.BOTH, expand=True)
text.configure(height=10, width=50)

###########################################################

def search_text():
    global text
    text.tag_remove("found", "1.0", tk.END)
    search_string = search_entry.get()
    try:
        if search_string:
            pattern = re.compile(search_string, re.IGNORECASE)
            matches = pattern.finditer(text.get("1.0", tk.END))
            for match in matches:
                start = match.start()
                end = match.end()
                text.tag_add("found", f"1.0+{start}c", f"1.0+{end}c")
                text.tag_config("found", background="green", foreground="black")
            text.see("1.0")
    except Exception as e:
        print(f"An error occurred: {e}")

# Create a copy button
copy_button = tk.Button(frame, text="Copy All", command=lambda: root.clipboard_append(text.get("1.0", tk.END)), font="Consolas 10", fg="green", bg="black")
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

def spoof_mac():
    try:
        target_ip = Lip_entry.get()
        new_mac = mac_entry.get()

        # Fetching local IP address
        local_ip = socket.gethostbyname_ex(socket.gethostname())[2][0]
        messagebox.showinfo("Your IP Address", f"Your current IP address: {local_ip}")

        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=new_mac)
        send(arp_request)

        messagebox.showinfo("Success", "MAC spoofing successful!")
    except Exception as e:
        messagebox.showerror("Error", f"Error: {e}")

# Create a Frame with black background
frame = Frame(root, bg="black")
frame.place(x=3, y=800)

# Labels with green font and Consolas font family
Label(frame, text="Target IP:", bg="black", fg="green", font=("Consolas", 10)).grid(row=0, column=0)
Label(frame, text="New MAC:", bg="black", fg="green", font=("Consolas", 10)).grid(row=1, column=0)

# Entry widgets with green font and Consolas font family
Lip_entry = Entry(frame, font=("Consolas", 10), fg="green", bg="black")
mac_entry = Entry(frame, font=("Consolas", 10), fg="green", bg="black")

Lip_entry.grid(row=0, column=1)
mac_entry.grid(row=1, column=1)

# Spoof button with green font and Consolas font family, placed next to the entry widgets
spoof_button = Button(frame, text="Spoof MAC", command=spoof_mac, font=("Consolas", 8), fg="green", bg="black")
spoof_button.grid(row=0, column=2, padx=10)

# Clear fields button with green font and Consolas font family, placed next to the entry widgets
def clear_fields():
    Lip_entry.set('')
    mac_entry.set('')

clear_button = Button(frame, text="Clear Fields", command=clear_fields, font=("Consolas", 8), fg="green", bg="black")
clear_button.grid(row=0, column=3, padx=2.5)

###########################################################

update_output()
root.mainloop()


