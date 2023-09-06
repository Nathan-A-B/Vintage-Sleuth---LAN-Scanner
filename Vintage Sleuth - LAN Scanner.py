import datetime
import subprocess
import tkinter as tk
from tkinter import *
from tkinter import scrolledtext
from mac_vendor_lookup import MacLookup

def update_output():
    # Get the current date and time
    now = datetime.datetime.now()
    # Run the arp -a command and get its output
    output = subprocess.check_output(["arp", "-a"])
    # Format the current date and time as a string
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    # Create the output filename with the timestamp
    filename = f"output_{timestamp}.txt"
    # Add a timestamp to the output
    output_with_timestamp = f"ARP Table ( Printed On: {now.strftime('%H:%M:%S')} )\n{output.decode('ascii')}"
    
    # Get vendor information from MAC addresses
    mac = MacLookup()
    output_lines = []
    for line in output.decode('ascii').split('\n'):
        if 'dynamic' in line:
            mac_address = line.split()[1]
            vendor_name = mac.lookup(mac_address)
            output_lines.append(f"{line} ({vendor_name})")
        else:
            output_lines.append(line)
    
    # Update the output field
    output_field.delete("1.0", tk.END)
    
    # Align the text to the left in the output field
    output_field.tag_configure("left", justify="left")
    output_field.tag_configure("center", justify="center")
    output_field.insert(tk.END, "[Last Updated: ", "center")
    output_field.insert(tk.END, now.strftime('%H:%M:%S'), "center")
    output_field.insert(tk.END, "]\n", "left")
    
    # Add vendor information to each line of the ARP table
    for line in output_lines:
        output_field.insert(tk.END, f"{line}\n", "left")
    
    # Set the font of the text in the output field to Consolas
    output_field.configure(font=("Consolas", 12))
    
    # Call the function again after 10 second
    root.after(5000, update_output)

# Create Window, Set Window Title, Set Window Icon, Set Miminize Icon
root = tk.Tk()
root.title("Vintage Sleuth - LAN Scanner")
root.iconbitmap(default='App Icon.ico')

# Enable Resizing Window
root.resizable(width=True, height=True)

# Create a frame that fills the entire window
frame = tk.Frame(root, bg="black")
frame.pack(fill=tk.BOTH, expand=tk.YES)

# Create a scrolled text widget with a height of 25 and width of 80
output_field = scrolledtext.ScrolledText(frame, height=21, width=80, bg="black", fg="green")
output_field.pack(fill=tk.BOTH, expand=tk.YES)

# Disable editing of the text widget
output_field.bind("<Key>", lambda e: "break")

# Create a grip for dragging the window
grip = tk.Label(root, text="", bg="black", fg="white")
grip.pack(side=tk.TOP, fill=tk.X)

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

# Create a search bar with black background and green foreground
search_bar = tk.Entry(frame, bg="black", fg="green")
search_bar.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)

# Create a search button with black background and green foreground
search_button = tk.Button(frame, text="Highlight", bg="black", fg="green", command=search_text)
search_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.NO)

# Create a tag for highlighting search results
output_field.tag_configure("search", background="green", foreground="black")

# Make the grip draggable
def start_drag(event):
    grip.bind("<B1-Motion>", drag_window)
    grip.bind("<ButtonRelease-1>", stop_drag)
    grip._drag_start_x = event.x_root - root.winfo_x()
    grip._drag_start_y = event.y_root - root.winfo_y()

def drag_window(event):
    x = event.x_root - grip._drag_start_x
    y = event.y_root - grip._drag_start_y
    root.geometry(f"+{x}+{y}")

def stop_drag(event):
    grip.unbind("<B1-Motion>")
    grip.unbind("<ButtonRelease-1>")

grip.bind("<ButtonPress-1>", start_drag)

frame.grid_columnconfigure(0, weight=1)
frame.grid_columnconfigure(1, weight=1)

def on_closing():
    pass

update_output()
root.mainloop()
