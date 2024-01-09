import subprocess
import tkinter as tk
from tkinter import *
from tkinter import scrolledtext
from mac_vendor_lookup import MacLookup

def update_output():
   
    # Run the arp -a command and get its output
    output = subprocess.check_output(["arp", "-a"])

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

    # Update the output field
    output_field.delete("1.0", tk.END)

    # Align the text to the left in the output field
    output_field.tag_configure("left", justify="left")
    output_field.tag_configure("center", justify="center")

    # Add vendor information to each line of the ARP table
    for line in output_lines:
        output_field.insert(tk.END, f"{line}\n", "left")

    # Set the font of the text in the output field to Consolas
    output_field.configure(font=("Consolas", 12))

    # Constant Update
    root.after(1000, update_output)

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
