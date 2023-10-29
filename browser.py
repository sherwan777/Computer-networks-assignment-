import socket
import ssl
import webbrowser
import tkinter as tk
import threading
from collections import OrderedDict
from admin import AdminPortal

class BrowserGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Browser")
        self.window.geometry("800x600")

        # Create URL entry
        url_frame = tk.Frame(self.window)
        url_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        url_label = tk.Label(url_frame, text="Enter URL:")
        url_label.pack(side=tk.LEFT)
        self.url_entry = tk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
        self.url_entry.bind("<Return>", self.handle_button_click)

        # Create Request button
        self.submit_button = tk.Button(url_frame, text="Request", command=self.handle_button_click)
        self.submit_button.pack(side=tk.LEFT, padx=10)

        # Create View Cache button
        self.cache_button = tk.Button(url_frame, text="View Cache", command=self.view_cache)
        self.cache_button.pack(side=tk.LEFT, padx=10)

        #Admin portal
        self.admin_button = tk.Button(url_frame, text="Admin Portal", command=self.show_admin_interface)
        self.admin_button.pack(side=tk.LEFT, padx=10)

        # Create output text box and scrollbar together
        output_frame = tk.Frame(self.window)
        output_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output_text = tk.Text(output_frame, wrap=tk.WORD)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.config(yscrollcommand=scrollbar.set)

        self.cache_size = 3
        self.cache_algo = 'LRU'
        self.cache = OrderedDict()
        self.admin_password = "admin"
    
    def run(self):
        self.window.mainloop()

    def show_admin_interface(self):
        # Create a new login window
        login_window = tk.Toplevel(self.window)
        login_window.title("Admin Login")
        login_window.geometry("300x100")

        # Create a password entry and submit button
        password_frame = tk.Frame(login_window)
        password_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        password_label = tk.Label(password_frame, text="Enter password:")
        password_label.pack(side=tk.LEFT)
        password_entry = tk.Entry(password_frame, show="*")
        password_entry.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
        password_entry.bind("<Return>", lambda event: submit_password())

        def submit_password():
            # Check if the password is correct
            if password_entry.get() == self.admin_password:
                # Open the admin portal if the password is correct
                login_window.destroy()
                AdminPortal()
            else:
                # Show an error message if the password is incorrect
                tk.messagebox.showerror("Error", "Incorrect password")

        # Create a submit button
        submit_button = tk.Button(password_frame, text="Submit", command=submit_password)
        submit_button.pack(side=tk.LEFT, padx=10)
    
    def handle_button_click(self, event=None):
        # Create a new thread to run the get_request method
        url = self.url_entry.get()
        t = threading.Thread(target=self.get_request, args=(url,))
        t.start()

    def get_request(self, url):
        
        # check the file for blocked website
        if self.is_blocked(url):
            self.show_blocked_message()
            return
        # Check if response is in cache
        elif url in self.cache:
            output_text = f"Status: 200 (OK) (from cache)\n{url}\n\n"
            self.window.after(0, self.update_gui, output_text)
            # Open the response in the default system browser
            webbrowser.open(url)
            return

        # Parse the URL to extract the hostname, port, and path
        try:
            parsed_url = url.split('/')
            hostname = parsed_url[2]
            path = '/' + '/'.join(parsed_url[3:])
            port = 443 if parsed_url[0] == 'https:' else 80
        except:
            self.update_gui("Error: Invalid URL")
            return

        # Check if the response is in the cache
        if url in self.cache:
            # Show the cached response in the GUI
            self.window.after(0, self.update_gui, self.cache[url])
            return

        # Create a socket connection to the server
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((hostname, port))
                if port == 443:
                    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    s = context.wrap_socket(s, server_hostname=hostname)

                # Send a GET request for the specified path
                request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\n\r\n"
                s.sendall(request.encode())

                # Receive the response from the server
                response = b''
                data = s.recv(1000000000)
                response += data
                # output_text = data
                # self.update_gui(output_text)
        except:
            self.update_gui("Error: Unable to establish connection with server\n")
            return

        #Extract the status code from the response
        response = response.decode()
        try:
            status_code = int(response.split()[1])
        except:
            self.update_gui("Error: Invalid server response")
            return

        # Cache the response using LRU or FIFO scheduling algorithm
        if len(self.cache) >= self.cache_size:
            # remove least recently used (LRU) item
            if self.cache_algo == 'LRU':
                self.cache.popitem(last=False)
            # remove first-in-first-out (FIFO) item
            elif self.cache_algo == 'LIFO':
                self.cache.popitem()
        self.cache[url] = response

        # Show the response status and url in the GUI
        output_text = f"Status: {status_code}\n{url}\n\n"
        self.window.after(0, self.update_gui, output_text)

        # Open the response in the default system browser
        webbrowser.open(url)

    def view_cache(self):
        output_text = "\n".join(self.cache.keys())
        if not output_text:
            output_text = "Cache is empty\n\n"
        else:
            self.update_gui("Cached URLs:\n")
        self.update_gui(output_text)
        self.update_gui("\n\n") 
    
    def update_gui(self, output_text):
        self.output_text.configure(state="normal")
        self.output_text.insert(tk.END, output_text)
        self.output_text.configure(state="disabled")

    def is_blocked(self, url):
        # Read the list of blocked URLs from a text file
        with open("blocked_patterns.txt", "r") as file:
            blocked_urls = file.read().splitlines()

        # Check if the given URL matches any of the blocked URLs
        for blocked_url in blocked_urls:
            if blocked_url in url:
                return True
        return False

    def show_blocked_message(self):
        message = "This URL is blocked.\n\n"
        self.output_text.configure(state="normal")
        self.output_text.insert(tk.END, message)
        self.output_text.configure(state="disabled")

if __name__ == '__main__':
    gui = BrowserGUI()
    gui.run()
