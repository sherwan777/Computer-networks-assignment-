import tkinter as tk
import re

class AdminPortal:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Admin Portal")
        self.window.geometry("500x400")

        # Create URL entry
        url_frame = tk.Frame(self.window)
        url_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        url_label = tk.Label(url_frame, text="Enter URL pattern to block:")
        url_label.pack(side=tk.LEFT)
        self.url_entry = tk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, expand=tk.YES, fill=tk.X)
        self.url_entry.bind("<Return>", self.handle_add_button_click)

        # Create Add button
        self.add_button = tk.Button(url_frame, text="Add", command=self.handle_add_button_click)
        self.add_button.pack(side=tk.LEFT , padx=10)

        # Create Remove button
        self.remove_button = tk.Button(url_frame, text="Remove", command=self.handle_remove_button_click)
        self.remove_button.pack(side=tk.LEFT , padx=10)

        # Create output text box and scrollbar
        output_frame = tk.Frame(self.window)
        output_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output_text = tk.Text(output_frame, wrap=tk.WORD)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.config(yscrollcommand=scrollbar.set)

        # Load the current blocking rules
        self.load_blocking_rules()

    def run(self):
        self.window.mainloop()

    def show_error_message(self):
        message = "Wrong password entered.\n\n"
        self.output_text.configure(state="normal")
        self.output_text.insert(tk.END, message)
        self.output_text.configure(state="disabled")

    def load_blocking_rules(self):
        try:
            with open("blocked_patterns.txt", "r") as f:
                blocked_patterns = f.read().splitlines()
                self.output_text.insert(tk.END, f"Current blocking rules:\n{blocked_patterns}\n")
        except FileNotFoundError:
            self.output_text.insert(tk.END, "No blocking rules found.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error loading blocking rules: {str(e)}\n")

    def save_blocking_rules(self, blocked_patterns):
        try:
            with open("blocked_patterns.txt", "w") as f:
                f.write("\n".join(blocked_patterns))
        except Exception as e:
            self.output_text.insert(tk.END, f"Error saving blocking rules: {str(e)}\n")

    def handle_add_button_click(self, event=None):
        try:
            pattern = self.url_entry.get()
            if pattern:
                with open("blocked_patterns.txt", "a") as f:
                    f.write(pattern + "\n")
                self.output_text.insert(tk.END, f"Added blocking rule: {pattern}\n")
                self.url_entry.delete(0, tk.END)
        except Exception as e:
            self.output_text.insert(tk.END, f"Error adding blocking rule: {str(e)}\n")

    def handle_remove_button_click(self, event=None):
        pattern = self.url_entry.get()
        if pattern:
            try:
                with open("blocked_patterns.txt", "r") as f:
                    blocked_patterns = f.read().splitlines()
                if any(re.match(pattern, url) for url in blocked_patterns):
                    blocked_patterns.remove(pattern)
                    self.save_blocking_rules(blocked_patterns)
                    self.output_text.insert(tk.END, f"Removed blocking rule: {pattern}\n")
                else:
                    self.output_text.insert(tk.END, f"Blocking rule not found: {pattern}\n")
            except FileNotFoundError:
                self.output_text.insert(tk.END, "No blocking rules found.\n")
            except Exception as e:
                self.output_text.insert(tk.END, f"Error occurred while removing blocking rule: {e}\n")
        else:
            self.output_text.insert(tk.END, "Please enter a URL pattern to remove.\n")
