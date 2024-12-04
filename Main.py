import os
import json
import random
import string
import logging
import joblib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from ttkthemes import ThemedTk
import pandas as pd
import time
import math
import sys

logging.basicConfig(filename='password_checker.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class PasswordStrengthGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("ML-based Password Strength Analyzer")
        self.master.geometry("550x500")
        self.master.set_theme("black")

        main_frame = ttk.Frame(self.master, padding=20)
        main_frame.pack(fill="both", expand=True)

        self.title_label = ttk.Label(main_frame, text="Password Strength Analyzer", font=("Helvetica", 16, "bold"))
        self.title_label.pack(pady=(0, 10))

        self.label = ttk.Label(main_frame, text="Enter password:", font=("Helvetica", 12))
        self.label.pack(anchor="w", pady=5)

        self.password_entry = ttk.Entry(main_frame, show="*", width=30, font=("Helvetica", 10))
        self.password_entry.pack(pady=(0, 10))
        self.password_entry.bind('<KeyRelease>', self.check_password)

        self.show_password_var = tk.BooleanVar()
        self.show_password_checkbutton = ttk.Checkbutton(
            main_frame, text="Show Password", variable=self.show_password_var, command=self.toggle_password)
        self.show_password_checkbutton.pack(anchor="w")

        self.progress = ttk.Progressbar(main_frame, length=300, mode='determinate')
        self.progress.pack(pady=10)

        self.result_label = ttk.Label(main_frame, text="", font=("Helvetica", 10, "italic"))
        self.result_label.pack(pady=(10, 5))

        self.suggestion_label = ttk.Label(main_frame, text="", font=("Helvetica", 10))
        self.suggestion_label.pack(pady=5)

        self.crack_time_label = ttk.Label(main_frame, text="", font=("Helvetica", 10, "italic"))
        self.crack_time_label.pack(pady=5)

        self.generate_button = ttk.Button(main_frame, text="Generate Strong Password", command=self.generate_password)
        self.generate_button.pack(pady=(15, 5))

        self.export_button = ttk.Button(main_frame, text="Export Results", command=self.export_results)
        self.export_button.pack(pady=(15, 15))

        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=5)

        self.results = []

        try:
            self.model = self.load_model()
        except Exception as e:
            logging.error(f"Error loading model: {str(e)}")
            messagebox.showerror("Model Error", "Failed to load the password strength classifier model.")
            self.model = None

    def load_model(self):
        try:
            if getattr(sys, 'frozen', False):  # If running as a bundled executable
                bundle_dir = sys._MEIPASS
                model_path = os.path.join(bundle_dir, "NewModelRF_v2.joblib")
            else:  # If running as a script
                script_dir = os.path.dirname(os.path.abspath(__file__))
                model_path = os.path.join(script_dir, "NewModelRF_v2.joblib")

            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found at {model_path}")

            model = joblib.load(model_path)
            return model
        except Exception as e:
            logging.error(f"Error loading model: {str(e)}")
            raise

    def smooth_update_progress(self, target_value):
        current_value = self.progress['value']
        increment = (target_value - current_value) / 20.0

        def update_progress():
            nonlocal current_value
            current_value += increment
            if (increment > 0 and current_value < target_value) or (increment < 0 and current_value > target_value):
                self.progress['value'] = current_value
                self.master.after(10, update_progress)
            else:
                self.progress['value'] = target_value

        update_progress()

    def extract_features(self, password):
        common_passwords_file = 'common_passwords.csv'
        if not hasattr(self, 'common_passwords'):
            if os.path.exists(common_passwords_file):
                self.common_passwords = set(pd.read_csv(common_passwords_file)['password'].tolist())
            else:
                self.common_passwords = set()

        is_common_password = 1 if password in self.common_passwords else 0 
        
        length = len(password)
        
        has_uppercase = sum(1 for c in password if c.isupper())
        has_lowercase = sum(1 for c in password if c.islower())
        has_digits = sum(1 for c in password if c.isdigit())
        has_special = sum(1 for c in password if c in string.punctuation)
        has_unique_chars = len(set(password))
        has_entropy = has_unique_chars / length if length > 0 else 0
        has_sequential = sum(1 for i in range(len(password) - 1) if ord(password[i + 1]) == ord(password[i]) + 1)
        has_repetition = sum(1 for i in range(len(password) - 1) if password[i + 1] == password[i])
        
        return [length, has_uppercase, has_lowercase, has_digits, has_special, has_unique_chars, has_entropy, has_sequential, has_repetition , is_common_password]

    def refined_estimate_crack_time(self, password):
        char_space = 0
        if any(c.islower() for c in password):
            char_space += 26
        if any(c.isupper() for c in password):
            char_space += 26
        if any(c.isdigit() for c in password):
            char_space += 10
        if any(c in string.punctuation for c in password):
            char_space += len(string.punctuation)

        password_length = len(password)
        entropy = password_length * (math.log2(char_space) if char_space > 0 else 0)

        cracking_speed = 1e10  # Assumed speed of 10 billion guesses per second

        total_combinations = 2 ** entropy
        crack_time = total_combinations / cracking_speed

        if crack_time < 60:
            return f"{crack_time:.2f} seconds"
        elif crack_time < 3600:
            return f"{crack_time / 60:.2f} minutes"
        elif crack_time < 86400:
            return f"{crack_time / 3600:.2f} hours"
        elif crack_time < 31536000:
            return f"{crack_time / 86400:.2f} days"
        else:
            return f"{crack_time / 31536000:.2f} years"

    def check_password(self, event=None):
        password = self.password_entry.get()
        if not password:
            self.result_label.config(text="Please enter a password.")
            self.smooth_update_progress(0)
            self.crack_time_label.config(text="")
            self.suggestion_label.config(text="")
            return

        features = self.extract_features(password)

        feature_names = ["length", "has_uppercase", "has_lowercase", "has_digits", "has_special", 
                        "has_unique_chars", "has_entropy", "has_sequential", "has_repetition", "is_common_password"]

        features_df = pd.DataFrame([features], columns=feature_names)

        try:
            strength_prediction = self.model.predict(features_df)[0]
            strength_map = {"weak": "Weak", "moderate": "Moderate", "strong": "Strong", "very strong": "Very Strong"}
            strength = strength_map.get(str(strength_prediction).lower(), "Unknown")
        except Exception as e:
            logging.error(f"Prediction error: {str(e)}")
            messagebox.showerror("Model Error", f"Prediction error: {str(e)}")
            strength = "Error"

        # Calculate strength percentage
        max_strength = 0
        if features[1] > 0: max_strength += 10  # Uppercase
        if features[2] > 0: max_strength += 10  # Lowercase
        if features[3] > 0: max_strength += 10  # Digits
        if features[4] > 0: max_strength += 10  # Special characters
        if features[5] > 0: max_strength += 10  # Unique characters
        if features[6] > 0.5: max_strength += 10  # High entropy
        if features[7] == 0: max_strength += 5  # No sequential patterns
        if features[8] == 0: max_strength += 5  # No repetitions
        if features[0] >= 12: max_strength += 15  # Good length
        if features[0] >= 16: max_strength += 15  # Very strong length

        strength_percentage = min(max_strength, 100)

        if strength_percentage >= 85:
            strength = "Very Strong"
        elif strength_percentage >= 70:
            strength = "Strong"
        elif strength_percentage >= 45:
            strength = "Moderate"
        else:
            strength = "Weak"

        # Update progress bar and strength labels
        self.smooth_update_progress(strength_percentage)
        self.result_label.config(text=f"Password Strength: {strength}")
        self.crack_time_label.config(text=f"Estimated Crack Time: {self.refined_estimate_crack_time(password)}")
        self.suggestion_label.config(text=f"Strength: {strength_percentage}%")

        # Provide suggestions
        suggestions = []
        if features[0] < 12:
            suggestions.append("Increase the length to at least 12 characters.")
        if features[1] == 0:
            suggestions.append("Add uppercase letters.")
        if features[2] == 0:
            suggestions.append("Add lowercase letters.")
        if features[3] == 0:
            suggestions.append("Include digits.")
        if features[4] == 0:
            suggestions.append("Use special characters (e.g., @, #, $).")
        if features[7] > 0:
            suggestions.append("Avoid sequential patterns (e.g., '123' or 'abc').")
        if features[8] > 0:
            suggestions.append("Reduce repeated characters (e.g., 'aaa').")
        if features[9] == 1:
            suggestions.append("Avoid using common passwords.")

        # Append suggestions to the suggestion label
        if suggestions:
            suggestion_text = "Suggestions:\n" + "\n".join(f"- {s}" for s in suggestions)
        else:
            suggestion_text = "Your password is strong! No changes needed."

        # Show suggestions and percentage together
        self.suggestion_label.config(text=f"Strength: {strength_percentage}%\n{suggestion_text}")

        self.results.append({
            "password": password,
            "strength": strength,
            "percentage": strength_percentage,
            "estimated_crack_time": self.refined_estimate_crack_time(password)
        })



    def toggle_password(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def generate_password(self):
        length = random.randint(12, 16)
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.check_password()

    def export_results(self):
        if not self.results:
            messagebox.showerror("Export Error", "No password data available to export.")
            return

        last_result = self.results[-1]
        password = last_result.get("password", "")
        strength = last_result.get("strength", "")

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Save Results As"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(f"Password: {password}\n")
                    f.write(f"Strength: {strength}\n")
                messagebox.showinfo("Export Successful", "Results exported successfully!")
            except Exception as e:
                logging.error(f"Error exporting results: {str(e)}")
                messagebox.showerror("Export Error", f"Error exporting results: {str(e)}")

if __name__ == "__main__":
    root = ThemedTk()
    app = PasswordStrengthGUI(root)
    root.mainloop()
