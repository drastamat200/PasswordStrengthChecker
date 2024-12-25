import tkinter as tk
from tkinter import ttk
import re
import math
from typing import Dict, List
from collections import Counter

class PasswordStrengthTester:
    # [Previous PasswordStrengthTester class code remains the same...]
    def __init__(self):
        self.common_passwords = {
            "password", "123456", "qwerty", "admin", "welcome",
            "letmein", "monkey", "dragon", "baseball", "abc123",
        }
        
        self.keyboard_patterns = [
            "qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty",
        ]

    def calculate_entropy(self, password: str) -> float:
        if not password:
            return 0.0
        
        frequencies = Counter(password)
        length = len(password)
        return -sum(count/length * math.log2(count/length) 
                   for count in frequencies.values())

    def check_keyboard_pattern(self, password: str) -> bool:
        lowercase_pwd = password.lower()
        for pattern in self.keyboard_patterns:
            if pattern in lowercase_pwd:
                return True
        return False

    def check_repeated_sequences(self, password: str) -> List[str]:
        sequences = []
        for i in range(len(password)-2):
            for j in range(i+3, len(password)+1):
                sequence = password[i:j]
                if password.count(sequence) > 1:
                    sequences.append(sequence)
        return sorted(sequences, key=len, reverse=True)

    def analyze_password(self, password: str) -> Dict:
        results = {
            'strength': 0,
            'length': len(password),
            'issues': [],
            'suggestions': [],
            'entropy': 0.0,
            'complexity_score': 0
        }
        
        if len(password) < 8:
            results['issues'].append("Password is too short (minimum 8 characters)")
        elif len(password) < 12:
            results['suggestions'].append("Consider using a longer password (12+ characters recommended)")
        
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        complexity_score = sum([
            has_upper * 26,
            has_lower * 26,
            has_digit * 10,
            has_special * 32
        ])
        results['complexity_score'] = complexity_score
        
        if not has_upper:
            results['issues'].append("Missing uppercase letters")
        if not has_lower:
            results['issues'].append("Missing lowercase letters")
        if not has_digit:
            results['issues'].append("Missing numbers")
        if not has_special:
            results['issues'].append("Missing special characters")
            
        if password.lower() in self.common_passwords:
            results['issues'].append("Password is commonly used and easily guessable")
            
        if self.check_keyboard_pattern(password):
            results['issues'].append("Contains keyboard pattern")
            
        repeated = self.check_repeated_sequences(password)
        if repeated:
            results['issues'].append(f"Contains repeated sequences: {', '.join(repeated[:3])}")
            
        results['entropy'] = self.calculate_entropy(password)
        
        base_strength = min(100, max(0, (
            (len(password) * 4) +
            (has_upper * 15) +
            (has_lower * 15) +
            (has_digit * 15) +
            (has_special * 15) +
            (results['entropy'] * 10)
        )))
        
        penalties = len(results['issues']) * 10
        results['strength'] = max(0, base_strength - penalties)
        
        if results['strength'] >= 80:
            results['rating'] = "Very Strong"
        elif results['strength'] >= 60:
            results['rating'] = "Strong"
        elif results['strength'] >= 40:
            results['rating'] = "Moderate"
        else:
            results['rating'] = "Weak"
            
        if results['entropy'] < 3.0:
            results['suggestions'].append("Increase password randomness")
        if complexity_score < 50:
            results['suggestions'].append("Use a wider variety of characters")
            
        return results

class PasswordStrengthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Tester")
        self.root.geometry("600x700")
        self.root.configure(bg='#f0f0f0')
        
        self.password_tester = PasswordStrengthTester()
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            self.main_frame,
            text="Password Strength Analyzer",
            font=('Helvetica', 16, 'bold')
        )
        title_label.pack(pady=10)
        
        # Password entry frame
        entry_frame = ttk.Frame(self.main_frame)
        entry_frame.pack(fill=tk.X, pady=10)
        
        self.password_var = tk.StringVar()
        self.password_var.trace_add('write', self.on_password_change)
        
        ttk.Label(entry_frame, text="Enter Password:").pack(side=tk.LEFT)
        self.password_entry = ttk.Entry(
            entry_frame,
            textvariable=self.password_var,
            show="•"
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Show/Hide password button
        self.show_password = tk.BooleanVar()
        self.toggle_btn = ttk.Checkbutton(
            entry_frame,
            text="Show",
            variable=self.show_password,
            command=self.toggle_password_visibility
        )
        self.toggle_btn.pack(side=tk.LEFT)
        
        # Strength meter frame
        meter_frame = ttk.LabelFrame(self.main_frame, text="Strength Meter", padding=10)
        meter_frame.pack(fill=tk.X, pady=10)
        
        self.strength_var = tk.DoubleVar()
        self.strength_meter = ttk.Progressbar(
            meter_frame,
            variable=self.strength_var,
            maximum=100,
            length=200,
            mode='determinate'
        )
        self.strength_meter.pack(pady=5)
        
        self.strength_label = ttk.Label(meter_frame, text="Strength: 0%")
        self.strength_label.pack()
        
        # Details frame
        details_frame = ttk.LabelFrame(self.main_frame, text="Password Analysis", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create text widget for details
        self.details_text = tk.Text(
            details_frame,
            height=15,
            width=50,
            wrap=tk.WORD,
            font=('Courier', 10)
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar for details
        scrollbar = ttk.Scrollbar(details_frame, command=self.details_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.details_text.configure(yscrollcommand=scrollbar.set)
        
        # Make text widget read-only
        self.details_text.configure(state='disabled')
        
    def toggle_password_visibility(self):
        self.password_entry.configure(
            show="" if self.show_password.get() else "•"
        )
        
    def on_password_change(self, *args):
        password = self.password_var.get()
        if not password:
            self.strength_var.set(0)
            self.strength_label.configure(text="Strength: 0%")
            self.details_text.configure(state='normal')
            self.details_text.delete(1.0, tk.END)
            self.details_text.configure(state='disabled')
            return
            
        results = self.password_tester.analyze_password(password)
        
        # Update strength meter
        self.strength_var.set(results['strength'])
        self.strength_label.configure(
            text=f"Strength: {results['strength']}% ({results['rating']})"
        )
        
        # Update details text
        self.details_text.configure(state='normal')
        self.details_text.delete(1.0, tk.END)
        
        self.details_text.insert(tk.END, f"Length: {results['length']} characters\n")
        self.details_text.insert(tk.END, f"Entropy: {results['entropy']:.2f}\n")
        self.details_text.insert(
            tk.END,
            f"Character Space Size: {results['complexity_score']}\n\n"
        )
        
        if results['issues']:
            self.details_text.insert(tk.END, "Issues Found:\n")
            for issue in results['issues']:
                self.details_text.insert(tk.END, f"❌ {issue}\n")
            self.details_text.insert(tk.END, "\n")
            
        if results['suggestions']:
            self.details_text.insert(tk.END, "Suggestions:\n")
            for suggestion in results['suggestions']:
                self.details_text.insert(tk.END, f"💡 {suggestion}\n")
                
        self.details_text.configure(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthGUI(root)
    root.mainloop()