#!/usr/bin/env python3
"""
ZeroVault - Encrypted Notes Application
A secure, local-only notes app with AES encryption
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import time


class ZeroVault:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ZeroVault - Encrypted Notes")
        self.root.geometry("800x600")
        self.root.configure(bg='#2b2b2b')
        
        # Security variables
        self.master_password = None
        self.cipher_suite = None
        self.vault_file = "vault.json"
        self.notes_data = {}
        self.dark_mode = True
        self.last_activity = time.time()
        self.lock_timeout = 300  # 5 minutes in seconds
        
        # Style configuration
        self.setup_styles()
        
        # Start with login screen
        self.show_login_screen()
        
        # Start activity monitor
        self.monitor_activity()
        
    def setup_styles(self):
        """Configure the visual style of the application"""
        style = ttk.Style()
        
        if self.dark_mode:
            # Dark theme colors
            bg_color = '#2b2b2b'
            fg_color = '#ffffff'
            select_bg = '#404040'
            button_bg = '#404040'
        else:
            # Light theme colors
            bg_color = '#ffffff'
            fg_color = '#000000'
            select_bg = '#e0e0e0'
            button_bg = '#f0f0f0'
            
        self.root.configure(bg=bg_color)
        
        # Configure ttk styles
        style.theme_use('clam')
        style.configure('TLabel', background=bg_color, foreground=fg_color)
        style.configure('TButton', background=button_bg, foreground=fg_color)
        style.configure('TEntry', fieldbackground=select_bg, foreground=fg_color)
        style.configure('TFrame', background=bg_color)
        style.configure('Treeview', background=select_bg, foreground=fg_color)
        
    def derive_key_from_password(self, password, salt=None):
        """Derive encryption key from master password using PBKDF2"""
        if salt is None:
            salt = b'zerovault_salt_2024'  # In production, use random salt per user
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
        
    def authenticate(self, password):
        """Authenticate user with master password"""
        try:
            key = self.derive_key_from_password(password)
            cipher = Fernet(key)
            
            # Test decryption with existing data if vault exists
            if os.path.exists(self.vault_file):
                with open(self.vault_file, 'r') as f:
                    data = json.load(f)
                    if 'test_data' in data:
                        # Try to decrypt test data
                        cipher.decrypt(data['test_data'].encode())
            else:
                # Create new vault with test data
                test_encrypted = cipher.encrypt(b"test").decode()
                self.notes_data = {'test_data': test_encrypted, 'notes': {}}
                self.save_vault()
                
            self.master_password = password
            self.cipher_suite = cipher
            return True
            
        except Exception as e:
            return False
            
    def show_login_screen(self):
        """Display the login/authentication screen"""
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create login frame
        login_frame = ttk.Frame(self.root)
        login_frame.pack(expand=True, fill='both', padx=50, pady=50)
        
        # Title
        title_label = ttk.Label(login_frame, text="🔐 ZeroVault", font=('Arial', 24, 'bold'))
        title_label.pack(pady=(0, 10))
        
        subtitle_label = ttk.Label(login_frame, text="Encrypted Notes Application", font=('Arial', 12))
        subtitle_label.pack(pady=(0, 30))
        
        # Password entry
        password_label = ttk.Label(login_frame, text="Master Password:", font=('Arial', 12))
        password_label.pack(pady=(0, 5))
        
        self.password_entry = ttk.Entry(login_frame, show="*", font=('Arial', 12), width=30)
        self.password_entry.pack(pady=(0, 20))
        self.password_entry.bind('<Return>', lambda e: self.handle_login())
        
        # Login button
        login_button = ttk.Button(login_frame, text="Unlock Vault", command=self.handle_login)
        login_button.pack(pady=(0, 10))
        
        # Info text
        info_text = "Enter your master password to access your encrypted notes.\nIf this is your first time, create a new password."
        info_label = ttk.Label(login_frame, text=info_text, font=('Arial', 10), justify='center')
        info_label.pack(pady=(20, 0))
        
        # Focus on password entry
        self.password_entry.focus()
        
    def handle_login(self):
        """Handle login attempt"""
        password = self.password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        if self.authenticate(password):
            self.load_vault()
            self.show_main_interface()
        else:
            messagebox.showerror("Authentication Failed", "Incorrect password or corrupted vault file")
            self.password_entry.delete(0, tk.END)
            
    def load_vault(self):
        """Load and decrypt the vault file"""
        try:
            if os.path.exists(self.vault_file):
                with open(self.vault_file, 'r') as f:
                    encrypted_data = json.load(f)
                    self.notes_data = encrypted_data
            else:
                self.notes_data = {'notes': {}}
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load vault: {str(e)}")
            self.notes_data = {'notes': {}}
            
    def save_vault(self):
        """Save and encrypt the vault file"""
        try:
            with open(self.vault_file, 'w') as f:
                json.dump(self.notes_data, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault: {str(e)}")
            
    def encrypt_text(self, text):
        """Encrypt text using the cipher suite"""
        return self.cipher_suite.encrypt(text.encode()).decode()
        
    def decrypt_text(self, encrypted_text):
        """Decrypt text using the cipher suite"""
        return self.cipher_suite.decrypt(encrypted_text.encode()).decode()
        
    def show_main_interface(self):
        """Display the main application interface"""
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Top frame for title and controls
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill='x', pady=(0, 10))
        
        title_label = ttk.Label(top_frame, text="🔐 ZeroVault - Your Encrypted Notes", font=('Arial', 16, 'bold'))
        title_label.pack(side='left')
        
        # Control buttons
        controls_frame = ttk.Frame(top_frame)
        controls_frame.pack(side='right')
        
        ttk.Button(controls_frame, text="🌙" if self.dark_mode else "☀️", 
                  command=self.toggle_theme, width=3).pack(side='left', padx=2)
        ttk.Button(controls_frame, text="🔒 Lock", command=self.lock_vault).pack(side='left', padx=2)
        
        # Create main content area with two panes
        paned_window = ttk.PanedWindow(main_frame, orient='horizontal')
        paned_window.pack(fill='both', expand=True)
        
        # Left pane - Notes list
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=1)
        
        # Search frame
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(search_frame, text="🔍 Search:").pack(side='left')
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=(5, 0))
        self.search_var.trace('w', self.filter_notes)
        
        # Notes list
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill='both', expand=True)
        
        ttk.Label(list_frame, text="📝 Your Notes:", font=('Arial', 12, 'bold')).pack(anchor='w')
        
        # Treeview for notes list
        self.notes_tree = ttk.Treeview(list_frame, columns=('date',), show='tree headings', height=15)
        self.notes_tree.heading('#0', text='Title', anchor='w')
        self.notes_tree.heading('date', text='Modified', anchor='w')
        self.notes_tree.column('#0', width=200)
        self.notes_tree.column('date', width=100)
        
        # Scrollbar for notes list
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.notes_tree.yview)
        self.notes_tree.configure(yscrollcommand=scrollbar.set)
        
        self.notes_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Bind double-click to open note
        self.notes_tree.bind('<Double-1>', self.open_selected_note)
        
        # Buttons for notes management
        buttons_frame = ttk.Frame(left_frame)
        buttons_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Button(buttons_frame, text="➕ New Note", command=self.create_new_note).pack(side='left', padx=(0, 5))
        ttk.Button(buttons_frame, text="📖 Open", command=self.open_selected_note).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="🗑️ Delete", command=self.delete_selected_note).pack(side='left', padx=5)
        
        # Right pane - Note editor
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=2)
        
        # Note editor header
        editor_header = ttk.Frame(right_frame)
        editor_header.pack(fill='x', pady=(0, 10))
        
        ttk.Label(editor_header, text="✏️ Note Editor:", font=('Arial', 12, 'bold')).pack(side='left')
        
        editor_buttons = ttk.Frame(editor_header)
        editor_buttons.pack(side='right')
        
        ttk.Button(editor_buttons, text="💾 Save", command=self.save_current_note).pack(side='left', padx=2)
        ttk.Button(editor_buttons, text="🆕 Clear", command=self.clear_editor).pack(side='left', padx=2)
        
        # Note title entry
        title_frame = ttk.Frame(right_frame)
        title_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(title_frame, text="Title:").pack(side='left')
        self.title_var = tk.StringVar()
        self.title_entry = ttk.Entry(title_frame, textvariable=self.title_var, font=('Arial', 12))
        self.title_entry.pack(side='left', fill='x', expand=True, padx=(10, 0))
        
        # Note content editor
        self.content_text = scrolledtext.ScrolledText(right_frame, wrap='word', font=('Arial', 11))
        self.content_text.pack(fill='both', expand=True)
        
        # Bind events for activity tracking
        self.bind_activity_events()
        
        # Load and display notes
        self.refresh_notes_list()
        
        # Store current note ID for editing
        self.current_note_id = None
        
    def bind_activity_events(self):
        """Bind events to track user activity"""
        def update_activity(event=None):
            self.last_activity = time.time()
            
        # Bind to various widgets
        self.root.bind('<Motion>', update_activity)
        self.root.bind('<Button>', update_activity)
        self.root.bind('<Key>', update_activity)
        
    def monitor_activity(self):
        """Monitor user activity and lock after timeout"""
        def check_timeout():
            while True:
                if self.master_password and time.time() - self.last_activity > self.lock_timeout:
                    self.root.after(0, self.lock_vault)
                    break
                time.sleep(10)  # Check every 10 seconds
                
        thread = threading.Thread(target=check_timeout, daemon=True)
        thread.start()
        
    def toggle_theme(self):
        """Toggle between dark and light theme"""
        self.dark_mode = not self.dark_mode
        self.setup_styles()
        self.show_main_interface()  # Refresh UI with new theme
        
    def lock_vault(self):
        """Lock the vault and return to login screen"""
        self.master_password = None
        self.cipher_suite = None
        self.notes_data = {}
        messagebox.showinfo("Vault Locked", "Vault has been locked for security")
        self.show_login_screen()
        
    def filter_notes(self, *args):
        """Filter notes list based on search query"""
        search_term = self.search_var.get().lower()
        self.refresh_notes_list(search_term)
        
    def refresh_notes_list(self, search_filter=""):
        """Refresh the notes list display"""
        # Clear existing items
        for item in self.notes_tree.get_children():
            self.notes_tree.delete(item)
            
        # Get notes from vault
        notes = self.notes_data.get('notes', {})
        
        for note_id, encrypted_note in notes.items():
            try:
                # Decrypt note data
                decrypted_data = json.loads(self.decrypt_text(encrypted_note))
                title = decrypted_data.get('title', 'Untitled')
                modified = decrypted_data.get('modified', 'Unknown')
                
                # Apply search filter
                if search_filter and search_filter not in title.lower():
                    continue
                    
                # Add to tree
                self.notes_tree.insert('', 'end', iid=note_id, text=title, values=(modified,))
                
            except Exception as e:
                # Skip corrupted notes
                continue
                
    def create_new_note(self):
        """Create a new note"""
        self.clear_editor()
        self.current_note_id = None
        self.title_entry.focus()
        
    def clear_editor(self):
        """Clear the note editor"""
        self.title_var.set('')
        self.content_text.delete(1.0, tk.END)
        self.current_note_id = None
        
    def open_selected_note(self, event=None):
        """Open the selected note in the editor"""
        selection = self.notes_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a note to open")
            return
            
        note_id = selection[0]
        notes = self.notes_data.get('notes', {})
        
        if note_id in notes:
            try:
                # Decrypt and load note
                decrypted_data = json.loads(self.decrypt_text(notes[note_id]))
                
                self.title_var.set(decrypted_data.get('title', ''))
                self.content_text.delete(1.0, tk.END)
                self.content_text.insert(1.0, decrypted_data.get('content', ''))
                self.current_note_id = note_id
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt note: {str(e)}")
                
    def save_current_note(self):
        """Save the current note in the editor"""
        title = self.title_var.get().strip()
        content = self.content_text.get(1.0, tk.END).strip()
        
        if not title:
            messagebox.showwarning("Missing Title", "Please enter a title for the note")
            return
            
        # Create note data
        note_data = {
            'title': title,
            'content': content,
            'modified': time.strftime('%Y-%m-%d %H:%M:%S'),
            'created': time.strftime('%Y-%m-%d %H:%M:%S') if not self.current_note_id else None
        }
        
        # If editing existing note, preserve creation date
        if self.current_note_id:
            try:
                existing_data = json.loads(self.decrypt_text(self.notes_data['notes'][self.current_note_id]))
                note_data['created'] = existing_data.get('created', note_data['modified'])
            except:
                pass
        else:
            # Generate new note ID
            self.current_note_id = f"note_{int(time.time())}"
            
        # Encrypt and save
        try:
            encrypted_note = self.encrypt_text(json.dumps(note_data))
            
            if 'notes' not in self.notes_data:
                self.notes_data['notes'] = {}
                
            self.notes_data['notes'][self.current_note_id] = encrypted_note
            self.save_vault()
            self.refresh_notes_list()
            
            messagebox.showinfo("Success", f"Note '{title}' saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save note: {str(e)}")
            
    def delete_selected_note(self):
        """Delete the selected note"""
        selection = self.notes_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a note to delete")
            return
            
        note_id = selection[0]
        
        # Get note title for confirmation
        try:
            note_data = json.loads(self.decrypt_text(self.notes_data['notes'][note_id]))
            title = note_data.get('title', 'Unknown')
        except:
            title = 'Unknown'
            
        # Confirm deletion
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{title}'?\n\nThis action cannot be undone."):
            try:
                del self.notes_data['notes'][note_id]
                self.save_vault()
                self.refresh_notes_list()
                
                # Clear editor if this note was being edited
                if self.current_note_id == note_id:
                    self.clear_editor()
                    
                messagebox.showinfo("Success", f"Note '{title}' deleted successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete note: {str(e)}")
                
    def run(self):
        """Start the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
        
    def on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit ZeroVault?"):
            self.root.destroy()


if __name__ == "__main__":
    # Create and run the application
    app = ZeroVault()
    app.run()