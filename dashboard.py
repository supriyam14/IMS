import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk

# Database initialization
def initialize_db():
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE,
                      password TEXT)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT,
                      quantity INTEGER,
                      price REAL)''')

    conn.commit()
    conn.close()

# User authentication
def register_user(username, password):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def authenticate_user(username, password):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()

    conn.close()
    return user is not None

# Product management
def add_product(name, quantity, price):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    cursor.execute('INSERT INTO products (name, quantity, price) VALUES (?, ?, ?)', (name, quantity, price))
    conn.commit()
    conn.close()

def edit_product(product_id, name=None, quantity=None, price=None):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    if name is not None:
        cursor.execute('UPDATE products SET name = ? WHERE id = ?', (name, product_id))
    if quantity is not None:
        cursor.execute('UPDATE products SET quantity = ? WHERE id = ?', (quantity, product_id))
    if price is not None:
        cursor.execute('UPDATE products SET price = ? WHERE id = ?', (price, product_id))

    conn.commit()
    conn.close()

def delete_product(product_id):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()

def low_stock_alert(threshold):
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM products WHERE quantity < ?', (threshold,))
    low_stock_products = cursor.fetchall()

    conn.close()
    return low_stock_products

# GUI Application
class InventoryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Inventory Management System")
        self.current_user = None

        self.create_widgets()
        self.initialize_db()

    def create_widgets(self):
        # Main frame for login
        self.login_frame = tk.Frame(self.root, bg='#f0f8ff')
        self.login_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        tk.Label(self.login_frame, text="Username", bg='#f0f8ff', font=('Arial', 12)).grid(row=0, column=0, pady=5)
        tk.Label(self.login_frame, text="Password", bg='#f0f8ff', font=('Arial', 12)).grid(row=1, column=0, pady=5)

        self.username_entry = tk.Entry(self.login_frame, font=('Arial', 12))
        self.password_entry = tk.Entry(self.login_frame, show='*', font=('Arial', 12))

        self.username_entry.grid(row=0, column=1, pady=5, padx=10)
        self.password_entry.grid(row=1, column=1, pady=5, padx=10)

        tk.Button(self.login_frame, text="Login", command=self.login, bg='#4CAF50', fg='white', font=('Arial', 12)).grid(row=2, column=0, columnspan=2, pady=10, padx=10)
        tk.Button(self.login_frame, text="Register", command=self.register, bg='#008CBA', fg='white', font=('Arial', 12)).grid(row=3, column=0, columnspan=2, pady=10, padx=10)

    def initialize_db(self):
        initialize_db()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if authenticate_user(username, password):
            self.current_user = username
            messagebox.showinfo("Login", "Login successful")
            self.login_frame.pack_forget()
            self.show_inventory()
        else:
            messagebox.showerror("Login", "Invalid credentials")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if register_user(username, password):
            messagebox.showinfo("Register", "Registration successful")
        else:
            messagebox.showerror("Register", "Username already exists")

    def show_inventory(self):
        # Main frame for inventory management
        self.inventory_frame = tk.Frame(self.root, bg='#f0f8ff')
        self.inventory_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        tk.Label(self.inventory_frame, text="Product Name", bg='#f0f8ff', font=('Arial', 12)).grid(row=0, column=0, pady=5)
        tk.Label(self.inventory_frame, text="Quantity", bg='#f0f8ff', font=('Arial', 12)).grid(row=0, column=1, pady=5)
        tk.Label(self.inventory_frame, text="Price", bg='#f0f8ff', font=('Arial', 12)).grid(row=0, column=2, pady=5)

        self.name_entry = tk.Entry(self.inventory_frame, font=('Arial', 12))
        self.quantity_entry = tk.Entry(self.inventory_frame, font=('Arial', 12))
        self.price_entry = tk.Entry(self.inventory_frame, font=('Arial', 12))

        self.name_entry.grid(row=1, column=0, pady=5, padx=10)
        self.quantity_entry.grid(row=1, column=1, pady=5, padx=10)
        self.price_entry.grid(row=1, column=2, pady=5, padx=10)

        tk.Button(self.inventory_frame, text="Add Product", command=self.add_product, bg='#4CAF50', fg='white', font=('Arial', 12)).grid(row=2, column=0, columnspan=3, pady=10, padx=10)
        tk.Button(self.inventory_frame, text="Edit Product", command=self.edit_product, bg='#FFC107', fg='white', font=('Arial', 12)).grid(row=3, column=0, columnspan=3, pady=10, padx=10)
        tk.Button(self.inventory_frame, text="Delete Product", command=self.delete_product, bg='#f44336', fg='white', font=('Arial', 12)).grid(row=4, column=0, columnspan=3, pady=10, padx=10)
        tk.Button(self.inventory_frame, text="View Low Stock", command=self.view_low_stock, bg='#2196F3', fg='white', font=('Arial', 12)).grid(row=5, column=0, columnspan=3, pady=10, padx=10)

        self.products_tree = ttk.Treeview(self.inventory_frame, columns=("ID", "Name", "Quantity", "Price"), show='headings', style='Treeview')
        self.products_tree.heading("ID", text="ID")
        self.products_tree.heading("Name", text="Name")
        self.products_tree.heading("Quantity", text="Quantity")
        self.products_tree.heading("Price", text="Price")
        self.products_tree.grid(row=6, column=0, columnspan=3, pady=10, padx=10, sticky='nsew')

        style = ttk.Style()
        style.configure("Treeview", background="#ffffff", foreground="black", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", background="#2196F3", foreground="white")

        self.load_products()

    def load_products(self):
        for item in self.products_tree.get_children():
            self.products_tree.delete(item)

        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM products')
        products = cursor.fetchall()
        conn.close()

        for product in products:
            self.products_tree.insert('', tk.END, values=product)

    def add_product(self):
        name = self.name_entry.get()
        try:
            quantity = int(self.quantity_entry.get())
            price = float(self.price_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Quantity must be an integer and price must be a number")
            return

        add_product(name, quantity, price)
        self.load_products()
        self.name_entry.delete(0, tk.END)
        self.quantity_entry.delete(0, tk.END)
        self.price_entry.delete(0, tk.END)

    def edit_product(self):
        selected_item = self.products_tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "No product selected")
            return

        product_id = self.products_tree.item(selected_item)['values'][0]
        name = self.name_entry.get()
        try:
            quantity = int(self.quantity_entry.get())
            price = float(self.price_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Quantity must be an integer and price must be a number")
            return

        edit_product(product_id, name, quantity, price)
        self.load_products()
        self.name_entry.delete(0, tk.END)
        self.quantity_entry.delete(0, tk.END)
        self.price_entry.delete(0, tk.END)

    def delete_product(self):
        selected_item = self.products_tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "No product selected")
            return

        product_id = self.products_tree.item(selected_item)['values'][0]
        delete_product(product_id)
        self.load_products()

    def view_low_stock(self):
        threshold = 10  # Example threshold
        low_stock_products = low_stock_alert(threshold)

        if not low_stock_products:
            messagebox.showinfo("Low Stock", "No low stock items.")
            return

        report_window = tk.Toplevel(self.root)
        report_window.title("Low Stock Alert")
        report_window.configure(bg='#f0f8ff')

        tk.Label(report_window, text="ID", bg='#f0f8ff', font=('Arial', 12)).grid(row=0, column=0, pady=5)
        tk.Label(report_window, text="Name", bg='#f0f8ff', font=('Arial', 12)).grid(row=0, column=1, pady=5)
        tk.Label(report_window, text="Quantity", bg='#f0f8ff', font=('Arial', 12)).grid(row=0, column=2, pady=5)

        for i, product in enumerate(low_stock_products):
            tk.Label(report_window, text=product[0], bg='#f0f8ff', font=('Arial', 12)).grid(row=i+1, column=0, pady=5)
            tk.Label(report_window, text=product[1], bg='#f0f8ff', font=('Arial', 12)).grid(row=i+1, column=1, pady=5)
            tk.Label(report_window, text=product[2], bg='#f0f8ff', font=('Arial', 12)).grid(row=i+1, column=2, pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = InventoryApp(root)
    root.mainloop()
