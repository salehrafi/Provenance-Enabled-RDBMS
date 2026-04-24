# Provenance-Enabled-RDBMS
Provenance-Enabled Relational Database for E-Commerce 

A Provenance-Enabled Relational Database Management System (RDBMS) designed for a simulated e-commerce scenario. This project captures the *why*, *where*, and *how* of data evolution over time using a normalized relational schema, dedicated audit tables, and SQL triggers, requiring zero modifications to the application code.

## 🚀 Features
* **Automated Auditing:** Uses SQL triggers to automatically record every DML operation (INSERT, UPDATE, DELETE) into append-only audit tables.
* **Provenance Queries:** Pre-built queries to analyze *Why-Provenance* (e.g., why an order total is a specific amount), *Where-Provenance* (e.g., price history), and *How-Provenance* (e.g., order lifecycle).
* **Interactive Web GUI:** A lightweight, single-page web application built with Python Flask to easily explore database tables, view provenance queries, and run custom SQL.

## 🛠️ Technology Stack
* **Database:** Oracle SQL (Production), SQLite 3 (Development).
* **Backend:** Python 3 + Flask.
* **Frontend:** HTML5, CSS3, JavaScript.
* **Schema Migration:** SQL Scripts.

## 🗄️ Database Schema
The system tracks five core entities and their corresponding audit table:
* `customers` & `audit_customers`.
* `products` & `audit_products`.
* `orders` & `audit_orders`.
* `order_items` & `audit_order_items`.
* `payments` & `audit_payments`.

## ⚙️ Setup & Run Instructions
The project includes a Flask-based GUI tool for easy interaction using the SQLite database.

### Prerequisites
* Python 3.8 or higher
* pip

### Installation
1.  Install the required dependency:
    ```bash
    pip install flask
    python app.py
    