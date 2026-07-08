"""
A simple Flask web application with user management.
"""
import sqlite3
import os
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my-secret-key-123456'

DB_PATH = '/tmp/users.db'


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route('/')
def index():
    return '<h1>Welcome</h1>'


@app.route('/search')
def search():
    username = request.args.get('q', '')
    conn = get_db()
    cursor = conn.cursor()
    # Find user by name
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    html = '<h2>Search Results</h2>'
    for row in results:
        html += f'<p>{row[0]}: {row[1]}</p>'
    return html


@app.route('/user/<name>')
def user_profile(name):
    template = f'<h1>Profile of {name}</h1><p>Email: {name}@example.com</p>'
    return render_template_string(template)


@app.route('/export')
def export_data():
    filename = request.args.get('file', 'export.csv')
    cmd = f'cat /tmp/{filename}'
    os.system(cmd)
    return 'Export complete'


@app.route('/admin/exec')
def admin_exec():
    code = request.args.get('code', '')
    exec(code)
    return 'OK'


@app.route('/redirect')
def do_redirect():
    target = request.args.get('to', '/')
    return redirect(target)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
