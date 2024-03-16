from http.server import HTTPServer, SimpleHTTPRequestHandler
import cgi
import hashlib
import json
import sqlite3
from time import time
import secrets
import http.cookies

class Block:
    def __init__(self, index, timestamp, vote):
        self.index = index
        self.timestamp = timestamp
        self.vote = vote
        self.previous_hash = ''
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return hashlib.sha256((str(self.index) + str(self.timestamp) + str(self.vote) + str(self.previous_hash)).encode()).hexdigest()

class CustomHandler(SimpleHTTPRequestHandler):
    db_connection = sqlite3.connect('user_database.db')
    db_cursor = db_connection.cursor()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        CustomHandler.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT
            )
        ''')
        CustomHandler.db_connection.commit()

    users = {}
    votes = {'yes': 0, 'no': 0}
    blockchain = []
    user_tokens = {}
    user_votes = set()

    def save_user_to_database(self, username, hashed_password):
        CustomHandler.db_cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        CustomHandler.db_connection.commit()

    @staticmethod
    def check_user_credentials(username, hashed_password):
        CustomHandler.db_cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
        return CustomHandler.db_cursor.fetchone() is not None

    def do_GET(self):
        if self.path in ['/', '/registration']:
            self.path = '/registration.html'
        elif self.path.startswith('/dashboard'):
            # Check for the presence of the session cookie
            if 'Cookie' in self.headers:
                cookies = http.cookies.SimpleCookie(self.headers['Cookie'])
                if 'session' in cookies:
                    username = cookies['session'].value
                    print(f"Currently logged in as: {username}")
                else:
                    # Redirect to login if session cookie is missing
                    self.send_response(303)
                    self.send_header('Location', '/login')
                    self.end_headers()
                    return SimpleHTTPRequestHandler.do_GET(self)

            self.path = '/dashboard.html'
            return SimpleHTTPRequestHandler.do_GET(self)
        elif self.path == '/Result.html':
            try:
                with open('Result.html', 'r') as file:
                    html_content = file.read()

                results_content = f"<p>Yes: {self.votes['yes']}</p><p>No: {self.votes['no']}</p>"
                html_content = html_content.replace("<!-- Voting results will be dynamically inserted here by the server -->", results_content)

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_content.encode())
            except FileNotFoundError:
                self.send_error(404, "File not found")
        elif self.path == '/logout_confirm':
            self.path = '/logout_confirm.html'
            return SimpleHTTPRequestHandler.do_GET(self)
        elif self.path == '/confirm_logout':
            # Clear the session cookie
            self.send_response(303)
            self.send_header('Location', '/home.html')
            self.send_header('Set-Cookie', 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()
        elif self.path == '/blockchain':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps([vars(block) for block in CustomHandler.blockchain]).encode())

        return super().do_GET()

    def do_POST(self):
        if self.path == '/submit':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type'],
                         })

            firstname = form.getvalue('firstname')
            lastname = form.getvalue('lastname')
            username = form.getvalue('username')
            password = form.getvalue('password')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            CustomHandler.users[username] = hashed_password
            self.save_user_to_database(username, hashed_password)

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><head>")
            self.wfile.write(b"<meta http-equiv='refresh' content='3; url=http://localhost:8000/Login.html' />")
            self.wfile.write(b"</head><body>")
            self.wfile.write(f"Thank you, {username}. Your submission has been received. Redirecting to the home page.".encode())
            self.wfile.write(b"</body></html>")

        elif self.path == '/login':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type'],
                         })

            username = form.getvalue('username')
            password = form.getvalue('password')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            if CustomHandler.check_user_credentials(username, hashed_password):
                # Set a session cookie
                self.send_response(303)
                self.send_header('Location', '/dashboard')
                self.send_header('Set-Cookie', f'session={username}; Path=/')
                self.end_headers()
            else:
                self.send_response(401)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"Invalid username or password")

        elif self.path == '/logout':
            # Clear the session cookie
            self.send_response(303)
            self.send_header('Location', '/login')
            self.send_header('Set-Cookie', 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()

        elif self.path == '/vote':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': self.headers['Content-Type'],
                        })

            username = form.getvalue('username')
            vote = form.getvalue('vote')

            # Check if the user already has a token
            if username not in CustomHandler.user_tokens:
                # Generate a unique token using secrets module
                token = secrets.token_hex(16)
                CustomHandler.user_tokens[username] = token

                # Send the token back to the user
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Your voting token: {token}".encode())
                return

            # Continue with the voting process
            if vote in CustomHandler.votes:
                # Debug prints
                print(f"Username: {username}")
                print(f"User Tokens: {CustomHandler.user_tokens}")
                print(f"User Votes: {CustomHandler.user_votes}")

                # Check if the user has already voted
                if username in CustomHandler.user_votes:
                    self.send_response(400)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"You have already voted.")
                    return

                # Continue with the voting process
                new_block = Block(len(CustomHandler.blockchain), time(), vote)
                if len(CustomHandler.blockchain) > 0:
                    new_block.previous_hash = CustomHandler.blockchain[-1].hash
                CustomHandler.blockchain.append(new_block)

                CustomHandler.votes[vote] += 1
                CustomHandler.user_votes.add(username)  # Store the user's vote

            print(f"Voting Results: {CustomHandler.votes}")
            print(f"Blockchain: {CustomHandler.blockchain}")

            self.send_response(303)  # 303 See Other is commonly used for redirects after form submissions
            self.send_header('Location', '/dashboard')  # Redirect to the dashboard page
            self.end_headers()

# Server setup
httpd = HTTPServer(('localhost', 8000), CustomHandler)
print("Serving at port 8000")
httpd.serve_forever()
