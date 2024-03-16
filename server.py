from http.server import HTTPServer, SimpleHTTPRequestHandler
import cgi
import hashlib

class CustomHandler(SimpleHTTPRequestHandler):
    users = {}  # Dictionary to store username and hashed passwords

    def do_GET(self):
        if self.path in ['/', '/registration']:
            self.path = '/registration.html'  # Serve the registration page at root
        elif self.path == '/dashboard':
            self.path = '/dashboard.html'  # Serve the dashboard page
        # Add more elif blocks here if you have more pages to serve, like '/login', etc.
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        if self.path == '/submit':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type'],
                         })

            # Extracting form data
            firstname = form.getvalue('firstname')
            lastname = form.getvalue('lastname')
            # ... other form fields ...

            username = form.getvalue('username')
            password = form.getvalue('password')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            # Storing the username and hashed password
            CustomHandler.users[username] = hashed_password

            # Respond with a simple confirmation and redirect
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><head>")
            self.wfile.write(b"<meta http-equiv='refresh' content='3; url=http://localhost/' />")  # Redirect after 3 seconds
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

            # Check if username exists and passwords match
            if username in CustomHandler.users and CustomHandler.users[username] == hashed_password:
                # Successful login, redirect to the dashboard
                self.send_response(303)  # 303 See Other
                self.send_header('Location', '/dashboard')
                self.end_headers()
            else:
                # Login failed
                self.send_response(401)  # Unauthorized
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"Invalid username or password")

# Server setup
httpd = HTTPServer(('localhost', 8000), CustomHandler)
print("Serving at port 8000")
httpd.serve_forever()
