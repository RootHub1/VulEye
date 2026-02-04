import http.server
import socketserver
import socket
import os

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_PUT(self):

        path = self.translate_path(self.path)


        try:
            length = int(self.headers['Content-Length'])
        except TypeError:
            self.send_response(411, "Length Required")
            self.end_headers()
            return


        try:
            with open(path, 'wb') as f:
                f.write(self.rfile.read(length))

            self.send_response(201, "Created")
            self.end_headers()
            self.wfile.write(b"File uploaded successfully\n")
            print(f"📥 File uploaded: {path}")
        except Exception as e:
            self.send_response(500, "Internal Server Error")
            self.end_headers()
            print(f"error: {e}")



try:
    port_input = input("Enter port (Enter для 8000): ")
    PORT = int(port_input) if port_input.strip() else 8000
except ValueError:
    PORT = 8000

IP = get_local_ip()

print(f"\n{'=' * 40}")
print(f" SERVER STARTED (DOWNLOAD + UPLOAD)")
print(f"🔗 Adress: http://{IP}:{PORT}")
print(f"{'=' * 40}")


print("\nHOW TO UPLOAD A FILE HERE:")
print(f"Use curl:  curl -T file_name http://{IP}:{PORT}/file_name")
print(f"{'=' * 40}\n")

with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass