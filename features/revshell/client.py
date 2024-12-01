import socket

def start_server(host='0.0.0.0', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Listening on {host}:{port}...")
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connection from {addr}")
            while True:
                command = input("Shell> ")
                if command.lower() in ('exit', 'quit'):
                    break
                conn.sendall(command.encode() + b'\n')
                response = conn.recv(4096)
                print(response.decode(), end='')

if __name__ == "__main__":
    start_server()
