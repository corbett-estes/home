import socket

target = input("What do you want to scan?: ")
target_ip = socket.gethostbyname(target)
print("Starting scan on host:", target_ip)

for port in range(1, 1025):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = sock.connect_ex((target_ip, port))
    if(conn == 0) :
        print(f"Port {port} is open.")
    sock.close()