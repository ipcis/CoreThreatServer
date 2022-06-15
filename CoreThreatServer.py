import socket
import sys





def banner():
    print("")
    print(" Core|Threat Server")
    print("")
    

banner()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

port = 8888 if len(sys.argv) == 1 else int(sys.argv[1])
sock.bind(('localhost', port))
sock.listen(5)


print("  [+] listening on port: " + str(port))
print("  [+] server is up and running")


def checkMessage(message):
    if "vssadmin" in message.lower():
        print("FOUND")
    


try:
    while True:
        conn, info = sock.accept()

        data = conn.recv(1024)
        while data:
            data = conn.recv(1024)
            checkMessage(str(data))
            
# blocking socket - interrupt is not working!
except KeyboardInterrupt:
    sock.close