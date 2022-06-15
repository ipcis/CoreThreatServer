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


# because animation is cool
switch = 0

def checkMessage(message):
    
    global switch
    
    if switch == 0:
        print('  [-] receiving data ...', end='\r', flush=True)
        switch = 1
        return

    if switch == 1:
        print('  [|] receiving data ...', end='\r', flush=True)
        switch = 0
        return
    #print("  [+] receiving data...")

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