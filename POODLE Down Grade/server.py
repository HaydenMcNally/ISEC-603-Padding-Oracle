import socket
import ssl
import time
import select


'''
create_ssl_server
Takes
host - host IP address
port - port number of socket
cerfile - cerfitiacte file for ssl socket
keyfile - private key for the certificate

This function is creates a socket and then accepts clients doing a short communitcation with them, thing to note is that is support TLSv1
'''
def create_ssl_server(host, port, certfile, keyfile):
    # Create a standard socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    
    #Create the ssl context, Note these context changes are needed as rightful insecure ciphers and version are disable by default
    ctx = ssl.create_default_context()
    ctx.options &= ~ssl.OP_NO_TLSv1 #This line enables TLSv1 which is ususaly disable
    ctx.minimum_version = ssl.TLSVersion.TLSv1 #Setting the minimum version allowed to be TLSv1
    #ctx.check_hostname = False
    # Bind the socket to the address and port
    server_socket.bind((host, port))

    while True:
        # Accept an incoming client connection
        try:
            server_socket.listen()
            print(f"SSL server listening on {host}:{port}")


            client_socket, addr = server_socket.accept()
            print(f"Connection established with {addr}")
            #Wrap the connection is and ssl socket to provide tls
            ssl_socket = ssl.wrap_socket(
                   client_socket, 
                   keyfile=keyfile, 
                   certfile=certfile, 
                   server_side=True,  # Server-side connection
            )
        except Exception as e:
            print(f"Error handling client: {e}")
            client_socket.close()
            continue 
        try:
        # Handle the client connection
            

            print("getting data")
            data = ssl_socket.recv(1024)
            if data:
                print(f"Received from client: {data.decode('utf-8')}")
                ssl_socket.sendall(b"Hello, Client!")
            else:
                print("No data received.")
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            ssl_socket.close()
            client_socket.close()

if __name__ == "__main__":
    host = "10.29.107.24"
    port = 65434
    certfile = "server.crt"  # Path to the self-signed certificate
    keyfile = "server.key"   # Path to the private key
    
    create_ssl_server(host, port, certfile, keyfile)