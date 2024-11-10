import socket
import ssl
import time


'''
create_ssl_client
Takes
host - host IP address
port - port number of socket


This function is creates a socket and then tries to connect to a server doing a short communitcation with them, thing to note is that the client will try the connection and if it fails fall back to TLSv1
'''

def create_ssl_client(host, port):
    # Create a standard socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(5)
    
    # Wrap the socket with SSL, don't verify the server's certificate
    ssl_socket = ssl.wrap_socket(
        client_socket, 
        keyfile=None,    # No private key for the client
        certfile=None,   # No certificate for the client
        server_side=False,
        cert_reqs=ssl.CERT_NONE,  # Disable certificate verification
        ssl_version=ssl.PROTOCOL_TLSv1_2
    )
    

    # Connect to the server
    try:
        ssl_socket.connect((host, port))
        print(f"Connected to SSL server at {host}:{port}")

    except Exception as e:
        #When an error happens we feel something is wrong with the socket so we create a new one with TLSv1
        print(f"Error handling client: {e}")
        ssl_socket.close() #Closing old socket
        print("swapping to ssl 3")
        time.sleep(10)
        new_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #New client socket to wrap
        ssl_socket_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1) #Setting the tls version
        ssl_socket_context.options &= ~ssl.OP_NO_TLSv1 # Enabling TLSv1
        #ssl_socket_context.check_hostname = False
        ssl_socket_context.set_ciphers('AES128-SHA') #Setting the cipher to AES 128 CBC as this is the cipher vulnerably to the Padding Oracle attack
        ssl_socket = ssl_socket_context.wrap_socket(new_client_socket, server_side=False) #Wrap our original socket with TLS
        ssl_socket.connect((host, port))
        print(f"Connected to SSL server at {host}:{port}")
    # Send some data to the server
        try:
            ssl_socket.sendall(b"Hello Server Here is my super security Password:GoodPassword")
    
    # Receive data from the server
            data = ssl_socket.recv(1024)
            print(f"Received from server: {data.decode('utf-8')}")
        except Exception as e:
            print(e)
    ssl_socket.close()

if __name__ == "__main__":
    host = "10.29.107.24"
    port = 65434

    create_ssl_client(host, port)