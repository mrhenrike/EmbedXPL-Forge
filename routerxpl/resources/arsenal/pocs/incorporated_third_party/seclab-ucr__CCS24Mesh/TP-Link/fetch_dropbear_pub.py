import paramiko
import socket

def get_server_public_key(hostname, port=20001):
    try:
        # Create a transport object
        transport = paramiko.Transport((hostname, port))
        transport.start_client()

        # Get the server's public key
        server_key = transport.get_remote_server_key()
        transport.close()

        # Display the public key
        return f"{server_key.get_name()} {server_key.get_base64()}"
    except paramiko.SSHException as e:
        return f"SSH Exception: {e}"
    except socket.error as e:
        return f"Socket Error: {e}"

if __name__ == "__main__":
    target_host = input("Enter the hostname or IP address of the server: ")
    target_port = input("Enter the port number of TP-Link Dropbear (default is 20001): ")
    target_port = int(target_port) if target_port else 20001

    public_key = get_server_public_key(target_host, target_port)
    print("\nServer's Public Key:")
    print(public_key)
