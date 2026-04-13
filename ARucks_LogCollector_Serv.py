# Andrew Rucks
# 4/10/2026
# REMOTE WINDOWS SECURITY EVENT LOG COLLECTOR - SERVER SIDE

# Sends most recent Windows event logs (security) to a requesting client using a socket.
# To use, start the program, fill out the information asked, and then start the client program.
# Both the client and the server can be run on the same machine using the loopback address.
# Note: This script must be ran as Administrator.

import socket
import subprocess
import getpass
import ARucks_SimpleCrypto as simplecrypto

DEFAULT_HOST = "127.0.0.1" #loopback
DEFAULT_PORT = 12345

symmetric_key = "" #provided by user input in main()
port = DEFAULT_PORT
host = DEFAULT_HOST

# MAIN FUNCTION
def main():
    print("Reminder: Administrative permission required.")

    port = input("Input the port number to use, or hit Enter to use default (12345): ")
    if port == "":
        port = DEFAULT_PORT
    else:
        port = int(port)

    host = input("Input the IP address of this machine, or hit Enter to use default (127.0.0.1): ")
    if host == "":
        host = DEFAULT_HOST

    symmetric_key = getpass.getpass("Input your encryption key (concealed): ")
    listen_for_request()
    return


# RUNS A POWERSHELL COMMAND THAT OUTPUTS LOGS AS CSV TEXT
def collect_logs():
    output = subprocess.run('PowerShell -NoProfile -Command "Get-WinEvent -LogName Security -MaxEvents 100 | Select-Object TimeCreated, Id, Level, Message | ConvertTo-Csv -NoTypeInformation"', 
        capture_output=True, text=True, shell=True)

    return output.stdout 


# CONTINUALLY LISTENS FOR CONNECTION REQUESTS FROM CLIENTS
def listen_for_request():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        sock.bind((host, port))
        sock.listen()
        print("Listening...")

        conn, addr = sock.accept()
        # if connected, send encrypted log data
        with conn:
            print("Connected by ", addr)
            
            # gathers and then encrypts logs
            data = simplecrypto.encrypt(collect_logs(), symmetric_key, 10)

            # sends to socket connection
            conn.sendall(data)
            print("Logs sent.")

            # keep listening
            sock.close()
            listen_for_request()


if __name__ == "__main__":
    main() #start