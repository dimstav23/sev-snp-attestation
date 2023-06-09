import socket
import ssl
import os
import subprocess
import argparse

def create_dirs(secrets_dir, report_dir):
  """
  Create directories if they don't exist.
  :param secrets_dir: Directory for secrets
  :param report_dir: Directory for attestation reports
  """
  directories = [secrets_dir, report_dir]
  for directory in directories:
    if not os.path.exists(directory):
      os.makedirs(directory)
  return

def generate_private_key(key_path):
  # Generate the private key
  subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", key_path])
  return

def generate_self_signed_cert(key_path, cert_path, common_name):
  # Generate the self-signed certificate using the private key
  subprocess.run(["openssl", "req", "-new", "-x509", "-key", key_path, "-out", cert_path, "-subj", "/CN="+common_name])
  return

def find_next_avail_idx(report_dir):
  """
  Find the next available index in the report directory.
  :param report_dir: Directory containing folders with naming conventions clt0, clt1, clt2, etc.
  :return: The next available index as an integer.
  """
  index = 0
  while True:
    folder_name = f"clt{index}"
    folder_path = os.path.join(report_dir, folder_name)
    if not os.path.exists(folder_path):
      return index
    index += 1
  
  return index

def prep_sev_guest_kernel_module():
  # Check if the sev-guest kernel module is loaded
  if check_sev_guest_module():
    print("sev-guest kernel module is loaded.")
  else:
    print("sev-guest kernel module is not loaded. Attempting to load it...")
    if load_sev_guest_module():
      print("sev-guest kernel module loaded successfully.")
    else:
      print("Failed to load sev-guest kernel module.")
      return False

  # Check if the /dev/sev-guest device is available
  if check_sev_guest_device():
    print("/dev/sev-guest device is available.")
  else:
    print("/dev/sev-guest device is not available.")
    return False

  return True

def check_sev_guest_module():
  """
  Check if the sev-guest kernel module is loaded.
  :return: True if the module is loaded, False otherwise.
  """
  try:
    # Use lsmod command to check if the sev_guest module is loaded
    cmd = 'lsmod | grep sev_guest'
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return True
  except subprocess.CalledProcessError:
    return False

def load_sev_guest_module():
  """
  Load the sev-guest kernel module using sudo modprobe.
  :return: True if the module is loaded successfully, False otherwise.
  """
  try:
    # Use sudo modprobe command to load the sev_guest module
    cmd = 'sudo modprobe sev_guest'
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return True
  except subprocess.CalledProcessError:
    return False

def check_sev_guest_device():
  """
  Check if the /dev/sev-guest device is available.
  :return: True if the device is available, False otherwise.
  """
  try:
    # Use ls command to check if /dev/sev-guest file exists
    cmd = 'ls /dev/sev-guest'
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return True
  except subprocess.CalledProcessError:
    return False

def generate_attestation_report(snpguest, report_dir):
  """
  Generate an attestation report using snpguest.
  :param snpguest: Path to snpguest binary.
  :param report_dir: Directory to store the attestation report and related files.
  :return: Path to the generated attestation report if successful.
  :raises: Exception if failed to generate the attestation report.
  """
  folder_prefix = "clt"
  index = find_next_avail_idx(report_dir)
  clt_folder = os.path.join(report_dir, f"{folder_prefix}{index}")
  create_dir(clt_folder)
  report_file = os.path.join(clt_folder, "attestation_report.bin")
  nonce_file = os.path.join(clt_folder, "random-request-file.txt")

  try:
    # Generate the attestation report using snpguest command
    cmd = f"sudo {snpguest} report --random -a {report_file} --request {nonce_file}"
    subprocess.run(cmd, shell=True, check=True)
    return report_file
  except subprocess.CalledProcessError as e:
    error_message = f"Failed to generate attestation report. {e}"
    raise Exception(error_message)

def handle_client_connection(client_socket, snpguest, report_dir, cert_file, key_file):
  """
  Handle client connection and perform SEV-SNP attestation.
  :param client_socket: Client socket object
  """
  # Create an SSL context
  context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  context.load_cert_chain(certfile=cert_file, keyfile=key_file) 
  
  # Require client certificate
  context.verify_mode = ssl.CERT_REQUIRED
  # context.load_verify_locations(cafile=client_cert_file)

  # Wrap the socket with SSL/TLS
  ssl_socket = context.wrap_socket(client_socket, server_side=True)

  try:
    # Perform TLS handshake
    ssl_socket.do_handshake()

    # Verify and save the client certificate
    client_cert = ssl_socket.getpeercert()
    # save_client_certificate(client_cert)  # Implement this function to save the client certificate to a file

    # Perform AMD SEV-SNP attestation
    try:
      attestation_report = generate_attestation_report(snpguest, report_dir)
      print(f"Attestation report generated successfully: {attestation_report}")
    except Exception as e:
      print(f"Error: {str(e)}")

    # Read the attestation report file
    with open(attestation_report, "rb") as file:
      report_content = file.read()

    # Send the attestation report to the client
    ssl_socket.sendall(report_content)

    # Receive data from the client
    data = ssl_socket.recv(1024).decode()
    print("Received from client:", data)

    # Send a response to the client
    response = "Message received: {}".format(data)
    ssl_socket.send(response.encode())

  except ssl.SSLError:
    print("TLS handshake failed.")

  # Close the SSL socket
  ssl_socket.close()

def run_server(snpguest, report_dir, cert_file, key_file):
  # Create a TCP socket
  # server_socket = socket.create_server(('localhost', 8888))
  server_socket = socket.create_server(('192.168.122.48', 8888))

  # Accept client connections
  while True:
    client_socket, client_address = server_socket.accept()
    handle_client_connection(client_socket, snpguest, report_dir, cert_file, key_file)

  # Close the server socket
  server_socket.close()

if __name__ == '__main__':
  # Check if the sev-guest kernel module is loaded and
  # if the /dev/sev-guest device is present
  if (not prep_sev_guest_kernel_module):
    exit()

  # Parse command line arguments
  parser = argparse.ArgumentParser()
  parser.add_argument('-r',  '--report_dir', default='./reports', help="Directory to store attestation reports (default: ./reports)")
  parser.add_argument('-sg', '--snpguest', default='./snpguest/target/debug/snpguest', help="Location of the snpguest utility executable (default: ./snpguest/target/debug/snpguest)")
  parser.add_argument('-s',  '--secrets_dir', default='./srv_secrets', help="Directory to store server's secret (default: ./srv_secrets)")
  parser.add_argument('-k',  '--key_file', default='server.key', help="Name of the server's key file (default: server.key)")
  parser.add_argument('-sc', '--self_cert_file', default='server.pem', help="Name of the server's certificate file (default: server.pem)")
  parser.add_argument('-cn', '--common_name', default='localhost', help="Common name to be used as a certificate parameter (default: localhost)")
  args = parser.parse_args()

  create_dirs(args.secrets_dir, args.report_dir)

  # Generate client private key and self-signed certificate
  key_file = os.path.join(args.secrets_dir, args.key_file)
  generate_private_key(key_file)
  cert_file = os.path.join(args.secrets_dir, args.self_cert_file)
  generate_self_signed_cert(key_file, cert_file, args.common_name)

  # generate_attestation_report(args.snpguest, args.report_dir)
  # Run the server
  run_server(args.snpguest, args.report_dir, cert_file, cert_file)
