import socket
import ssl
import argparse
import subprocess
import sys
import os

def create_dirs(secrets_dir, cert_dir, report_dir):
  """
  Create directories if they don't exist.
  :param secrets_dir: Directory for secrets
  :param cert_dir: Directory for certificates
  :param report_dir: Directory for attestation reports
  """
  directories = [secrets_dir, cert_dir, report_dir]
  for directory in directories:
    if not os.path.exists(directory):
      os.makedirs(directory)
  return

def generate_private_key(key_path):
  if not os.path.exists(key_path):
    # Generate the private key
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", key_path])
  return

def generate_self_signed_cert(key_path, cert_path, common_name):
  if not os.path.exists(cert_path):
    # Generate the self-signed certificate using the private key
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", key_path, "-out", cert_path, "-subj", "/CN="+common_name])
  return

def verify_attestation_report(snpguest, attestation_report, processor_model, cert_dir):
  """
  Verify the SEV-SNP attestation report.
  :param snpguest: Path to snpguest binary
  :param attestation_report: Attestation report file
  :param processor_model: Processor model
  :param cert_dir: Directory to store the certificates
  :return: True if all verifications pass, False otherwise
  """
  return (
    retrieve_sev_snp_certs(snpguest, processor_model, cert_dir, attestation_report) and
    verify_sev_snp_certs(snpguest, cert_dir) and
    verify_sev_snp_tcb(snpguest, cert_dir, attestation_report) and
    verify_sev_snp_signature(snpguest, cert_dir, attestation_report)
  )

def retrieve_sev_snp_certs(snpguest, processor_model, cert_dir, attestation_report):
  """
  Retrieve SEV-SNP certificates.
  :param snpguest: Path to snpguest binary
  :param processor_model: Processor model
  :param cert_dir: Directory to store the certificates
  """
  cmd_ca = f"{snpguest} fetch ca {processor_model} {cert_dir}"
  cmd_vcek = f"{snpguest} fetch vcek {processor_model} {cert_dir} -a {attestation_report}"

  subprocess.run(cmd_ca, shell=True, check=True)
  subprocess.run(cmd_vcek, shell=True, check=True)

  # Check if the required files exist in the cert_dir
  required_files = ['ark.pem', 'ask.pem', 'vcek.der']
  missing_files = []
  for file in required_files:
    file_path = os.path.join(cert_dir, file)
    if not os.path.exists(file_path):
      missing_files.append(file)

  if missing_files:
    print(f"Error: Failed to retrieve certificates. Missing files: {', '.join(missing_files)}")
    return False

  print("Certificates acquired successfully.\n")
  return True

def verify_sev_snp_certs(snpguest, cert_dir):
  """
  Verify SEV-SNP certificates.
  :param snpguest: Path to snpguest binary
  :param cert_dir: Directory containing the certificates
  """
  cmd_verify_certs = f"{snpguest} verify certs {cert_dir}"
  expected_output_verify_certs = [
    "The AMD ARK was self-signed!",
    "The AMD ASK was signed by the AMD ARK!",
    "The VCEK was signed by the AMD ASK!"
  ]

  output_verify_certs = subprocess.check_output(cmd_verify_certs, shell=True, universal_newlines=True)

  # Split the actual output into individual lines and check if all the expected output lines are there
  split_output_verify_certs = output_verify_certs.strip().splitlines()
  if not all(line in split_output_verify_certs for line in expected_output_verify_certs):
    return False
  
  print(output_verify_certs)
  return True
  
def verify_sev_snp_tcb(snpguest, cert_dir, attestation_report):
  """
  Verify SEV-SNP TCB.
  :param snpguest: Path to snpguest binary
  :param cert_dir: Directory containing the certificates
  :param attestation_report: Attestation report file
  """
  cmd_verify_tcb = f"{snpguest} verify tcb {cert_dir} -a {attestation_report}"
  expected_output_verify_tcb = [
    "Reported TCB Boot Loader from certificate matches the attestation report.",
    "Reported TCB TEE from certificate matches the attestation report.",
    "Reported TCB SNP from certificate matches the attestation report.",
    "Reported TCB Microcode from certificate matches the attestation report.",
    "Chip ID from certificate matches the attestation report."
  ]

  output_verify_tcb = subprocess.check_output(cmd_verify_tcb, shell=True, universal_newlines=True)

  # Split the actual output into individual lines and check if all the expected output lines are there
  split_output_verify_tcb = output_verify_tcb.strip().splitlines()
  if not all(line in split_output_verify_tcb for line in expected_output_verify_tcb):
    return False

  print(output_verify_tcb)
  return True

def verify_sev_snp_signature(snpguest, cert_dir, attestation_report):
  """
  Verify SEV-SNP signature.
  :param snpguest: Path to snpguest binary
  :param cert_dir: Directory containing the certificates
  :param attestation_report: Attestation report file
  """
  cmd_verify_signature = f"{snpguest} verify signature {cert_dir} -a {attestation_report}"
  expected_output_verify_signature = "VCEK signed the Attestation Report!"

  output_verify_signature = subprocess.check_output(cmd_verify_signature, shell=True, universal_newlines=True)

  if expected_output_verify_signature not in output_verify_signature:
    print(f"Error: Failed to verify signature. Output: {output_verify_signature}")
    return False

  print(output_verify_signature)
  return True

def exchange_certificates(client_socket, client_cert_file, server_cert_file):
  """
  Perform certificate exchange between client and server.
  :param client_socket: Client socket object
  :param client_cert_file: File path of the client's certificate
  :param server_cert_file: File path of the server's certificate
  """
  # Read the client certificate
  with open(client_cert_file, 'rb') as cert_file:
    client_certificate = cert_file.read()

  # Send the length of the client certificate to the server
  client_socket.send(len(client_certificate).to_bytes(4, byteorder='big'))
  # Send the client certificate to the server
  client_socket.sendall(client_certificate)

  # Receive the server's certificate length
  server_cert_len = int.from_bytes(client_socket.recv(4), byteorder='big')
  # Receive the server's certificate
  server_certificate = client_socket.recv(server_cert_len)

  # Store the server's certificate to use it at load_verify_locations
  with open(server_cert_file, 'wb') as server_cert:
    server_cert.write(server_certificate)

def run_client(ip_addr, port, snpguest, secrets_dir, key_file, self_cert_file, root_cert, common_name, processor_model, cert_dir, report_dir, report_name):
  """
  Run the client and perform SEV-SNP attestation with the server.
  :param ip_addr: Server's IP address
  :param port: Port to connect
  :param snpguest: Path to snpguest utility executable
  :param secrets_dir: Directory to store client's secret
  :param key_file: Name of the client's key file
  :param self_cert_file: Name of the client's certificate file
  :param root_cert: Name of the trusted root certificate file
  :param common_name: Common name to be used as a certificate parameter
  :param processor_model: Processor type
  :param cert_dir: Directory to store certificates
  :param report_dir: Directory to store attestation reports
  :param report_name: Name of the attestation report file
  """
  # Generate client private key and self-signed certificate
  key_path = os.path.join(secrets_dir, key_file)
  generate_private_key(key_path)
  cert_path = os.path.join(secrets_dir, self_cert_file)
  generate_self_signed_cert(key_path, cert_path, common_name)

  # Create a TCP socket
  client_socket = socket.create_connection((ip_addr, port))

  # Perform certificate exchange between client and server
  server_cert_file = os.path.join(cert_dir,root_cert)
  exchange_certificates(client_socket, cert_path, server_cert_file)

  # Create an SSL context
  context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
  context.verify_mode = ssl.CERT_REQUIRED

  # Load client private key and certificate
  context.load_cert_chain(certfile=cert_path, keyfile=key_path)
  context.load_verify_locations(cafile=server_cert_file)

  # Wrap the socket with SSL/TLS
  ssl_socket = context.wrap_socket(client_socket, server_side=False, server_hostname='localhost')

  try:
    # Perform TLS handshake
    ssl_socket.do_handshake()

    # Receive the server's certificate length
    attestation_report_len = int.from_bytes(ssl_socket.recv(4), byteorder='big')
    # Receive attestation report from the server
    attestation_report = ssl_socket.recv(attestation_report_len)

    # Save attestation report to a file
    report_path = os.path.join(report_dir, report_name)
    with open(report_path, 'wb') as report_file:
      report_file.write(attestation_report)

    # Verify server's attestation report
    if verify_attestation_report(snpguest, report_path, processor_model, cert_dir):
      # Attestation successful, continue using the TLS channel for communication
      message = "Hello, server!"
      ssl_socket.send(message.encode())
      response = ssl_socket.recv(1024).decode()
      print("Received from server:", response)
    else:
      print("Attestation failed.")

  except ssl.SSLError:
    print("TLS handshake failed.")

  # Close the SSL socket
  ssl_socket.close()

def main():
  # Parse command line arguments
  parser = argparse.ArgumentParser()
  parser.add_argument('-ip', '--ip_addr', default='192.168.122.48', help="Server's IP address (default: 192.168.122.48)")
  parser.add_argument('-p',  '--port', default=8888, help="Port to connect (default: 8888)")
  parser.add_argument('-s',  '--secrets_dir', default='./clt_secrets', help="Directory to store client's secret (default: ./clt_secrets)")
  parser.add_argument('-k',  '--key_file', default='client.key', help="Name of the client's key file (default: client.key)")
  parser.add_argument('-sc', '--self_cert_file', default='client.pem', help="Name of the client's certificate file (default: client.pem)")
  parser.add_argument('-rc', '--root_cert', default='server.pem', help="Name of the trusted root certificate file (default: server.pem)") # since we have self-signed ceritificates, we make a cert exchange before
  parser.add_argument('-cn', '--common_name', default='localhost', help="Common name to be used as a certificate parameter (default: localhost)")
  parser.add_argument('-pm', '--processor_model', default='milan', help="Processor type (default: milan)")
  parser.add_argument('-c',  '--cert_dir', default='./certs', help="Directory to store certificates (default: ./certs)")
  parser.add_argument('-r',  '--report_dir', default='./reports', help="Directory to store attestation reports (default: ./reports)")
  parser.add_argument('-n',  '--report_name', default='attestation_report.bin', help="Name of the attestation report file (default: attestation_report.bin)")
  parser.add_argument('-sg', '--snpguest', default='./snpguest/target/debug/snpguest', help="Location of the snpguest utility executable (default: ./snpguest/target/debug/snpguest)")
  args = parser.parse_args()

  if not os.path.exists(args.snpguest):
    print(f"Error: snpguest binary not found at '{args.snpguest}'.")
    return

  create_dirs(args.secrets_dir, args.cert_dir, args.report_dir)

  # Run the client and perform attestation
  run_client(
    args.ip_addr,
    args.port,
    args.snpguest,
    args.secrets_dir,
    args.key_file,
    args.self_cert_file,
    args.root_cert,
    args.common_name,
    args.processor_model,
    args.cert_dir,
    args.report_dir,
    args.report_name
  )

if __name__ == '__main__':
  main()
