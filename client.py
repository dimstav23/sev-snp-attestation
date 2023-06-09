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
  # Generate the private key
  subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", key_path])
  return

def generate_self_signed_cert(key_path, cert_path, common_name):
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

def main():
  # Parse command line arguments
  parser = argparse.ArgumentParser()
  parser.add_argument('-s',  '--secrets_dir', default='./clt_secrets', help="Directory to store client's secret (default: ./clt_secrets)")
  parser.add_argument('-k',  '--key_file', default='client.key', help="Name of the client's key file (default: client.key)")
  parser.add_argument('-sc', '--self_cert_file', default='client.pem', help="Name of the client's certificate file (default: client.pem)")
  parser.add_argument('-cn', '--common_name', default='localhost', help="Common name to be used as a certificate parameter (default: localhost)")
  parser.add_argument('-p',  '--processor_model', default='milan', help="Processor type (default: milan)")
  parser.add_argument('-c',  '--cert_dir', default='./certs', help="Directory to store certificates (default: ./certs)")
  parser.add_argument('-r',  '--report_dir', default='./reports', help="Directory to store attestation reports (default: ./reports)")
  parser.add_argument('-n',  '--report_name', default='attestation_report.bin', help="Name of the attestation report file (default: attestation_report.bin)")
  parser.add_argument('-sg', '--snpguest', default='./snpguest/target/debug/snpguest', help="Location of the snpguest utility executable (default: ./snpguest/target/debug/snpguest)")
  args = parser.parse_args()

  if not os.path.exists(args.snpguest):
    print(f"Error: snpguest binary not found at '{args.snpguest}'.")
    return

  create_dirs(args.secrets_dir, args.cert_dir, args.report_dir)
  report_path = os.path.join(args.report_dir, args.report_name)

  # Generate client private key and self-signed certificate
  key_path = os.path.join(args.secrets_dir, args.key_file)
  generate_private_key(key_path)
  cert_path = os.path.join(args.secrets_dir, args.self_cert_file)
  generate_self_signed_cert(key_path, cert_path, args.common_name)

  # Create a TCP socket
  # client_socket = socket.create_connection(('localhost', 8888))
  client_socket = socket.create_connection(('192.168.122.48', 8888))

  # Create an SSL context
  context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

  # Load client private key and certificate
  context.load_cert_chain(certfile=cert_path, keyfile=key_path)

  # context.load_verify_locations(cafile="./secrets/server.crt")

  # # Require server certificate verification
  # context.verify_mode = ssl.CERT_REQUIRED

  # Wrap the socket with SSL/TLS
  ssl_socket = context.wrap_socket(client_socket, server_side=False, server_hostname='localhost')

  try:
    # Perform TLS handshake
    ssl_socket.do_handshake()

    # Send the client certificate to the server
    ssl_socket.send(cert_path)

    # Receive attestation report from the server
    attestation_report = ssl_socket.recv()

    # Save attestation report to a file
    report_path = os.path.join(args.report_dir, args.report_name)
    with open(report_path, 'wb') as report_file:
      report_file.write(attestation_report)

    # Verify server's attestation report
    if verify_attestation_report(args.snpguest, report_path, args.processor_model, args.cert_dir):
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


if __name__ == '__main__':
  main()