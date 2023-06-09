# SEV-SNP Attestation Server and Client
This repository contains the server and client scripts for performing the attestation of a SEV-SNP (Secure Encrypted Virtualization-Secure Nested Paging) guest VM. SEV-SNP is a feature provided by AMD processors that enables secure attestation of the CPU state, allowing the client to verify the integrity and security of the server's execution environment.

The server script creates a server that listens for client connections and performs a request for a SEV-SNP attestation report to be sent to the connected clients. The client script connects to the server and receives the attestation report which then verifies.

## Prerequisites
Before running the scripts, make sure you have the following prerequisites installed:
- `Python 3.x`
- `OpenSSL`
- `snpguest` utility (for attestation verification) -- provided as a submodule

## Server Script
The server script (`server.py`) performs the following tasks:

1. Checks if the `sev-guest` kernel module is loaded and if the `/dev/sev-guest` device is available.
2. Parses command line arguments to determine the configuration of the server.
3. Creates the required directories for storing attestation reports, secrets and certificates.
4. Generates a private key and a **self-signed** certificate for the server.
5. Sets up the server socket to listen for incoming client connections.
6. Handles client connections by performing the following steps:
    - Accepts the client connection.
    - Performs a certificate exchange (the other party (client) certificate acts as the root of trust in our example)
    - Performs TLS handshake with the client.
    - Generates an attestation report using the `snpguest` utility.
    - Sends the attestation report to the client.
    - Receives data from the client through the TLS channel (for testing).
    - Sends a response to the client through the TLS channel (for testing).

### Usage
To run the server script, use the following command:
```
python3 server.py [-ip IP_ADDR] [-p PORT] [-r REPORT_DIR] [-sg SNPGUEST_PATH] [-s SECRETS_DIR] [-k KEY_FILE] [-sc SELF_CERT_FILE] [-cn COMMON_NAME]
```

The command line arguments are as follows:

- `-ip IP_ADDR` (optional): IP address (default: `192.168.122.48`).
- `-p PORT` (optional): Port to connect (default: `8888`).
- `-r REPORT_DIR` (optional): Directory to store attestation reports (default: `./reports`).
- `-sg SNPGUEST_PATH` (optional): Location of the snpguest utility executable (default: `./snpguest/target/debug/snpguest`).
- `-s SECRETS_DIR` (optional): Directory to store the server's secret (default: `./srv_secrets`).
- `-k KEY_FILE` (optional): Name of the server's key file (default: `server.key`).
- `-sc SELF_CERT_FILE` (optional): Name of the server's certificate file (default: `server.pem`).
- `-cn COMMON_NAME` (optional): Common name to be used as a certificate parameter (default: `localhost`).

## Client Script
The client script (`client.py`) performs the following tasks:

1. Parses command line arguments to determine the configuration of the client.
2. Creates the required directories for storing certificates and attestation reports.
3. Generates a private key and a **self-signed** certificate for the client.
4. Connects to the attestation server.
5. Performs a certificate exchange (the other party (server) certificate acts as the root of trust in our example)
5. Performs TLS handshake with the server.
6. Expects the attestation report from the server.
7. Verifies the attestation report received from the server using the `snpguest` utility.
8. Sends data to the server through the TLS channel (for testing).
9. Receives a response from the server through the TLS channel (for testing).

### Usage
To run the client script, use the following command:
```
python3 client.py [-ip IP_ADDR] [-p PORT] [-s SECRETS_DIR] [-k KEY_FILE] [-sc SELF_CERT_FILE] [-rc ROOT_CERT] [-cn COMMON_NAME] [-pm PROCESSOR_MODEL] [-c CERT_DIR] [-r REPORT_DIR] [-n REPORT_NAME] [-sg SNPGUEST_PATH]
```

The command line arguments are as follows:

- `-ip IP_ADDR` (optional): Server's IP address (default: `192.168.122.48`).
- `-p PORT` (optional): Port to connect (default: `8888`).
- `-s SECRETS_DIR` (optional): Directory to store the client's secret (default: `./clt_secrets`).
- `-k KEY_FILE` (optional): Name of the client's key file (default: `client.key`).
- `-sc SELF_CERT_FILE` (optional): Name of the client's certificate file (default: `client.pem`).
- `-rc ROOT_CERT` (optional): Name of the trusted root certificate file (default: `server.pem`). **Note**: Since we have self-signed certificates, we exchange certificates before attestation.
- `-cn COMMON_NAME` (optional): Common name to be used as a certificate parameter (default: `localhost`).
- `-pm PROCESSOR_MODEL` (optional): Processor type (default: `milan`).
- `-c CERT_DIR` (optional): Directory to store certificates (default: `./certs`).
- `-r REPORT_DIR` (optional): Directory to store attestation reports (default: `./reports`).
- `-n REPORT_NAME` (optional): Name of the attestation report file (default: `attestation_report.bin`).
- `-sg SNPGUEST_PATH` (optional): Location of the snpguest utility executable (default: `./snpguest/target/debug/snpguest`).

## Example Workflow
1. Start the server by running the following command inside a SEV-SNP VM (`sudo` rights required):
```
python3 server.py
```
2. In a separate terminal, start the client by running the following command (adapt the parameters if needed):
```
python3 client.py
```
The server and client will perform the SEV-SNP attestation process, and the client will receive the server's attestation report. 
The client can then verify the attestation report using the `snpguest` utility.

## Additional Information
- The server and client scripts assume that the `snpguest` utility is built and available at the specified path. If not, you can modify the path in the script or build the utility using the provided submodule.
- Make sure to set up proper network connectivity between the server and client machines before running the scripts.
- The scripts provide basic functionality for SEV-SNP attestation. You can extend and modify them to fit your specific use case.