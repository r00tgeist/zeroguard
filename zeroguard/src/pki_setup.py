from OpenSSL import crypto
import os

CERT_DIR = "certs"
if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)

def generate_cert(cn, is_ca=False, ca_cert=None, ca_key=None, alt_names=None):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "CyberState"
    cert.get_subject().L = "ZeroTrustCity"
    cert.get_subject().O = "ZeroGuard Corp"
    cert.get_subject().CN = cn
    
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)

    extensions = []

    if is_ca:
        extensions.extend([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])
    else:
        extensions.extend([
            crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
            crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])
        if alt_names:
            san_list = ", ".join(alt_names).encode()
            extensions.append(crypto.X509Extension(b"subjectAltName", False, san_list))

    cert.add_extensions(extensions)

    if is_ca:
        cert.sign(k, 'sha256')
        return k, cert
    else:
        cert.set_issuer(ca_cert.get_subject())
        cert.add_extensions([
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert)
        ])
        cert.sign(ca_key, 'sha256')
        return k, cert

def save_pem(key, cert, name):
    with open(f"{CERT_DIR}/{name}.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(f"{CERT_DIR}/{name}.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    print(f"[+] Generated {name} certificate.")

ca_key, ca_cert = generate_cert("ZeroGuard Root CA", is_ca=True)
save_pem(ca_key, ca_cert, "ca")

server_key, server_cert = generate_cert(
    "localhost", 
    is_ca=False, 
    ca_cert=ca_cert, 
    ca_key=ca_key,
    alt_names=["DNS:localhost", "IP:127.0.0.1"] 
)
save_pem(server_key, server_cert, "server")

client_key, client_cert = generate_cert(
    "client_user_01", 
    is_ca=False, 
    ca_cert=ca_cert, 
    ca_key=ca_key
)
save_pem(client_key, client_cert, "client")

print("\n[SUCCESS] PKI Infrastructure updated. Certificates in /certs")