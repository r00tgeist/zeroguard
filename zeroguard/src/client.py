import requests
import json

URL = "https://localhost:8443/secure-data"
CERT_FILE = ("certs/client.crt", "certs/client.key")
ROOT_CA = "certs/ca.crt"

def try_access():
    print(f"[*] Attempting to access: {URL}")
    try:
        response = requests.get(URL, cert=CERT_FILE, verify=ROOT_CA)
        if response.status_code == 200:
            print("\n[SUCCESS] Access Granted!")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"\n[BLOCKED] Status: {response.status_code}")
            print(f"Reason: {response.text}")
    except requests.exceptions.SSLError as e:
        print("\n[FAILED] SSL Handshake Failed! Client certificate rejected or invalid.")
        print(e)

if __name__ == "__main__":
    try_access()