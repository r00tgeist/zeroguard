import ssl
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from policy_engine import PolicyEngine

app = FastAPI()
engine = PolicyEngine()

@app.get("/")
def home():
    return {"message": "Welcome to ZeroGuard Secure Vault"}

@app.get("/secure-data")
def secure_data(request: Request):
    user_context = {
        "user": "admin_user",
        "ip": request.client.host,
        "role": "Level-4",
        "device_health_verified": True
    }

    is_allowed, reason = engine.evaluate(user_context)

    if not is_allowed:
        raise HTTPException(status_code=403, detail=reason)

    return {
        "status": "success",
        "data": "CONFIDENTIAL_BLUEPRINT_X99",
        "log": reason
    }

if __name__ == "__main__":
    import ssl
    
    print("[*] Starting ZeroGuard Enforcer on https://localhost:8443")
    

    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8443,
        
       
        ssl_keyfile="certs/server.key", 
        ssl_certfile="certs/server.crt",
        
        
        ssl_ca_certs="certs/ca.crt",       
        ssl_cert_reqs=ssl.CERT_REQUIRED    
    )