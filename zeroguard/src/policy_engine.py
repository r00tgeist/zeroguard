import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - POLICY - %(message)s')
logger = logging.getLogger("ZeroGuard")

class PolicyEngine:
    def __init__(self):
        self.blocked_ips = ["192.168.1.100", "10.0.0.66"]
        self.required_clearance = "Level-4"

    def evaluate(self, user_context):
        logger.info(f"Evaluating Access Request: {user_context}")

        if user_context['ip'] in self.blocked_ips:
            return False, "DENIED: IP Address is flagged as malicious."

        if not user_context.get('device_health_verified'):
            return False, "DENIED: Device health checks failed (Anti-virus outdated)."

        if user_context['role'] != self.required_clearance:
            return False, f"DENIED: Insufficient clearance. Required {self.required_clearance}."

        return True, "ACCESS GRANTED: All Zero Trust checks passed."