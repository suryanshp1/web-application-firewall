from fastapi import FastAPI, Request, HTTPException
from langchain_groq import ChatGroq
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
import uvicorn
import json
import re
import os
from pydantic import BaseModel
import redis
import logging
from dotenv import load_dotenv

load_dotenv()

class BlockedIP(BaseModel):
    ip: str
    reason: str
    expires: int

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(debug=True, title="Web Application Firewall")

# Initialize Redis for rate limiting and IP blocking
redis_client = redis.Redis(host='redis', port=6379, db=0)

# Initialize LangChain components
PROMPT_TEMPLATE = """
As a security expert, Analyze the following HTTP request for potential security threats.
Consider SQL injection, XSS, command injection, and other web attacks.

Request Details:
Method: {method}
Path: {path}
Headers: {headers}
Body: {body}
Query Params: {query_params}

Determine if this request is:
1. Safe
2. Suspicious
3. Malicious

Provide your analysis as JSON with the following structure:
{{
    "threat_level": "safe/suspicious/malicious",
    "confidence": 0-1,
    "threats": ["threat1", "threat2"],
    "explanation": "reason for classification"
}}
Your JSON response is :
"""

prompt = PromptTemplate(
    input_variables=["method", "path", "headers", "body", "query_params"],
    template=PROMPT_TEMPLATE
)

# Initialize LangChain
llm = ChatGroq(temperature=0, api_key=os.getenv("GROQ_API_KEY"))
chain = LLMChain(llm=llm, prompt=prompt)

# Rate limiting configuration
RATE_LIMIT = 100  # requests per minute
BLOCK_DURATION = 3600  # 1 hour in seconds

def check_rate_limit(ip: str) -> bool:
    pipe = redis_client.pipeline()
    key = f"rate_limit:{ip}"
    pipe.incr(key)
    pipe.expire(key, 60)
    result = pipe.execute()
    request_count = result[0]
    return request_count <= RATE_LIMIT

def is_ip_blocked(ip: str) -> bool:
    return redis_client.exists(f"blocked:{ip}")

def block_ip(ip: str, reason: str):
    redis_client.setex(
        f"blocked:{ip}",
        BLOCK_DURATION,
        json.dumps({"reason": reason, "expires": BLOCK_DURATION})
    )

def contains_common_attacks(request_data: str) -> bool:
    attack_patterns = [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from)",  # SQL injection
        r"(?i)(<script>|javascript:|onerror=|onload=)",  # XSS
        r"(?i)(\|\||&&|\bping\b|\bcat\b|\bgrep\b)",  # Command injection
        r"(?i)(../../|\.\.%2f|\.\.%5c)",  # Path traversal
    ]
    return any(re.search(pattern, request_data) for pattern in attack_patterns)

async def analyze_request(request: Request) -> dict:
    # Get request details
    body = await request.body()
    body_str = body.decode() if body else ""
    
    headers = dict(request.headers)
    sanitized_headers = {k: v for k, v in headers.items() if k.lower() not in {'authorization', 'cookie'}}
    
    # Prepare request data for analysis
    request_data = {
        "method": request.method,
        "path": str(request.url.path),
        "headers": json.dumps(sanitized_headers),
        "body": body_str,
        "query_params": dict(request.query_params),
    }
    
    # Quick check for common attack patterns
    if contains_common_attacks(body_str) or contains_common_attacks(str(request.url)):
        return {
            "threat_level": "malicious",
            "confidence": 0.95,
            "threats": ["pattern_matched_attack"],
            "explanation": "Known attack pattern detected"
        }
    
    # AI analysis using LangChain
    try:
        result = chain.run(**request_data)
        return json.loads(result)
    except Exception as e:
        logger.error(f"Error in AI analysis: {e}")
        # Fallback to basic analysis if AI fails
        return {
            "threat_level": "suspicious" if contains_common_attacks(str(request_data)) else "safe",
            "confidence": 0.7,
            "threats": [],
            "explanation": "Fallback analysis due to AI error"
        }

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    client_ip = request.client.host
    
    # Check if IP is blocked
    if is_ip_blocked(client_ip):
        raise HTTPException(status_code=403, detail="IP is blocked")
    
    # Check rate limit
    if not check_rate_limit(client_ip):
        block_ip(client_ip, "Rate limit exceeded")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Analyze request
    analysis = await analyze_request(request)
    
    if analysis["threat_level"] == "malicious" and analysis["confidence"] > 0.8:
        block_ip(client_ip, analysis["explanation"])
        raise HTTPException(status_code=403, detail="Malicious request detected")
    
    if analysis["threat_level"] == "suspicious":
        logger.warning(f"Suspicious request from {client_ip}: {analysis['explanation']}")
    
    # Allow the request to proceed if it's deemed safe
    response = await call_next(request)
    return response

@app.get("/")
async def root():
    return {"message": "home"}

@app.get("/waf/status")
async def get_waf_status():
    """Get WAF status and statistics"""
    blocked_ips = []
    for key in redis_client.scan_iter("blocked:*"):
        ip = key.decode().split(":")[1]
        data = json.loads(redis_client.get(key))
        blocked_ips.append(BlockedIP(ip=ip, reason=data["reason"], expires=data["expires"]))
    
    return {
        "status": "active",
        "blocked_ips": blocked_ips,
        "total_blocked": len(blocked_ips)
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)