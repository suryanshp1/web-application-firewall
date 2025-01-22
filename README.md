# web-application-firewall

A simple web application firewall implementation using langchain, GROQ and fastAPI middleware

## How to use it ?

1. clone the repo

```bash
git clone https://github.com/suryanshp1/web-application-firewall.git
```

2. create a .env file with following env variable

```
GROQ_API_KEY=<YOUR API KEY>
```

3. Docker build and run command

```bash
docker compose up --build
```

4. Do a malicious request through postman or curl and your IP will be blocked

```bash
curl "http://127.0.0.1:80/?id=1 UNION SELECT * FROM users"
```