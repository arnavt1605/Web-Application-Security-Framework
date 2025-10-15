import re
from flask import Flask, request, Response
import requests

app = Flask(__name__)

DVWA_URL = "http://127.0.0.1:8080"


MALICIOUS_PATTERNS = [
    r"'\s*or\s*'1'\s*=\s*'1",   # SQLi: ' or '1'='1
    r"<\s*script\s*>",          # XSS: <script>
    r"(\bunion\b|\bselect\b).*\bfrom\b" # SQLi: UNION SELECT ... FROM
]

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    
    for key, value in request.args.items():
        for pattern in MALICIOUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                print(f"Malicious pattern '{pattern}' detected in parameter '{key}'. Blocking request.")

                return "Malicious request detected and blocked by WAF.", 403
 
    url = f"{DVWA_URL}/{path}"
    
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers={key: value for (key, value) in request.headers if key != 'host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )


        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.headers.items()
                   if name.lower() not in excluded_headers]

        response = Response(resp.content, resp.status_code, headers)
        return response

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to backend server: {e}")
        return "Error: Could not connect to the backend application.", 502


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)