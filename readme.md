# Web Application Security Framework

1. Made virtual environment
2. Installed docker, owasp zap, burpsuite (Owasp and burpsuite need a Java Runtime Environment to run on ), sqlmap
3. Downloaded DVWA using `docker pull vulnerables/web-dvwa`
4. Running image using `docker run --rm -it -p 80:80 vulnerables/web-dvwa`
5. DVWA loaded up at `http:/127.0.0.1`
6. Command to rerun dvwa again: `docker run -d --rm -it -p 8080:80 vulnerables/web-dvwa`. -d is for detach.
7. To check docker running status; `docker ps`
