# Web Application Security Framework

1. Made virtual environment
2. Installed docker, owasp zap, burpsuite (Owasp and burpsuite need a Java Runtime Environment to run on ), sqlmap
3. Downloaded DVWA using `docker pull vulnerables/web-dvwa`
4. Running image using `docker run -d --name dvwa -p 172.17.0.1:8080:80 vulnerables/web-dvwa`
5. DVWA loaded up at `http:/172.17.0.1:8080`
7. To check docker running status; `docker ps`
8. To remove docker image if overlapping: `docker rm -f dvwa`
