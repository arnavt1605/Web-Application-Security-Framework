Command to run DVWA on machine IP: `docker run -d --name dvwa -p 172.17.0.1:8080:80 vulnerables/web-dvwa`

```
docker run -d --name dvwa -p 172.17.0.1:8080:80 vulnerables/web-dvwa
81c628adfa9c9612018250a248899dc6760b64719cc39a6b445a3ca9ad443f7d

~$ docker ps
CONTAINER ID   IMAGE                  COMMAND      CREATED          STATUS          PORTS                     NAMES
81c628adfa9c   vulnerables/web-dvwa   "/main.sh"   15 seconds ago   Up 15 seconds   172.17.0.1:8080->80/tcp   dvwa
```

Command to check machine IP Address: `hostname -I`

Command to test the connection from localhost to DVWA: `curl -v -x http://127.0.0.1:8081 http://172.17.0.1:8080/`
BurpSuite is connected to port 8081 proxy setting and DVWA runs on port 8080 

```
curl -v -x http://127.0.0.1:8081 http://172.17.0.1:8080/
*   Trying 127.0.0.1:8081...
* Connected to 127.0.0.1 (127.0.0.1) port 8081
> GET http://172.17.0.1:8080/ HTTP/1.1
> Host: 172.17.0.1:8080
> User-Agent: curl/8.5.0
> Accept: */*
> Proxy-Connection: Keep-Alive
```
