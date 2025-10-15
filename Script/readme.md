1. For testing purposes DVWA has to run on `172.17.0.1:8080 -> 80` But for running the `waf.py` script this is not the case.
2. Need to create a new container `docker run --rm -it -p 8080:80 --name dvwa vulnerables/web-dvwa`
