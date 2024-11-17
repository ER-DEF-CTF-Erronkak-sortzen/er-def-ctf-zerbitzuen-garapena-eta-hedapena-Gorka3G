FROM ubuntu:latest
RUN apt update && apt install -y openssh-server

RUN apt-get install -y python3-scapy
RUN apt-get install -y tcpdump

COPY ./echoRequestSend.py /usr/src/echoRequestSend.py


# Configure SSH  Xabat
RUN mkdir /var/run/sshd
# Start SSH server Xabat
CMD ["/usr/sbin/sshd", "-D"]
