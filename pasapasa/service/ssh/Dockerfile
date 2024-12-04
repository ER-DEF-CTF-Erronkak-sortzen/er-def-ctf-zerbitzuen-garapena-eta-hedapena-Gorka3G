FROM ubuntu:latest
RUN apt update && apt install -y openssh-server

# Configure SSH  Xabat
RUN mkdir /var/run/sshd
# Start SSH server Xabat
CMD ["/usr/sbin/sshd", "-D"]
