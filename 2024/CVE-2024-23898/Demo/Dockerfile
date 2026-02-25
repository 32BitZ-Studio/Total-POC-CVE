# Use the official Jenkins image as the base
FROM jenkins/jenkins:2.441

# Switch to root user to install packages
USER root

# Install OpenSSH server
RUN apt-get update && apt-get install -y openssh-server && \
    mkdir /var/run/sshd && \
    echo "jenkins:jenkins" | chpasswd

# Configure SSH to allow Jenkins user access
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# Allow Jenkins to be run as a service with SSH
RUN echo "export PATH=$PATH:/usr/local/bin" >> /etc/profile

# Expose SSH port (default: 22) and Jenkins port (8080)
EXPOSE 22 8080

# Start SSH and Jenkins services
CMD service ssh start && /usr/local/bin/jenkins.sh
