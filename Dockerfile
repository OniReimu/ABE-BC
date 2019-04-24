FROM ubuntu:16.04

WORKDIR /app

ENV DEBIAN_FRONTEND noninteractive

# Install SSH
RUN echo root:123456 | chpasswd && \
	apt-get update && \
	apt-get install openssh-server -y && \
	sed -i -e 's|PermitRootLogin prohibit-password|PermitRootLogin yes|' /etc/ssh/sshd_config && \
	sed -i -e 's|UsePAM yes|UsePAM no|' /etc/ssh/sshd_config

# ADD PPA and python-pip
RUN apt-get update && \
	apt-get install -y --no-install-recommends apt-utils && \
	apt-get install -y python3-pip && \
	pip3 install --upgrade pip

# Upgrade the python3.5 to 3.6
RUN apt-get install -y software-properties-common && \
	add-apt-repository ppa:jonathonf/python-3.6 && \
	apt-get update && \
	apt-get install -y python3.6

# Install dependencies.
ADD requirements.txt /app
RUN cd /app && \
    pip3 install -r requirements.txt

# Install charm crypto
RUN apt update && apt install --yes build-essential flex bison wget subversion m4 python3 python3-dev python3-setuptools libgmp-dev libssl-dev
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar xvf pbc-0.5.14.tar.gz && cd ./pbc-0.5.14 && ./configure LDFLAGS="-lgmp" && make && make install && ldconfig
COPY ./charm/ /charm
RUN cd /charm && ./configure.sh && make && make install && ldconfig && cp -r /usr/local/lib/python3.5/dist-packages/ /usr/local/lib/python3.6

# Add actual source code.
ADD blockchain.py /app

EXPOSE 22
EXPOSE 5000
EXPOSE 5001
EXPOSE 5002

# CMD ["python3.6", "blockchain.py", "--port", "5000"]
