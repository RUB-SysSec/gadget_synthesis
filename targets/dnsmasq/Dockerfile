FROM ubuntu:18.04 AS dnsmasq-builder

ARG DNSMASQ_VER=2.77
ARG DNSMASQ_URL=http://www.thekelleys.org.uk/dnsmasq/

# archive is outdated, replace with old-releases
#RUN sed -i -- 's/archive/old-releases/g' /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
	gcc \
	make vim tmux\
	build-essential \
	wget curl \
	tar \
	&& rm -r /var/lib/apt/lists/*

WORKDIR /tmp

COPY Makefile .

RUN wget -O /tmp/dnsmasq-$DNSMASQ_VER.tar.gz -q ${DNSMASQ_URL}dnsmasq-$DNSMASQ_VER.tar.gz \
	&& tar -zxvf dnsmasq-$DNSMASQ_VER.tar.gz \
	&& cd dnsmasq-$DNSMASQ_VER \
	&& cp ../Makefile . \
	&& sed -i "s+/usr/local+/opt/dnsmasq+g" Makefile \
	&& make install
