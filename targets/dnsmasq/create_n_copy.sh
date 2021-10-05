docker create -ti --name dnsmasq-builder-container dnsmasq-builder bash
docker cp dnsmasq-builder-container:/opt/dnsmasq/ .
docker rm -f dnsmasq-builder-container
