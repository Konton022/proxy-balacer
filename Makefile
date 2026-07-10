.PHONY: build install restart stop status logs

build:
	cd /opt/proxy-balancer && go build -o proxy-balancer .

install: build
	cp /opt/proxy-balancer/proxy-balancer /opt/proxy-balancer/proxy-balancer
	systemctl restart proxy-balancer

restart: install

stop:
	systemctl stop proxy-balancer

status:
	systemctl status proxy-balancer

logs:
	journalctl -u proxy-balancer -f
