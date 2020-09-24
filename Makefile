project=certmngr
TOP_PATH =$(shell pwd)


.PHONY:clean run d

objs= main.cpp CertMngr.cpp log.cpp platutil.cpp
$(project):$(objs)
	g++ -g $(objs) -o certmngr 
	bash init.sh
	mv certmngr bin/certmngr
	cp ca/etc/client.conf bin/client.conf



clean:
	rm -rf $(TOP_PATH)/bin/ca/
	rm -rf $(TOP_PATH)/bin/cert/
	rm -rf $(TOP_PATH)/bin/csr/
	rm -rf $(TOP_PATH)/bin/tmp/
	rm -rf $(TOP_PATH)/bin/core.certmngr
run:
	$(TOP_PATH)/bin/certmngr
d:
	gdb $(TOP_PATH)/bin/certmngr	$(TOP_PATH)/bin/core.certmngr
sign:
	cp $(TOP_PATH)/bin/csr/* $(TOP_PATH)/ca/client/tmp
	cd $(TOP_PATH)/ca && bash signcsr.sh