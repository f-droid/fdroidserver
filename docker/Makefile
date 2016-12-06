SHELL := /bin/bash
ALIAS = "dscanner"
EXISTS := $(shell docker ps -a -q -f name=$(ALIAS))
RUNNED := $(shell docker ps -q -f name=$(ALIAS))
ifneq "$(RUNNED)" ""
IP := $(shell docker inspect $(ALIAS) | grep "IPAddress\"" | head -n1 | cut -d '"' -f 4)
endif
STALE_IMAGES := $(shell docker images | grep "<none>" | awk '{print($$3)}')
EMULATOR ?= "android-19"
ARCH ?= "armeabi-v7a"

COLON := :

.PHONY = build clean kill info

all: help

help:
	@echo "usage: make {help|build|clean|kill|info}"
	@echo ""
	@echo "  help    this help screen"
	@echo "  build   create docker image"
	@echo "  clean   remove images and containers"
	@echo "  kill    stop running containers"
	@echo "  info    details of running container"

build:
	@docker build -t "dscanner/fdroidserver:latest" .

clean: kill
	@docker ps -a -q | xargs -n 1 -I {} docker rm -f {}
ifneq "$(STALE_IMAGES)" ""
	@docker rmi -f $(STALE_IMAGES)
endif

kill:
ifneq "$(RUNNED)" ""
	@docker kill $(ALIAS)
endif

info:
	@docker ps -a -f name=$(ALIAS)
ifneq "$(RUNNED)" ""
	$(eval ADBPORT := $(shell docker port $(ALIAS) | grep '5555/tcp' | awk '{split($$3,a,"$(COLON)");print a[2]}'))
	@echo -e "Use:\n adb kill-server\n adb connect $(IP):$(ADBPORT)"
else
	@echo "Run container"
endif
