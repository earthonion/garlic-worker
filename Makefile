PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

PS5_CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_INCDIR := $(PS5_PAYLOAD_SDK)/target/include
PS5_LIBDIR := $(PS5_PAYLOAD_SDK)/target/lib

WORKER_KEY := $(shell python3 -c "import secrets; print(secrets.token_hex(32))")
CFLAGS := -O2 -Wall -D_BSD_SOURCE -std=gnu11 -Isrc -I$(PS5_INCDIR) -DWORKER_KEY=\"$(WORKER_KEY)\"
LDFLAGS := -L$(PS5_LIBDIR)
LIBS := -lkernel_sys -lkernel -lSceSystemService -lSceUserService -lSceFsInternalForVsh

SRCS := src/main.c src/http.c src/config.c src/worker.c src/savedata.c src/zip.c src/json.c src/util.c

all: garlic-worker.elf

garlic-worker.elf: $(SRCS)
	@echo "Worker Key: $(WORKER_KEY)"
	$(PS5_CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f garlic-worker.elf

.PHONY: all clean
