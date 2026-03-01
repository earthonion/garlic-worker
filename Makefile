PS4_PAYLOAD_SDK ?= $(HOME)/code/ps4/ps4-payload-dev-sdk
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

WORKER_KEY := $(shell python3 -c "import secrets; print(secrets.token_hex(32))")

# Shared sources
SHARED_SRCS := src/config.c src/json.c src/zip.c src/util.c src/log.c

# PS5
PS5_CC      := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_CFLAGS  := -O2 -Wall -D_BSD_SOURCE -std=gnu11 -Isrc -Isrc/ps5 \
               -I$(PS5_PAYLOAD_SDK)/target/include -DWORKER_KEY=\"$(WORKER_KEY)\"
PS5_LDFLAGS := -L$(PS5_PAYLOAD_SDK)/target/lib
PS5_LIBS    := -lkernel_sys -lkernel -lSceSystemService -lSceUserService -lSceFsInternalForVsh -lSceNet
PS5_SRCS    := src/ps5/main.c src/ps5/http.c src/ps5/worker.c src/ps5/savedata.c

# PS4
PS4_CC      := $(PS4_PAYLOAD_SDK)/bin/orbis-clang
PS4_CFLAGS  := -O2 -Wall -std=gnu11 -Isrc -Isrc/ps4 \
               -I$(PS4_PAYLOAD_SDK)/target/include -DWORKER_KEY=\"$(WORKER_KEY)\"
PS4_LDFLAGS := -L$(PS4_PAYLOAD_SDK)/target/lib
PS4_LIBS    := -lkernel -lSceSystemService -lSceUserService -lSceNet
PS4_SRCS    := src/ps4/main.c src/ps4/http.c src/ps4/worker.c src/ps4/savedata.c

# Default: build both
all: ps5 ps4

ps5: garlic-worker-ps5.elf
ps4: garlic-worker-ps4.elf

garlic-worker-ps5.elf: $(PS5_SRCS) $(SHARED_SRCS)
	@echo "Worker Key: $(WORKER_KEY)"
	$(PS5_CC) $(PS5_CFLAGS) $(PS5_LDFLAGS) -o $@ $^ $(PS5_LIBS)

garlic-worker-ps4.elf: $(PS4_SRCS) $(SHARED_SRCS)
	@echo "Worker Key: $(WORKER_KEY)"
	$(PS4_CC) $(PS4_CFLAGS) $(PS4_LDFLAGS) -o $@ $^ $(PS4_LIBS)

clean:
	rm -f garlic-worker-ps5.elf garlic-worker-ps4.elf

.PHONY: all ps5 ps4 clean
