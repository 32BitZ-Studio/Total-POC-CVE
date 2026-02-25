CC := gcc

.PHONY: all clean

all: load_and_encrypt_config

load_and_encrypt_config: load_and_encrypt_config.c
	$(CC) $^ -o $@

clean:
	rm -rf load_and_encrypt_config redis.conf
