# SPDX-License-Identifier: GPL-2.0
CC      ?= clang
CFLAGS  ?= -Wall -Wextra -O2 -static
TARGET  := test_redirect

all: $(TARGET)

$(TARGET): test_redirect.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
