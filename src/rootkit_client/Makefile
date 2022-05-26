export V?=0

# If _HOST specific compiler is not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)"

.PHONY: clean
clean:
	$(MAKE) -C host clean
