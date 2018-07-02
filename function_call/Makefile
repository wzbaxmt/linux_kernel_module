A_DIR = A
B_DIR = B
SUBDIRS = $(A_DIR) $(B_DIR)
SUBDIRS_CLEAN = $(addsuffix .clean, $(SUBDIRS))

.PHONY: clean $(SUBDIRS)

all: $(SUBDIRS)
clean: $(SUBDIRS_CLEAN)

$(SUBDIRS):
	$(MAKE) -C $@

$(SUBDIRS_CLEAN): %.clean:
	$(MAKE) -C $* clean
