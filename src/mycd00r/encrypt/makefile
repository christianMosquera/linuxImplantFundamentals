CC=gcc
TARGET=encrypt
LDFLAGS=-lcrypto
CFLAGS=-Wall

CODEDIRS=.
BUILD_DIR = build

CFILES = $(foreach D,$(CODEDIRS),$(wildcard $(D)/*.c))
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(CFILES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c 
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -rf $(TARGET) $(BUILD_DIR)

.PHONY: all clean