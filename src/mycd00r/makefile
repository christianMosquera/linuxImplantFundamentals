TARGET = sniffer
BUILD_DIR = build
CODEDIRS = . lib
INCDIRS = . ./include/

DEPFLAGS = -MP -MD
CC = gcc
CFLAGS = -Wall $(foreach D,$(INCDIRS),-I$(D)) $(DEPFLAGS)
LDFLAGS = -lpcap -lssl -lcrypto -lcurl

CFILES = $(foreach D,$(CODEDIRS),$(wildcard $(D)/*.c))
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(CFILES))
DEPFILES = $(patsubst %.c,$(BUILD_DIR)/%.d,$(CFILES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -rf $(TARGET) $(BUILD_DIR)

.PHONY: all clean

# Include dependency files if they exist
-include $(DEPFILES)