WD    = $(abspath .)
LIB   = $(abspath ../lib)
TOP   = $(abspath ..)

#ENTRY = DHCPReplies
ENTRY = DNSReply

SHELL = bash

INC = \
	-I$(LIB)/ \
	-I$(LIB)/include/ \
	-I$(LIB)/include/private \
	-I$(TOP)/demos/ti/cc3220_launchpad/common/config_files/ \
  -I$(TOP)/demos/ti/cc3220_launchpad/common/application_code/ti_code/ \
	-I$(TOP)/demos/espressif/esp32_devkitc_esp_wrover_kit/common/application_code/espressif_code/freertos/include/freertos/ \
	-I$(LIB)/third_party/mcu_vendor/ti/SimpleLink_CC32xx/v2_10_00_04/source/ \
  -I$(LIB)/FreeRTOS/portable/Rowley/MSP430F449/ \
	-I$(LIB)/FreeRTOS/portable/Paradigm/Tern_EE/small/ \
	-I$(LIB)/FreeRTOS-Plus-TCP/include/ \
	-I$(LIB)/FreeRTOS-Plus-TCP/source/portable/Compiler/GCC/ \

#DIRS := $(LIB)/:$(LIB)/include/private:$(LIB)/FreeRTOS-PLUS-TCP/source/
DIRS := $(LIB)/include/private $(LIB)/FreeRTOS-Plus-TCP/source/ $(LIB)/FreeRTOS/
#SOURCE_FILES := $(foreach d, $(DIRS), $(d))
SOURCE_FILES := $(foreach d, $(DIRS), $(wildcard $(d)*.c) )

# Create an object file of every cpp file
OBJECTS = $(patsubst %.c, %.o, $(SOURCE_FILES))
# Dependencies
DEPENDENCIES = $(patsubst %.c, %.d, $(SOURCE_FILES))

# Create .d files
%.d: %.c
	$(CC) -MM $< -MT "$*.o $*.d" -MF $*.d

# Make $(PROJECT) the default target
all: freertos

#SRC = $(wildcard *.c)
#SRC := $(foreach d, $(DIRS), $(wildcard $(d)*.c) )
#OBJ = $(SRC:.c=.o)

# infer flags
INFEROUT = infer-out
INFER    = infer
CLANG    = -- clang
INFERBO  = -a checkers --bufferoverrun

CC = gcc

freertos: $(OBJECTS)
	$(CC) $(CFLAGS) $(INC) -o $@ $^ 

# Include dependencies (if there are any)
ifneq "$(strip $(DEPENDENCIES))" ""
	 include $(DEPENDENCIES)
endif

.c.o: 
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

infer:
	$(INFER) $(INFERBO) run $(CLANG) $(INC) -c $(ENTRY).c

clean:
	$(RM) -r $(INFEROUT) 
	$(RM) -f *.o
