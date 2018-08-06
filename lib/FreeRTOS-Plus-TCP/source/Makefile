LIB   = $(HOME)/benchs/amazon-freertos/lib
TOP   = $(LIB)/..

ENTRY = DHCPReplies
#ENTRY = DNSReply

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
	-I$(LIB)/FreeRTOS-Plus-TCP/source/portable/Compiler/CompilerName/ \

VPATH=$(LIB)/include/private:$(LIB)/FreeRTOS-PLUS-TCP/source/

CC = gcc

SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

#all:

freertos: $(OBJ)
	$(CC) $(CFLAGS) $(INC) -o $@ $^ 

.c.o: 
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

clean:
	rm *.o

