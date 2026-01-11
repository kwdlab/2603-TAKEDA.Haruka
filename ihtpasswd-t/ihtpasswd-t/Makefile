CC = gcc

CFLAGS = -O2 -Wall
CFLAGS += -I./include
CFLAGS += -I/usr/include/apr-1.0 

LIBS = -lapr-1
LIBS += -laprutil-1
LIBS += -lcrypt
LIBS += -luchardet
LIBS += -lutf8proc

SRC = htpasswd.c passwd_common.c
OBJ = $(SRC:.c=.o)
TARGET = ihtpasswd

.PHONY: all clean
all: $(TARGET)

$(TARGET): $(OBJ)
		$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
