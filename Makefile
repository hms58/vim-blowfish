CC = gcc
CFLAGS = -Wall -g -O2 
 
SRC = $(wildcard *.c)
OBJS = $(SRC:.c=.o)
AOUT = blowfish
 
all : $(AOUT) 
 
$(AOUT) : $(OBJS)
	$(CC) -o $@ $^
%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<
clean :
	@rm -f *.o
cleaner : clean
	@rm -f $(AOUT)
