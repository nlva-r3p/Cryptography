CC = gcc
CFLAGS  = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS  = -lcrypto

# Preprocessor flags for client and server builds:
CLIENT_FLAGS = -DCLIENT_BUILD
SERVER_FLAGS = -DSERVER_BUILD

CLIENT_OBJS = rsa_common_client.o rsa_encrypt.o net_utils.o client_main.o
SERVER_OBJS = rsa_common_server.o rsa_decrypt.o net_utils.o server_main.o

all: client server

client: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(CLIENT_FLAGS) -o $@ $(CLIENT_OBJS) $(LDFLAGS) $(LDLIBS)

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(SERVER_FLAGS) -o $@ $(SERVER_OBJS) $(LDFLAGS) $(LDLIBS)

# Compile rsa_common.c for the client.
rsa_common_client.o: rsa_common.c
	$(CC) $(CFLAGS) $(CLIENT_FLAGS) -c rsa_common.c -o $@

# Compile rsa_common.c for the server.
rsa_common_server.o: rsa_common.c
	$(CC) $(CFLAGS) $(SERVER_FLAGS) -c rsa_common.c -o $@

# Generic rule for other .c files.
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) *.o client server

.PHONY: test
test: all
	@echo "Starting server in background..."
	@./server &
	@sleep 2
	@echo "Running client..."
	@./client
	@sleep 2
	@pkill server
