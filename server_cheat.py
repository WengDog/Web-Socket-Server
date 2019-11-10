from websocket_server_cheat import WebsocketServer

OPCODE_TEXT         = 0x1
OPCODE_BINARY       = 0x2

# Called for every client connecting (after handshake)
def new_client(client, server):
	print("New client connected and was given id %d" % client['id'])

def calculateMD5(filename, block_size=2**20):
	"""Returns MD% checksum for given file.
	"""
	import hashlib

	md5 = hashlib.md5()
	try:
		file = open(filename, 'rb')
		while True:
			data = file.read(block_size)
			if not data:
				break
			md5.update(data)
	except IOError:
		print('File \'' + filename + '\' not found!')
		return None
	except:
		return None
	return md5.hexdigest

# Called for every client disconnecting
def client_left(client, server):
	print("Client(%d) disconnected" % client['id'])


# Called when a client sends a message
def message_received(client, server, message):
    if '!echo' in message:
        server.send_message(client, message[6:], OPCODE_TEXT)
        print("Client(%d) said: %s" % (client['id'], message))
    elif '!submission' in message:
        temp = b''
        with open('UNIX.zip', "rb") as f:
            temp = f.read()
        server.send_message(client, temp, OPCODE_BINARY)
        print("Client(%d) said %s" % (client['id'], message))
    else:
        print("kasus 3 ga masuk echo, ga masuk submis")
        

    

PORT=8978
server = WebsocketServer(PORT)
server.set_fn_new_client(new_client)
server.set_fn_client_left(client_left)
server.set_fn_message_received(message_received)
server.run_forever()