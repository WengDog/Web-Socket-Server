from websocket import WebsocketServer
import hashlib

OPCODE_TEXT         = 0x1
OPCODE_BINARY       = 0x2

# Penanda bahwa client sudah tersambung dengan handshake
def new_client(client, server):
	print("New client connected and was given id %d" % client['id'])

# Penanda bahwa client sudah memutuskan handshake
def client_left(client, server):
	print("Client(%d) disconnected" % client['id'])


# Dipanggil ketika client mengirim data ke server
def message_received(client, server, message):
	if '!echo' in message:
		# Mengurus kasus 1, dimana client mengirim !echo <message> 
		# Server mengirim ulang <message>
		server.send_message(client, message[6:], OPCODE_TEXT)
		print("Client(%d) said: %s" % (client['id'], message))
	elif '!submission' in message:
		# Mengurus kasus 2, dimana client mengirim !submission 
		# Server mengirim berkas zip berisi source code dan readme
		data_file = b''
		with open('Bariancrot.zip', "rb") as f:
			data_file = f.read()
		server.send_message(client, data_file, OPCODE_BINARY)
		print("Client(%d) said %s" % (client['id'], message))
	else:
		# Mengurus kasus 3, dimana client mengirim berkas zip dari kasus 2
		# Server mengirim 1 jika md5 checksum file yang diterima = dengan file yang dikirim
		# mengirim 0 jika berbeda
		message_hash = hashlib.md5(message).hexdigest()
		
		with open('Bariancrot.zip', "rb") as f:
			file_data = f.read()
		data_hash = hashlib.md5(file_data).hexdigest()

		message_hash = message_hash.lower()
		data_hash = data_hash.lower()

		if(message_hash == data_hash):
			server.send_message(client, "1", OPCODE_TEXT)
		else:
			server.send_message(client, "0", OPCODE_TEXT)

PORT=6969
server = WebsocketServer(PORT)
server.set_fn_new_client(new_client)
server.set_fn_client_left(client_left)
server.set_fn_message_received(message_received)
server.run_forever()