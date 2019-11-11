import sys
import struct
from base64 import b64encode
from hashlib import sha1
import logging
from socket import error as SocketError
import errno
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

logger = logging.getLogger(__name__)
logging.basicConfig()

FIN    = 0x80
OPCODE = 0x0f
MASKED = 0x80
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e
PAYLOAD_LEN_EXT64 = 0x7f

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT         = 0x1
OPCODE_BINARY       = 0x2
OPCODE_CLOSE_CONN   = 0x8
OPCODE_PING         = 0x9
OPCODE_PONG         = 0xA

# API untuk menjalankan server web socket
class API():

    def run_forever(self):
        try:
            logger.info("Listening on port %d for clients.." % self.port)
            self.serve_forever()
        except KeyboardInterrupt:
            self.server_close()
            logger.info("Server terminated.")
        except Exception as e:
            logger.error(str(e), exc_info=True)
            exit(1)

    def new_client(self, client, server):
        pass

    def client_left(self, client, server):
        pass

    def message_received(self, client, server, message):
        pass

    def set_fn_new_client(self, fn):
        self.new_client = fn

    def set_fn_client_left(self, fn):
        self.client_left = fn

    def set_fn_message_received(self, fn):
        self.message_received = fn

    def send_message(self, client, msg, opcode):
        self._unicast_(client, msg, opcode)

    def send_message_to_all(self, msg):
        self._multicast_(msg)

# Kelas untuk web socket server yang dapat menghandle beberapa client
class WebsocketServer(ThreadingMixIn, TCPServer, API):
    allow_reuse_address = True
    daemon_threads = True  # untuk membuat thread tetap berjalan hingga selesai

    # tempat penampungan untuk client
    clients = []
    id_counter = 0

    def __init__(self, port, host='127.0.0.1', loglevel=logging.WARNING):
        logger.setLevel(loglevel)
        TCPServer.__init__(self, (host, port), WebSocketHandler)
        self.port = self.socket.getsockname()[1]

    def _message_received_(self, handler, msg):
        self.message_received(self.handler_to_client(handler), self, msg)

    def _ping_received_(self, handler, msg):
        handler.send_pong(msg)

    def _pong_received_(self, handler, msg):
        pass

    def _new_client_(self, handler):
        self.id_counter += 1
        client = {
            'id': self.id_counter,
            'handler': handler,
            'address': handler.client_address
        }
        self.clients.append(client)
        self.new_client(client, self)

    def _client_left_(self, handler):
        client = self.handler_to_client(handler)
        self.client_left(client, self)
        if client in self.clients:
            self.clients.remove(client)

    def _unicast_(self, to_client, msg, opcode):
        to_client['handler'].send_message(msg, opcode)

    def _multicast_(self, msg):
        for client in self.clients:
            self._unicast_(client, msg)

    def handler_to_client(self, handler):
        for client in self.clients:
            if client['handler'] == handler:
                return client

# Kelas yang berisi fungsi-fungsi untuk membantu fungsionalitas pada web socket server
class WebSocketHandler(StreamRequestHandler):

    def __init__(self, socket, addr, server):
        self.server = server
        StreamRequestHandler.__init__(self, socket, addr, server)

    def setup(self):
        StreamRequestHandler.setup(self)
        self.keep_alive = True
        self.handshake_done = False
        self.valid_client = False

    def handle(self):
        while self.keep_alive:
            if not self.handshake_done:
                self.handshake()
            elif self.valid_client:
                self.read_next_data()

    def read_bytes(self, num):
        bytes = self.rfile.read(num)
        return bytes

    def read_next_data(self):
        # melakukan pembacaan bytes data dari client
        try:
            b1, b2 = self.read_bytes(2)
        except SocketError as e: 
            if e.errno == errno.ECONNRESET:
                logger.info("Client closed connection.")
                self.keep_alive = 0
                return
            b1, b2 = 0, 0
        except ValueError as e:
            b1, b2 = 0, 0

        fin    = b1 & FIN
        opcode = b1 & OPCODE
        masked = b2 & MASKED
        payload_length = b2 & PAYLOAD_LEN

        if opcode == OPCODE_CLOSE_CONN:
            self.keep_alive = 0
            return
        if not masked:
            self.keep_alive = 0
            return
        if opcode == OPCODE_CONTINUATION:
            return
        elif opcode == OPCODE_BINARY:
            opcode_handler = self.server._message_received_
            return
        elif opcode == OPCODE_TEXT:
            opcode_handler = self.server._message_received_
        elif opcode == OPCODE_PING:
            opcode_handler = self.server._ping_received_
        elif opcode == OPCODE_PONG:
            opcode_handler = self.server._pong_received_
        else:
            logger.warn("Unknown opcode %#x." % opcode)
            self.keep_alive = 0
            return

        # handle payload yang lebih dari 125
        if payload_length == 126:
            payload_length = struct.unpack(">H", self.rfile.read(2))[0]
        elif payload_length == 127:
            payload_length = struct.unpack(">Q", self.rfile.read(8))[0]

        masks = self.read_bytes(4)
        message_bytes = bytearray()
        for message_byte in self.read_bytes(payload_length):
            message_byte ^= masks[len(message_bytes) % 4]
            message_bytes.append(message_byte)
        opcode_handler(self, message_bytes.decode('utf8'))

    def send_message(self, message, opcode):
        self.send_text(message, opcode)

    def send_pong(self, message):
        self.send_text(message, OPCODE_PONG)

    def send_text(self, message, opcode):
        header  = bytearray()

        if opcode == 0x1 or opcode == 0xA:
            payload = message.encode('utf-8')
        elif opcode == 0x2: 
            payload = message
        payload_length = len(payload)

        # Normal payload
        if payload_length <= 125:
            header.append(FIN | opcode)
            header.append(payload_length)

        # Extended payload
        elif payload_length >= 126 and payload_length <= 65535:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT16)
            header.extend(struct.pack(">H", payload_length))

        # Huge extended payload
        elif payload_length < 18446744073709551616:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT64)
            header.extend(struct.pack(">Q", payload_length))

        self.request.send(header + payload)
    
    def read_http_headers(self):
        headers = {}
        # baris pertama harus http GET
        http_get = self.rfile.readline().decode().strip()
        assert http_get.upper().startswith('GET')
        # setelahnya harus header
        while True:
            header = self.rfile.readline().decode().strip()
            if not header:
                break
            head, value = header.split(':', 1)
            headers[head.lower().strip()] = value.strip()
        return headers

    # Fungsi untuk melakukan menerima handshake dari client
    def handshake(self):
        headers = self.read_http_headers()

        try:
            assert headers['upgrade'].lower() == 'websocket'
        except AssertionError:
            self.keep_alive = False
            return

        try:
            key = headers['sec-websocket-key']
        except KeyError:
            logger.warning("Client tried to connect but was missing a key")
            self.keep_alive = False
            return

        response = \
          'HTTP/1.1 101 Switching Protocols\r\n'\
          'Upgrade: websocket\r\n'              \
          'Connection: Upgrade\r\n'             \
          'Sec-WebSocket-Accept: %s\r\n'        \
          '\r\n' % self.make_key(key)

        self.handshake_done = self.request.send(response.encode())
        self.valid_client = True
        self.server._new_client_(self)

    @classmethod
    # Fungsi untuk membuat key response sesuai standar rtf
    def make_key(cls, key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        hash = sha1(key.encode() + GUID.encode())
        response_key = b64encode(hash.digest()).strip()
        return response_key.decode('ASCII')

    def finish(self):
        self.server._client_left_(self)