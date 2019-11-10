import socketserver
import hashlib
import base64

class TCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        headers = self.data.split(b"\r\n")

        # is it a websocket request?
        if b"Connection: Upgrade" in self.data and b"Upgrade: websocket" in self.data:
            # getting the websocket key out
            for h in headers:
                if b"Sec-WebSocket-Key" in h:
                    key = h.split(b" ")[1]
        # let's shake hands shall we?
            self.handshake(key)

            while True:
                payload = self.decode_frame(bytearray(self.request.recv(1024).strip()))
                decoded_payload = payload.decode('utf-8')
                self.send_frame(payload)
                print(decoded_payload)
                if b"bye" == decoded_payload.lower():
                    b"Bidding goodbye to our client..."
                    return

                    
        else:
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\n" + \
                                 b"Content-Type: text/plain\r\n" + \
                                 b"Connection: close\r\n" + \
                                 b"\r\n" + \
                                 b"Incorrect request")

    def handshake(self,key):
        # Globally Unique Identifier
        GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

        # Perhitungan key sesuai standar RFC
        key = key + GUID
        resp_key = base64.standard_b64encode(hashlib.sha1(key).digest())

        resp=b"HTTP/1.1 101 Switching Protocols\r\n" + \
             b"Upgrade: websocket\r\n" + \
             b"Connection: Upgrade\r\n" + \
             b"Sec-WebSocket-Accept: %s\r\n\r\n"%(resp_key)
        
        print(resp.decode('ascii'))

        self.request.sendall(resp)

    def decode_frame(self,frame):

        fin = frame[0]

        rsv1 = frame[1]
        rsv2 = frame[2]
        rsv3 = frame[3]
        opcode = frame[4:7]
        mask = frame[8]
        payload_len = frame[9:15]
        if payload_len <= 125:
            payload_len = payload_len
        if payload_len == 126:
            payload_len += frame[16:31]
        if payload_len == 127:
            payload_len += frame[16:79]
        if mask == 1:
            mask_key = frame[9+len(payload_len):9+len(payload_len)+32]
            encrypted_payload = frame[9+len(payload_len)+32:9+len(payload_len)+32 + payload_len]
        if mask == 0:
            encrypted_payload = frame[9+len(payload_len):9+len(payload_len) + payload_len]

        payload = bytearray([encrypted_payload[i] ^ mask[i%4] for i in range(payload_len)])
        # opcode_and_fin = frame[0]

        # # assuming it's masked, hence removing the mask bit(MSB) to get len. also assuming len is <125
        # payload_len = frame[1] - 128

        # mask = frame [2:6]
        # encrypted_payload = frame [6: 6+payload_len]

        # payload = bytearray([ encrypted_payload[i] ^ mask[i%4] for i in range(payload_len)])

        return payload

    def send_frame(self, payload):
        # setting fin to 1 and opcpde to 0x1
        frame = [129]
        # adding len. no masking hence not doing +128
        frame += [len(payload)]
        # adding payload
        frame_to_send = bytearray(frame) + payload

        self.request.sendall(frame_to_send)


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), TCPHandler)
    server.serve_forever()