// A minimal RFC 6455 WebSocket server over Node's HTTP `upgrade` event — no
// external dependency. The feed is server→client only: the hub broadcasts new
// blocks and transactions as the indexer ingests them. Inbound frames are only
// inspected enough to answer pings and honor close.

import { createHash } from 'node:crypto';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export class WsHub {
  constructor() {
    this.clients = new Set();
  }

  handleUpgrade(req, socket) {
    const key = req.headers['sec-websocket-key'];
    if (!key) {
      socket.destroy();
      return;
    }
    const accept = createHash('sha1').update(key + GUID).digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    socket.setNoDelay(true);
    this.clients.add(socket);

    socket.on('data', (buf) => this._onData(socket, buf));
    const drop = () => this.clients.delete(socket);
    socket.on('close', drop);
    socket.on('error', drop);
  }

  _onData(socket, buf) {
    if (buf.length < 2) return;
    const opcode = buf[0] & 0x0f;
    if (opcode === 0x8) {
      // close
      this.clients.delete(socket);
      socket.end();
    } else if (opcode === 0x9) {
      // ping -> pong
      if (socket.writable) socket.write(encodeFrame(Buffer.alloc(0), 0xa));
    }
  }

  broadcast(obj) {
    if (this.clients.size === 0) return;
    const frame = encodeFrame(Buffer.from(JSON.stringify(obj)), 0x1);
    for (const socket of this.clients) {
      if (socket.writable) socket.write(frame);
    }
  }

  count() {
    return this.clients.size;
  }
}

/** Encode an unmasked server frame (FIN set) with the given opcode. */
function encodeFrame(payload, opcode) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}
