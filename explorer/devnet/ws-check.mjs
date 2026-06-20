#!/usr/bin/env node
// A tiny raw-socket WebSocket client to smoke-test the explorer's live feed:
// performs the RFC 6455 handshake against /ws and prints any broadcast frames.
// Usage: node devnet/ws-check.mjs [port]
import net from 'node:net';

const port = Number(process.argv[2] || 8730);
const sock = net.connect(port, '127.0.0.1', () => {
  sock.write(
    'GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n' +
      'Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
      'Sec-WebSocket-Version: 13\r\n\r\n',
  );
});

let handshook = false;
sock.on('data', (buf) => {
  if (!handshook) {
    const text = buf.toString('latin1');
    console.log('HANDSHAKE:', text.split('\r\n')[0]);
    handshook = true;
    const end = text.indexOf('\r\n\r\n');
    const rest = buf.subarray(end + 4);
    if (rest.length) decode(rest);
  } else {
    decode(buf);
  }
});
sock.on('error', (e) => console.log('ERROR:', e.message));

function decode(buf) {
  let i = 0;
  while (i + 2 <= buf.length) {
    const op = buf[i] & 0x0f;
    let len = buf[i + 1] & 0x7f;
    i += 2;
    if (len === 126) {
      len = buf.readUInt16BE(i);
      i += 2;
    } else if (len === 127) {
      len = Number(buf.readBigUInt64BE(i));
      i += 8;
    }
    const payload = buf.subarray(i, i + len);
    i += len;
    if (op === 0x1) console.log('FRAME:', payload.toString('utf8'));
  }
}

setTimeout(() => process.exit(0), 6000);
