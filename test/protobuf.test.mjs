import test from 'node:test';
import assert from 'node:assert/strict';
import { concatBytes, decodeProvisioningAddress, decodeWebSocketMessage, encodeResponse, encodeVarint } from '../app/protobuf.mjs';

const encoder = new TextEncoder();
const number = (field, value) => concatBytes(encodeVarint(field * 8), encodeVarint(value));
const binary = (field, value) => concatBytes(encodeVarint(field * 8 + 2), encodeVarint(value.length), value);
const text = (field, value) => binary(field, encoder.encode(value));
function request(id = 1n, address = 'opaque-address-123') {
  return concatBytes(number(1, 1), binary(2, concatBytes(
    text(1, 'PUT'), text(2, '/v1/address'), binary(3, text(1, address)), number(4, id),
  )));
}

test('decodes the current Signal provisioning request and preserves uint64 IDs', () => {
  const id = 0xffffffffffffffffn;
  const result = decodeWebSocketMessage(request(id));
  assert.equal(result.type, 'request');
  assert.equal(result.verb, 'PUT');
  assert.equal(result.path, '/v1/address');
  assert.equal(result.id, id);
  assert.equal(decodeProvisioningAddress(result.body), 'opaque-address-123');
});

test('response ACK uses the matching request ID and 200 status', () => {
  const result = decodeWebSocketMessage(encodeResponse(9007199254740993n));
  assert.deepEqual(result, { type: 'response', id: 9007199254740993n, status: 200, message: 'OK' });
});

test('unknown valid fields are skipped, including fixed32 and fixed64', () => {
  const extra = concatBytes(Uint8Array.of(0x25, 1, 2, 3, 4), Uint8Array.of(0x29, 1, 2, 3, 4, 5, 6, 7, 8));
  assert.equal(decodeWebSocketMessage(concatBytes(request(), extra)).type, 'request');
});

test('truncated frames, length overflow and invalid tags fail closed', () => {
  const valid = request();
  for (let end = 0; end < valid.length; end++) assert.throws(() => decodeWebSocketMessage(valid.slice(0, end)));
  for (const bad of [Uint8Array.of(0), Uint8Array.of(8, 0x80), Uint8Array.of(8, 1, 18, 0xff, 0xff, 0xff, 0xff, 0x0f), Uint8Array.of(0x0b)]) {
    assert.throws(() => decodeWebSocketMessage(bad));
  }
});

test('uint64 overflow and out-of-range encoder values are rejected', () => {
  assert.throws(() => decodeWebSocketMessage(concatBytes(Uint8Array.of(8), Uint8Array.from([255,255,255,255,255,255,255,255,255,2]))));
  assert.throws(() => encodeVarint(-1));
  assert.throws(() => encodeVarint(1n << 64n));
});

test('duplicate singular fields and conflicting envelopes are rejected', () => {
  assert.throws(() => decodeWebSocketMessage(concatBytes(request(), number(1, 1))));
  assert.throws(() => decodeWebSocketMessage(concatBytes(request(), binary(3, new Uint8Array()))));
  assert.throws(() => decodeProvisioningAddress(concatBytes(text(1, 'one'), text(1, 'two'))));
});

test('invalid UTF-8, empty/control-character addresses and oversize input are rejected', () => {
  for (const bad of [binary(1, Uint8Array.of(0xff)), text(1, ''), text(1, 'abc\n'), text(1, 'x'.repeat(1025))]) {
    assert.throws(() => decodeProvisioningAddress(bad));
  }
  assert.throws(() => decodeWebSocketMessage(new Uint8Array(65537)));
});

test('excessive fields and wrong wire types are rejected', () => {
  assert.throws(() => decodeProvisioningAddress(concatBytes(...Array.from({ length: 129 }, () => number(9, 1)))));
  assert.throws(() => decodeProvisioningAddress(number(1, 123)));
  assert.throws(() => encodeResponse(1n, 999));
});
