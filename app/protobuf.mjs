// Diagnostic-only subset of Signal's chat_websocket.proto and chat_provisioning.proto.
// Schema: signalapp/libsignal@8be00c282001caa3585d18de0f044c6d500348ab/rust/net/src/proto/
// This does not decode message envelopes or perform account provisioning.
const utf8 = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();
const MAX_FRAME = 64 * 1024;
const MAX_FIELDS = 128;
const UINT64_MAX = (1n << 64n) - 1n;

function bytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  throw new TypeError('Expected binary protobuf bytes');
}

function readVarint(input, cursor) {
  let value = 0n;
  for (let n = 0; n < 10; n++) {
    if (cursor.offset >= input.length) throw new Error('Truncated protobuf varint');
    const byte = input[cursor.offset++];
    if (n === 9 && byte > 1) throw new Error('Protobuf uint64 overflow');
    value |= BigInt(byte & 0x7f) << BigInt(n * 7);
    if (!(byte & 0x80)) return value;
  }
  throw new Error('Overlong protobuf varint');
}

function parseFields(value) {
  const input = bytes(value);
  if (input.length > MAX_FRAME) throw new Error('Protobuf frame exceeds diagnostic size limit');
  const cursor = { offset: 0 };
  const result = new Map();
  let count = 0;
  while (cursor.offset < input.length) {
    if (++count > MAX_FIELDS) throw new Error('Too many protobuf fields');
    const tag = readVarint(input, cursor);
    if (tag > 0xffffffffn) throw new Error('Invalid protobuf tag');
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (field === 0 || field > 0x1fffffff) throw new Error('Invalid protobuf field number');
    let item;
    if (wire === 0) item = readVarint(input, cursor);
    else if (wire === 1 || wire === 2 || wire === 5) {
      const length = wire === 1 ? 8 : wire === 5 ? 4 : Number(readVarint(input, cursor));
      if (!Number.isSafeInteger(length) || length < 0 || length > input.length - cursor.offset) {
        throw new Error('Truncated protobuf field');
      }
      item = input.subarray(cursor.offset, cursor.offset + length);
      cursor.offset += length;
    } else throw new Error('Unsupported protobuf wire type');
    const values = result.get(field) ?? [];
    values.push({ wire, value: item });
    result.set(field, values);
  }
  return result;
}

function one(fields, number, wire, required = false) {
  const matches = fields.get(number) ?? [];
  if (matches.length > 1) throw new Error(`Duplicate protobuf field ${number}`);
  if (!matches.length) {
    if (required) throw new Error(`Missing protobuf field ${number}`);
    return undefined;
  }
  if (matches[0].wire !== wire) throw new Error(`Invalid wire type for field ${number}`);
  return matches[0].value;
}

function string(value, limit) {
  if (value === undefined) return undefined;
  if (value.length > limit) throw new Error('Protobuf string exceeds diagnostic limit');
  return utf8.decode(value);
}

export function decodeProvisioningAddress(input) {
  const fields = parseFields(input);
  const address = string(one(fields, 1, 2, true), 1024);
  if (!address || /[\u0000-\u001f\u007f]/u.test(address)) throw new Error('Invalid provisioning address');
  // Upstream defines this as an opaque address, not necessarily a UUID.
  return address;
}

export function decodeWebSocketMessage(input) {
  const fields = parseFields(input);
  const type = one(fields, 1, 0, true);
  if (type === 1n) {
    if (fields.has(3)) throw new Error('Unexpected response on request frame');
    const request = parseFields(one(fields, 2, 2, true));
    return {
      type: 'request',
      verb: string(one(request, 1, 2, true), 32),
      path: string(one(request, 2, 2, true), 256),
      body: one(request, 3, 2) ?? new Uint8Array(),
      id: one(request, 4, 0, true),
    };
  }
  if (type === 2n) {
    if (fields.has(2)) throw new Error('Unexpected request on response frame');
    const response = parseFields(one(fields, 3, 2, true));
    const status = one(response, 2, 0, true);
    if (status > 0xffffffffn) throw new Error('Response status overflow');
    return {
      type: 'response', id: one(response, 1, 0, true), status: Number(status),
      message: string(one(response, 3, 2), 1024),
    };
  }
  throw new Error('Unknown Signal WebSocket frame type');
}

export function encodeVarint(value) {
  let number = BigInt(value);
  if (number < 0n || number > UINT64_MAX) throw new Error('Value outside protobuf uint64 range');
  const result = [];
  do {
    const low = Number(number & 0x7fn);
    number >>= 7n;
    result.push(low | (number ? 0x80 : 0));
  } while (number);
  return Uint8Array.from(result);
}

export function concatBytes(...parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

export function encodeResponse(id, status = 200, message = 'OK') {
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new Error('Invalid response status');
  const text = encoder.encode(message);
  if (text.length > 1024) throw new Error('Response message too long');
  const response = concatBytes(
    Uint8Array.of(8), encodeVarint(id),
    Uint8Array.of(16), encodeVarint(status),
    Uint8Array.of(26), encodeVarint(text.length), text,
  );
  return concatBytes(Uint8Array.of(8, 2, 26), encodeVarint(response.length), response);
}
