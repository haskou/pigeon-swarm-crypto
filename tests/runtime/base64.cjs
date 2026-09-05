const assert = require('node:assert/strict');
const { StrictBase64 } = require('../../dist/internal/StrictBase64');

const payload = Buffer.alloc(8 * 1024 * 1024, 191).toString('base64');
const invalid = new Error('Invalid Base64');

assert.doesNotThrow(() => StrictBase64.ensure(payload, invalid));
assert.throws(() => StrictBase64.ensure(payload.slice(0, -4) + '!!!!', invalid), invalid);
assert.throws(() => StrictBase64.ensure('AA=A', invalid), invalid);
assert.throws(() => StrictBase64.ensure('A===', invalid), invalid);
assert.throws(() => StrictBase64.ensure('AAAA\\n', invalid), invalid);
assert.throws(() => StrictBase64.ensure('', invalid), invalid);
assert.doesNotThrow(() => StrictBase64.ensure('', invalid, { allowEmpty: true }));
console.log('PASS: maximum-size Base64 validation with a 256 KiB stack');
