# Call media frames

`CallMediaFrameCipher` encrypts encoded audio and video frames end to end
inside WebRTC insertable streams, so relays and SFUs only forward ciphertext.

`CallMediaFrameCipher.fromKey(key)` copies a 256-bit `SymmetricKey`, normally
the call key exported from the group epoch. `seal(frame)` returns
`"PSCE1" || nonce || ciphertext || tag` with AES-256-GCM, a fresh random 96-bit
nonce per frame and no AAD. Frames are at most 8 MiB.

`hasMarker(frame)` tells encrypted frames from plaintext ones without
decrypting. `open(frame)` requires the marker, at least 33 bytes and at most
8 MiB plus 33 bytes, and throws `InvalidCallMediaFrameError` for any frame that
does not authenticate.

With random 96-bit nonces a key should protect fewer than 2^32 frames. Rotate
the call key with the group epoch. The class works in Node, browsers and
dedicated workers.

`vectors/call-media-frame.json` pins sealed frames with their injected nonces.
