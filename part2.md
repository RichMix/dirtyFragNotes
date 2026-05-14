The second half of Dirty Frag is structurally similar to the first, but lives in a different subsystem and has different operational properties. It is the variant that runs on hosts where the xfrm-ESP variant is blocked.

Where the Bug Lives
The relevant function is rxkad_verify_packet_1() in the RxRPC kernel module (rxrpc.ko). RxRPC is the kernel-side implementation of the RPC protocol used by the Andrew File System. The verify function performs an in-place single-block decrypt on the first 8 bytes of the rxrpc payload:

sg_init_table(sg, ARRAY_SIZE(sg));
ret = skb_to_sgvec(skb, sg, sp->offset, 8);
memset(&iv, 0, sizeof(iv));
skcipher_request_set_sync_tfm(req, call->conn->rxkad.cipher);
skcipher_request_set_crypt(req, sg, sg, 8, iv.x);   // src == dst
ret = crypto_skcipher_decrypt(req);
skb_to_sgvec() translates the skb's frag directly into the scatter-gather list. If the frag was planted via splice, the list now points at the attacker's page cache page. The set_crypt call with sg, sg makes the operation in-place. The decrypt runs and writes 8 bytes back to the same page.

The 8-Byte STORE
The cipher in use is pcbc(fcrypt), with the IV set to zero. For a single block, PCBC reduces to a plain fcrypt_decrypt(C, K). fcrypt is an Andrew File System cipher with a 56-bit key and an 8-byte block.

This is where the RxRPC variant differs sharply from the xfrm-ESP variant. With xfrm-ESP, the 4 bytes written are seq_hi, a value the attacker hands to the kernel directly. With RxRPC, the 8 bytes written are fcrypt_decrypt(C, K), where C is the actual ciphertext bytes that already exist at that file offset, and K is the session key the attacker registers in user-space.

The attacker can therefore choose K, but cannot directly choose what gets written. To plant a desired 8-byte plaintext, the attacker has to brute force K in user-space until fcrypt_decrypt(C, K) returns the desired pattern. The cost grows exponentially with the number of constrained plaintext bytes. Constraining all 8 bytes is infeasible (around 2⁵⁶ keys), but constraining only 2 or 3 bytes is fast.

Privilege Requirement
The session key is registered via add_key("rxrpc", desc, payload, ..., KEY_SPEC_PROCESS_KEYRING). Registering an RxRPC key requires no special capabilities. The trigger uses a UDP socket pair and an AF_RXRPC socket, both of which are accessible to unprivileged users. No namespace creation is required.

The constraint that affects this variant is module availability. The RxRPC variant only works if the rxrpc.ko module is loaded. The V4bel writeup specifically calls out RHEL 10.1's default build as not shipping rxrpc.ko, and notes that the module is absent from most distributions in general. On Ubuntu, however, the module is loaded by default, which is precisely where the namespace-blocking AppArmor policy makes the xfrm-ESP variant unreliable. Each variant covers the other's blind spot.

Choosing /etc/passwd Instead of /usr/bin/su
The xfrm-ESP variant overwrites a 192-byte ELF over /usr/bin/su in 48 separate 4-byte writes. The RxRPC variant cannot do this. Each 8-byte write requires its own user-space brute force, and even with fcrypt running at around 18 million keys per second, writing 192 bytes of fully constrained shellcode would take longer than several lifetimes.

The variant targets /etc/passwd instead. The first line of /etc/passwd reads:

root:x:0:0:root:/root:/bin/bash
The exploit overwrites characters 4 through 15 with the pattern ::0:0:GGGGGG: using three overlapping 8-byte writes at offsets 4, 6, and 8. Last-write-wins resolves the overlap. The result is:

root::0:0:GGGGGG:/root:/bin/bash
Note that the password field (between the first two colons) is now empty. PAM's pam_unix.so nullok accepts an empty password and returns PAM_SUCCESS without prompting. A subsequent su - runs without any authentication challenge, drops to UID 0, and execs /bin/bash.

Only 12 bytes of plaintext need to be controlled, of which 5 of them carry the very weak constraint of "anything other than colon, newline, or null". The brute force completes in roughly five milliseconds for the first two writes and around one second for the third.


Mark as complete
