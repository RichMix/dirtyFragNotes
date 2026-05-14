The first half of Dirty Frag is a 4-byte controlled write into the page cache, delivered through the kernel's IPsec ESP input path. The bug has been present since January 2017, giving it the same nine-year lifespan as Copy Fail.

Where the Bug Lives
The relevant function is esp_input() in net/ipv4/esp4.c (and its IPv6 sibling in net/ipv6/esp6.c). Before the patch, the input path took a fast path that skipped skb_cow_data() whenever the skb was uncloned and had no frag_list, even if the skb carried fragments planted via splice. The decision branch looked like this:

if (!skb_cloned(skb)) {
    if (!skb_is_nonlinear(skb)) {
        nfrags = 1;
        goto skip_cow;
    } else if (!skb_has_frag_list(skb)) {
        nfrags = skb_shinfo(skb)->nr_frags;
        nfrags++;
        goto skip_cow;
    }
}
err = skb_cow_data(skb, 0, &trailer);
A non-linear skb with no frag list, made out of attacker-pinned page cache pages, jumped straight to skip_cow. From there, crypto_authenc_esn_decrypt() ran in-place AEAD decryption with src and dst pointing at the same scatter-gather list, both rooted in the attacker's page.

The 4-Byte STORE
Inside crypto_authenc_esn_decrypt(), before the actual decryption, the algorithm rearranges the sequence number bytes. As part of that rearrangement, it performs a 4-byte write at assoclen + cryptlen within the dst scatter-gather list:

scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);
The value being written is the high-order 32 bits of the sequence number (seq_hi). That value is set by the user when registering the IPsec security association via the XFRMA_REPLAY_ESN_VAL netlink attribute. The user fully controls it.

The position of the write is also controllable. By tuning the payload length and the splice offset so that the attacker's page sits at exactly the assoclen + cryptlen position of the dst SGL, the 4 bytes land at any chosen offset within the page cache.

The HMAC verification afterwards fails (the attacker has no idea what the legitimate authentication key is, and supplies a random one). An -EBADMSG is returned to userspace. However, the 4-byte write has already completed before the verification step. The error has no effect on the corruption.

Privilege Requirement
esp_input() only fires for traffic destined for a registered IPsec security association, and registering an SA requires CAP_NET_ADMIN. The exploit obtains that capability by entering a new user namespace via unshare(CLONE_NEWUSER | CLONE_NEWNET). Inside the namespace the process maps itself to root (uid_map: 0 <real_uid> 1) and gains CAP_NET_ADMIN for the namespace's network operations.

This is where Ubuntu's AppArmor policy becomes relevant. Ubuntu often blocks unprivileged user namespace creation through a system-wide AppArmor profile. On hosts where that policy is active, unshare(CLONE_NEWUSER) returns -EPERM and the xfrm-ESP variant cannot be triggered at all. That blind spot is what the RxRPC variant in Task 4 exists to cover.

How the Trigger Reaches esp_input
A direct socket(AF_INET, SOCK_RAW, IPPROTO_ESP) to inject ESP traffic would be visible to any kernel filter watching for raw sockets. The exploit instead routes through the UDP encapsulation path:

A receiver UDP socket is bound to 127.0.0.1:4500 and configured with setsockopt(SOL_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)
A sender UDP socket connects to the same port
A pipe is filled with a forged ESP wire header (8-byte header plus 16-byte IV) via vmsplice, then 16 bytes of /usr/bin/su's page cache via splice
A final splice from pipe to sender socket sends the packet
Once the ESPINUDP-marked socket receives a packet, udp_queue_rcv_one_skb() routes it through xfrm4_udp_encap_rcv() and into xfrm_input(), which delivers it to esp_input(). The flow runs entirely over loopback.

The packet's skb arrives at esp_input() looking like this:

skb {
    head/linear: ESP_hdr(8) + IV(16) = 24 bytes
    frags[0]:    page=&P, off=i*4, size=16    // page cache page of /usr/bin/su
}
The fast path triggers, the in-place decrypt runs, and a 4-byte write lands at offset i*4 of the page. By cycling i from 0 through 47, the exploit assembles a 192-byte static ELF over the first 192 bytes of the cached /usr/bin/su binary. That static ELF executes setgid(0); setuid(0); execve("/bin/sh", ...) at its entry point.

The setuid bit on /usr/bin/su is intact throughout. The kernel still grants effective UID 0 when the binary is executed. The shellcode runs as roo
