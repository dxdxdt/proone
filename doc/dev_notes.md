# Proone Dev Notes

## Potential Improvements
### TODO switching to real threads?

### Put Mbed TLS on Diet
The build is not light because the Mbed TLS library is extensive. Proone is
tested using default Mbed TLS config included in Buildroot, but size reduction
may be achieved by disabling unnessary features like threading and DTLS support.

### Don't Build Clean-up Code
Excluding clean-up code for release build is widely accepted technique to reduce
code size. Proone does not expect user's intervention. Proone is programmed to
exit when SIGINT is received for debugging purposes only. You can also see some
code size reduction from removing the handling of the signal as well.

## Bugs Found
### Musl SOCKETCALL
In the early stage of development, Musl was considered for the libc
implementation as it seemed to have more benefits than uClinux can
[offer](http://www.etalabs.net/compare_libcs.html).
However, it was later determined that, regardless of the benefits, I could not
take the risk of encountering more bugs like
[this one](https://www.openwall.com/lists/musl/2020/08/03/6).
Using Musl is abandoned immediately after the discovery of the bug.

### Mbed TLS `getrandom()` Blocks
https://github.com/ARMmbed/mbedtls/issues/3551

Mbed TLS uses `getrandom()` to initialise CTR_DRBG contexts. On systems where
the function is not available, the library falls back to using `/dev/urandom`,
which never blocks. This contracts the behaviour of `getrandom()` function.

`prne_mbedtls_entropy_init()` had to be implemented to modify the "factory"
function for creating CTR_DRBG contexts so that the library always uses
`/dev/urandom`. This would have been unacceptable measure if Proone handles
sensitive data, but the main purpose of Proone using TLS is to hide its
characteristics so that it's hard for law enforcements or ISPs to filter the
traffic of Proone.

### Pthsem's Improper Use of `FD_SET()`
Calling `FD_SET()` with a negative fd value is undefined. Pthsem uses `select()`
for internal scheduling and the fd value is not check in `pth_poll()`. Therefore
calling `pth_poll()` with `pollfd` with negative fds results in undefined
behaviour because the fd values are propagated to `FD_SET()`. uClibc does not
take this well and the program crashes with SIGBUS. Nothing serious happens if
the program is linked with Glibc on x86 hosts.

To get around this issue, `prne_pth_poll()` is used where the use of
`pth_poll()` is required. In `prne_pth_poll()`, the `pollfd` elements with
negative fd values are transparently filtered out before passed to `pth_poll()`.

## Problems
### Evading Packet Sniffing
Lawful interception is conducted in most countries. Law enforcements often use
the characteristics exhibited by malwares to prevent the spread by filtering
traffic. These are the "characteristics" of Proone.

* SYN packets to remote port 64420[^2]
* The ALPN string "prne-htbt" in TLS hello messages
* Client and server certificates in TLS hello messages
* Spewing of crafted SYN packets followed by RST packets if the remote end has
  that port open[^1]

Most of the characteristics can be changed by regenerating the PKI or using
different port for Heartbeat.

The use of ALPN can be disabled by not setting the ALPN list for ssl config(ie.
not calling `mbedtls_ssl_conf_alpn_protocols()`).


[^1]: The crafted packets are not recognised by the kernel because no socket is
associated with the port. The kernel is forced to send a RST back and this
packet will reach the remote end if there's no firewall in the way that filters
it.
[^2]: The port 64420 is in the ephemeral port range. Blocking this port may lead
to mild consequences for ISPs.
