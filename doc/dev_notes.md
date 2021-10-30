# Proone Dev Notes

## Platform-specifics
### Erasing arguments passed to Proone
The Proone instance processes may look suspicious because the cmdline string
contains long base64 strings. Modification of cmdline is platform-specific.

* Linux: Zero-filling all `main()` argv elements after index 0, as per *ps(1)*
> command with all its arguments as a string.  Modifications to the arguments
may be shown.

### Querying link-local addresses
* Linux: *getifaddrs(3)*

## "Hacks"
### Use lightweight crypto
The RSA keys are at least 2048 bits long. Consider using elliptic-curve based
alternatives to reduce the size of the executables.

## Potential Improvements
### Switching to real threads?
Cooperative threading is employed to limit the execution of the process to one
physical thread and for ease of programming. The majority of embedded devices,
especially the vulnerable ones, have one physical thread so there will be
improvements for those devices from using the "real/conventional" preemptive
threading. However, multithread embedded devices will benefit from it due to
reduction in context switching. The number of threads will still have to be
limited because in the worst case(or best?) scenario, the instance can spawn
a large number of bne workers. Although there's no doubt that a regular PC is
capable of running 100 or more bne workers.

The original idea was to implement both cooperative and preemtive threading
using C macros. You'll find some condition variables and locks for this purpose
in the resolv implementation. This idea was abandoned. Should you have to switch
to real threads, expect some race condition related bugs.

### Put Mbed TLS on Diet
The build is not light because the Mbed TLS library is extensive. Proone is
tested using default Mbed TLS config included in Buildroot, but size reduction
may be achieved by disabling unnessary features like threading and DTLS support.

### Don't Build Clean-up Code
Disabling clean-up code for release build is widely accepted technique to reduce
code size. Proone does not expect user's intervention. Proone is programmed to
exit when SIGINT is received for debugging purposes only. You can also see some
code size reduction from removing the handling of the signal as well.

### Using SSH Subchannel for Transfering Binary Data
Data transfer over a SSH session can be optimised by using a separate SSH
channel for data transfer. The current implementation uses the data transfer
method using commands available on the host such as echo and base64. This method
is slow and expensive, even for regular PCs, but it's the only feasible method
of transfering binary data over telnet connections.

On a SSH connection, however, multiple channels can be created. Once the
availability of the commands are checked, a separate channel can be opened for
data transfer. To give you an idea,

```sh
ssh user@host "cat > file" < file
# or even better
gzip -c file | ssh user@host "gzip -cd > file"
```

## Ideas
### "Organic" Cred Dict
Rather than relying on the cred dict, program instances to try a few randomly
generated comboes before trying cred dict. If the instance gets a working random
combo, save it on memory. During the htbt m2m, exchange the saved random comboes
to see if there's any common combo found by both parties. If there is, add that
combo to the cred dict with the lowest weight value. If the combo already exists
in the cred dict, increment the weight value.

This will require the instance's ability to manipulate the cred dict, which is
stored in dvault. Would it be beneficial, considering the size of code that will
incur? The change of getting random combo is slim and two instances getting the
same combo and exchanging it is even more slim. The screening process(exchange
of the random combos) is necessary because well-designed devices are shipped
with randomly generated default login credentials. The process screens the
credentials from these devices.

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
* Spewing crafted SYN packets followed by RST packets if the remote end has that
  port open[^1]
* Bogus ICMPv6 packets multicast to the link-local network. The packets contain
  a destination option that the node should not process. The recipient nodes are
  required to notify the source node by sending an ICMPv6 packet with type 4 and
  code 2

Most of the characteristics can be changed by regenerating the PKI or using
different port for Heartbeat.

The use of ALPN can be disabled by not setting the ALPN list for ssl config(ie.
not calling `mbedtls_ssl_conf_alpn_protocols()`).

### Risky Binary Upgrade
From *execve(2)*:

> In  most cases where execve() fails, control returns to the original
executable image, and the caller of execve() can then handle the error.
However, in (rare) cases (typically  caused  by resource  exhaustion),  failure
may occur past the point of no return: the original executable image has been
torn down, but the new image could not be completely built.  In such cases, the
kernel kills the process with a SIGSEGV (SIGKILL until Linux 3.17) signal.

This means that binary upgrade can result in the loss of the control over hosts.
But doing exec() from the main process seemed as an acceptable risk becuase the
host doesn't have to maintain both old and new images this way. Memory is a
scarce commodity on embedded devices!

## Notes on Arch
For ARM, the codes are assigned for arches with major changes as per the
"industry standard". ARMV4T is the first and oldest Linux suppports. The thumb
variant has been chosen because almost all ARM CPUs run Linux kernel with Thumb
enabled. Major improvements and features were introduced with ARMV7(hfp) and
AARCH64(more hfp registers and 64bit address space). Note that in order for a
64-bit kernel to run 32-bit executables, the kernel must be configured with
CONFIG_COMPAT. There's no major penalty for enabling this so it's assumed that
most AARCH64 devices are configured with CONFIG_COMPAT.

Proone recognises that the arches that have gone "extinct". SH4 is one example
of this. They are merely defined to honor the Mirai's choice of arches. There
are also arches that lack the prevalence in embedded devices. These include PPC
and SPARC(not assigned, but targetted by Mirai). ARC CPUs are supported by Linux
but no actual product powered by ARC runs Linux.

## Lineage Tracing
`org_id` and `instance_id` can be used to trace the lineage of the instances. In
conjunction with *proone-hostinfod*, the host info from instances can be
collected and analysed. The final product will be a family tree of instances
tracing all the way back to the instances with zeroed-out org_id.

You can write simple script in the language of your choice to output visual
representation(such as PlantUML) of the family tree.

## Ephemeral Presence(Cont'd)
If you want to make a Linux virus "permanent" on the device, in other words to
program the virus to register it as a startup service, there are many challenges
you have to face:

* There is no unified way of making something a startup program on Linux because
  there are many init implementations like Sys V, Systemd, Buildroot and OpenWrt
  to name a few. Many of them are shell script based, but there are slight
  differences
* It is possible to overlay the root file system with a ramdisk so that any
  change made on root is lost after a reboot
* Some devices use battery-backed volatile memory to store files that change
  frequently such as state of the program or user configuration. These storage
  devices will appear as normal mtd/ide/scsi/nvme blocks

It's not worth it. People hardly do a routinely hardware reset of embedded
devices, especially on poorly made products. Even if they do, you can hope that
other instances on the network will infect the device again.

## Footnotes
[^1]: The crafted packets are not recognised by the kernel because no socket is
      associated with the port. The kernel is forced to send a RST back and this
      packet will reach the remote end if there's no firewall in the way that
      filters it.

[^2]: The port 64420 is in the ephemeral port range. Blocking this port may lead
      to mild consequences for ISPs.
