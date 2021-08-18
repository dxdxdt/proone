# Proone Software Design Spec
This document is part of **Proone Worm Project**. See [README.md](/README.md)
for overview.

## Subsystems
### Heartbeat
**Heartbeat** is a subsystem of Proone that consists of a backdoor and CNC
mechanism on infected devices. **The Heartbeat protocol** is a point-to-point or
a broadcast framing protocol that works over a transport stream such as TCP/IP.
The subsystem is documented separately in [htbt.md](htbt.md).

### Recon
TODO

### BNE
TODO

## Binary Archive and Data Vault
Proone aims to be a decentralised botnet. To spread without binary distribution
servers, Proone carries all the executables of arch types it supports. For this,
a special file structure is designed.

The **Data Vault**("**DVault**") is a binary block containing large and
sensitive data necessary for operation of Proone. DVault is a kempt version of
the data table of Mirai. DVault also helps reduce the size of Proone. Each
executable contains the *.data* section. If there's a long string in the
program, the value of the string will end up in each *.data* section of the
executables. Compression leviates this issue but there's a limit because the
size of data dictionary blocks can only get big. Having a custom *.data* section
for large data solves this issue at the cost of the size of code for fetching
and unmasking values from DVault. This implies that, in some cases, storing
static values in the *.data* section of an ELF is efficient enough[^1]. Another
purpose of DVault is masking sensitive data like `PRNE_DATA_KEY_CNC_TXT_REC` and
`PRNE_DATA_KEY_CRED_DICT` so that they're not revealed when `strings` command is
run on the executable or when the process is core dumped. DVault is loaded when
Proone initialises. The loaded contents remain in memory masked and unmasked
only when needed.

The contents of DVault are XORed with a 256 byte array of random numbers
generated on each compilation. This process makes it impossible to compress the
DVault binary block because of high entropy. It's not a good idea to use DVault
to store exceptionally large values. This issue may be solved by compressing the
value separately at the cost of CPU time.

The **Binary Archive**("**BA**") is a binary block containing compressed
executables and an index of the executables.

## Binary Recombination
TODO

## IPv6
TODO: precedence

## Requirements
### Targetting Wide Range of Devices and Kernel Configurations
A number of methods has been employed in efforts to target a wide range of Linux
devices. The assumption is that there are still devices running old images of
Linux and targetting these devices means coding up to the standard of old POSIX
specs and testing under old versions of Linux(namely 2.6.x).
`_POSIX_C_SOURCE=200112L` macro is defined to meet this requirement. Note that
using this macro does not give you an error when you accidentally use APIs not
in the 200112L standard. The compiler will only give you a warning and your code
will compile just fine. If you happen to use a function that the kernel of the
host does not support, the syscall will fail with `ENOSYS`. If the feature
requiring the new API can be silently switched off at runtime, removal of the
macro is recommended.

The Linux kernel is highly configurable. Pesudo file systems and the device file
system may not be present on a Linux host since they can be disabled. Disabling
any of these file systems is unusual for PCs but practical on embedded devices.
Proone do not assume that these file systems are available on the host and try
to run without using them if not available.

### Running Lean
Proone is designed under the assumption that honouring other processes on the
system will decrease the change of getting caught by system administrators.

Proone is compartmentalised so that it's somewhat immune to syscall fails. This
design is to counter `ENOMEM` as it runs lean on lean embedded systems. This
implies that proone can be initialised "half-complete". For example,
it can be initialised with all the workers running except the Heartbeat worker.
In this case, proone will be able to infect other devices on the network
while unable to respond to CNC TXT REC. Another notable case would be an
instance running without the Recon worker. It will respond to the CNC TXT REC
and serve the local backdoor connections while unable to infecting the other
devices on the network. Proone does not reattempt to start the workers it failed
to run on start. The assumption is that the system is already running with its
memory full to the brim and it's futile to wait for resource it failed to claim
as it's likley that the other services on the system will claim the reource at
some point.

Proone does cooperative multitasking by using **Pthsem** library. This is one
of many efforts to "run lean" whereby restricting CPU usage to one logical
thread. This may seem as a huge missed opportunity if Proone scores infecting
itself onto a beefy multi-core system. Keep in mind that Proone is designed to
run on resource-scarce embedded devices. Most poorly-designed vulnerable devices
will be single core, anways. The strategy is getting the most small-powered
devices infected rather than having a few infected high-performance systems.

### Ephemeral Presence
TODO

## Dependencies
The dependencies for Proone have been kept to absolute necessities. libssh2 is
used for the SSH brute force vector. Coupled with libssh2's SSL backend is
Mbedtls for TLS connection to public name servers and the Heartbeat protocol.
zlib is used to implement binary archive. All the libraries are compiled with
default configurations. Pthsem is used for threading.

libyaml and mariadb-connector-c-devel is required to build hostinfod. YAML has
been chosen for the configuration file format and output format of
proone-htbtclient. MariaDB for DB backend.


[^1]: i.e. representing values in code: `int value = 123;`
