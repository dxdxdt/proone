# Heartbeart Protocol Spec
The subsystem can work with DNS TXT records or over a TCP/IP connection. A
complete heartbeat connection consists of an **authoritive host** and a
**submissive host**. The authoritive host and the submissive host can be either
end of the TCP/IP connection.

Copyright (c) 2019-2021 David Timber &lt;mieabby@gmail.com&gt;

**A session** is a series of messages identified by a single message id. A
message is a combination of one or more frames. All messages begin with the
message header frame. The frame that should appear next depdens on the OP code
of the message header frame. A session is usually terminated by a message that
indicates the end of the session.

```
+------------+-------+------------+-------+-----+------------+-------+
| Msg Header | Frame | Msg Header | Frame | ... | Msg Header | Frame |
+------------+-------+------------+-------+-----+------------+-------+

| ---- Message ----- | ---- Message ----- | ... | ---- Message ----- |

| -- Session Init -- | - Session continued .. - | - Terminator Msg - |

| ---------------------------- Session ----------------------------- |
```

* All message headers in a session share the same msg id
* The OP code of a message header dictates the format of the following frame

The framinig protocol is designed so that multiple sessions can be pipelined
into a single TCP/IP connection or a DNS TXT record stream.

## Other Characteristics
* Heartbeat Protocol is a big-endian protocol
* Frames are not aligned to minimise "packet footprint"
* "Blackbox Interface" design
  * Serialise and deserialise functions can be called using the unified function
    pointer types
  * Unified behaviour of serialise and deserialise functions
    * The functions always return `actual` value, which can be used to determine
      the size of the packet and the amount of memory required to process the
      frame
    * The unified return type `prne_htbt_ser_rc_t`
  * Unified usage convention for extensibility
    * E.g. use of init and free even if there's no dynamically allocated
      resources associated with the frame
* Bit fields are not used for performance and portability

## TXT REC CNC
Unlike conventional botnets, Proone instances(our jargon for "bots") are
controlled by TXT DNS records containing one or more request sessions of an
authoritive host. In this scheme, Proone instances periodicallty query the
contents of the TXT records to parse and serve request messages as if they were
from a "real" authoritive host on the TLS connection. Any response data resulted
in the process is discarded. The serialised frames in the records are encoded in
base64 because most DNS management software do not accept binary data for the
value of TXT records. The
spec([rfc1035](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3) does
not impose such restriction.

The subthread called "CNC probe worker(CNCP)" of the heartbeat worker runs CNC
instructions by querying the CNC TXT REC periodically. The interval is hardcoded
to 1800±1800 seconds. The value of the header record is configured with the
macro `PRNE_CNC_TXT_REC` and defined as:

```re
([0-9a-fA-F]{8})(.*)
```

The first capture group is the number of the data records in hexadecimal with
leading zeros. The second capture group is the suffix of the data records.
The name of data TXT records can be constructed like so:

```c
for (uint32_t i = 0; i < nb_rec; i += 1) {
    printf("%08X%s", i, suffix);
}
```

Where

* *nb_rec* is the number of the data records
* *suffix* is the suffix of the data records

The CNCP worker will query the data records sequentially from 0th record to get
the base64 encoded binary data. The stream of base64 data is then decoded and
fed into a submissive heartbeat context for process.

For example, if the value of the header record is `00000003.cnc.test`, the
following series of data records are queried.

* `00000000.cnc.test`
* `00000001.cnc.test`
* `00000002.cnc.test`

Note that the suffix does not have to start with a dot. And the records from
different domains can be involved. For example, the name of the header record
can be "cnc.mydomain.example" and the value "0000000F.otherdomain.example".
Multiple values of the header record may be defined to achieve load balancing.
However, a data record must have only 1 value otherwise the CNCP worker will
regard it as a protocol error.

Only public DNS servers which support DNS over TLS are used to counter lawful
interception. The rationale behind this is that the DNS protocol is not
encrypted and ISPs or law enforcfements can easily filter out TXT REC CNC
traffic simply by doing plain-text string search. Proone queries public DNS
servers directly rather than using system functions. This eliminates the chance
of ISP DNS servers giving false results. Using public DNS servers is also
beneficial because law enforcements would have to take down the domain itself as
it would be difficult to convince the operators of public DNS servers to block a
recursive query to a particular name server. Another benefit is not having to
run CNC implementations for simple tasks like running shell scripts.

There are 2 recommended applications. One typical application is having a
`PRNE_HTBT_OP_HOVER`(Hand-over Command) request frame in TXT records to instruct
the instances to connect to servers running authoritive htbt implementations for
furthur instructions. The second application is having a
`PRNE_HTBT_OP_RUN_CMD`(Execute) frame or a
`PRNE_HTBT_OP_RUN_BIN`(Execute Binary Command) containing a simple minified
shell script to be run on the hosts.

Using CNC TXT records to transfer a large amount of data is possible but not
recommended. For Proone instances, quering TXT records, decoding base64 data and
running a slave heartbeat context is a costly operation.

## M2M
The protocol leaves room for implementing M2M mechanisms. A Proone instance
checks if the target host is already infected by attempting to connect to a
**local back door**(or simply, **LBD**) on the target host. This is called "M2M
handshake". The hardcoded default port of LDB is 64420. The LBD port is served
by a submissive Heartbeat context. The current version of instances upgrade
their own executable when a new version is detected during this process.

**proone-htbtclient** can be used to examine and maintain the Proone instance
via this port.

## TLS PKI
Unlike in a usual TLS set up, both server and client heartbeat implementations
are required to verify the remote host's certificate. This prevents access to
the instances from unwanted parties and enforces "domains" of the same
implementation operated by different users. The ALPN(application layer protocol
negotiation) string "prne-htbt" is also used to further ensure that the remote
endpoint the implementation connects to is served by a Proone implementation
serving heartbeat connections.

The Proone executables carry files necessray to set up TLS connections hardcoded
in their binary. These files include the CA cert, a DH param, a cert and a
private key for client connections and a cert and private key for server
connections.

## Custom Authoritive Server Implementations
In order to do things of complexity, it's recommended to implement an
authoritive server implementation and command Proone instances to take orders
from the servers running the implementation. Load balancing can be done at the
DNS level using techniques like round-robin DNS or GeoDNS. Once a Proone
instance connects to an authoritive server, the server can fully utilise the
heartbeat protocol. To make an example, **proone-hostinfod** is implemented.

## Possible Use Cases
Shell scripts can be run on Proone hosts with `PRNE_HTBT_OP_RUN_BIN`(Execute
Binary Command) as long as the script contains a shebang line at the very start
of the script and the host kernel supports it. Note that most embedded devices
run lightweight shells like Ash(BusyBox) and Toysh(Toybox). The best is strategy
is targetting Bourne shell, which has been a default shell for the majority of
systems(historically).

* `reboot -nf` to reboot host: this effectively terminates Proone's presence on
  the host)
* `half -nf` to disable host: the device will remain dormant until the owner of
  the device resets it

To make hosts run an arbitrary binary executable, `PRNE_HTBT_OP_HOST_INFO`(Host
Info Request) can be used to query the archeticture type of the host to select
a suitable binary for upload. This is what `proone-htbtclient upbin` command
does to prepare the binary for the instance.

`PRNE_HTBT_OP_UP_BIN`(Binary Upgrade) can be used to replace the executable of
the Proone instance.

## The Frames
### Attributes
| Name   | Description                                                         |
| ------ | ------------------------------------------------------------------- |
| Type   | The structure representing the frame                                |
| Init   | The function used to initialise the members to the initial values   |
| Free   | The function used to free all dynamically allocated memory in the   |
|        | struct if any. No operation is performed if the pointer is NULL     |
| Ser    | The function used to serialise the frame to the buffer for          |
|        | transmission                                                        |
| Dser   | The function used to deserialise a frame from the buffer            |
| Eq     | Used to compare two frames of the same type. Returns true if the    |
|        | data of the frames are identical                                    |
| Alloc  | The function(s) used to allocate memory of dynamic members if any   |
| VLen   | "**YES**" if the length of the frame is variable                    |
| MinLen | The minimum possible length of the frame in bytes                   |
| MaxLen | The maximum possible length of the frame in bytes if the length of  |
|        | the frame is variable                                               |

### Message Header Frame
```
    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |I|             id              |      op       |
 3 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Description                                                          |
| ----- | -------------------------------------------------------------------- |
| I     | 1 if the frame is sent by the party that initiated the session       |
| id    | 15-bit unsigned integer message id                                   |
| op    | 8-bit unsigned integer op code                                       |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_msg_head_t`                                           |
| Init      | `prne_htbt_init_msg_head()`                                      |
| Free      | `prne_htbt_free_msg_head()`                                      |
| Ser       | `prne_htbt_ser_msg_head()`                                       |
| Dser      | `prne_htbt_dser_msg_head()`                                      |
| Eq        | `prne_htbt_eq_msg_head()`                                        |
| Alloc     | -                                                                |
| VLen      | no                                                               |
| MinLen    | 3                                                                |
| MaxLen    | -                                                                |

The message header frames mark the start of a message. The **op** code dictates
the type of the frame which follows the message header frame. The **id** is used
to identify which session the message belongs to. A session is initiated with a
message with a new *id* and the **I** flag set.

The special value 0x0000 is reserved for *id* for use in No Operation sessions.
The id value 0x00 is illegal if it's not used for NOOP. This rule is in place so
that the NOOP messages always appear as `80 00 00` and `00 00 00` in binary.

The special id value 0x7FFF is used to indicate a "notification session" in
which the recipient host is not expected to produce any response messages for
that session. For example, a Status message can be sent with the id 0x7FFF by
either host to report a protorol error.

#### OP Codes
| Enum      | Value | Name                 | Next Frame           |
| --------- | ----- | -------------------- | -------------------- |
| NOOP      | 0x00  | No Operation         | -                    |
| STATUS    | 0x01  | Status               | Status               |
| HOST_INFO | 0x02  | Hostinfo             | None if request      |
|           |       |                      | Hostinfo if response |
| HOVER     | 0x03  | Hand-over            | Handover             |
| SOLICIT   | 0x04  | Solicit              | -                    |
| RUN_CMD   | 0x05  | Execute              | Command              |
| UP_BIN    | 0x06  | Binary Upgrade       | Binary meta          |
| RUN_BIN   | 0x07  | Execute Binary       | Binary meta          |
| STDIO     | 0x08  | STDIO                | STDIO                |
| RCB       | 0x09  | Binary Recombination | RCB                  |

### Status Frame
```
    0
    0 1 2 3 4 5 6 7
 0 +-+-+-+-+-+-+-+-+
   |     code      |
   +-+-+-+-+-+-+-+-+
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 1 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              err                              |
 5 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Description                                                          |
| ----- | -------------------------------------------------------------------- |
| code  | 8-bit unsigned integer                                               |
| err   | 32-bit two's complement signed integer                               |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_status_t`                                             |
| Init      | `prne_htbt_init_status()`                                        |
| Free      | `prne_htbt_free_status()`                                        |
| Ser       | `prne_htbt_ser_status()`                                         |
| Dser      | `prne_htbt_dser_status()`                                        |
| Eq        | `prne_htbt_eq_status()`                                          |
| Alloc     | -                                                                |
| VLen      | no                                                               |
| MinLen    | 5                                                                |
| MaxLen    | -                                                                |

The status frame is used to describe the result of a request or an error
occurred. *err* is used to convey `errno` or a return value from the underlaying
library.

Note that the host CPU architecture may be using [unusual signed integer
format](https://en.wikipedia.org/wiki/Signed_number_representations). If this is
the case, the implementation must translate the host's signed integer
representation from/to two's complement representation.

#### Codes
| Enum      | Value | Description                                              |
| ----------| ----- | -------------------------------------------------------- |
| OK        | 0x00  | Operation was successful                                 |
| UNIMPL    | 0x01  | Request could not be served because a functionality      |
|           |       | required is not implemented                              |
| PROTO_ERR | 0x02  | Protocol error was detected while processing frames      |
| ERRNO     | 0x03  | Operation was not successful and *err* is set to errno   |
| SUB       | 0x04  | *err* is set to the error code returned from the  module |
| LIMIT     | 0x05  | Request could not be served because a limit was reached  |

### Hostinfo Frame
```
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                           prog_ver                            +
     |                                                               |
     +                                                               +
     |                                                               |
  16 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                            boot_id                            +
     |                                                               |
     +                                                               +
     |                                                               |
  32 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                          instance_id                          +
     |                                                               |
     +                                                               +
     |                                                               |
  48 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                            org_id                             +
     |                                                               |
     +                                                               +
     |                                                               |
  64 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         parent_uptime                         |
  68 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         child_uptime                          |
  72 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                            bne_cnt                            +
     |                                                               |
  80 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                          infect_cnt                           +
     |                                                               |
  88 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           crash_cnt                           |
  92 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          parent_pid                           |
  96 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           child_pid                           |
 100 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    hc_len     |     arch      |      os       |    bf_len     |
 104 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | hc and then bf ...
     +-------------------
```

| Field         | Description                                                  |
| ------------- | ------------------------------------------------------------ |
| prog_ver      | 128-bit uuid                                                 |
| boot_id       | 128-bit uuid                                                 |
| instance_id   | 128-bit uuid                                                 |
| org_id        | 128-bit uuid                                                 |
| parent_uptime | 32-bit unsigned integer parent process uptime in seconds     |
| child_uptime  | 32-bit unsigned integer child process uptime in seconds      |
| bne_cnt       | 64-bit unsigned integer "break and entry" count              |
| infect_cnt    | 64-bit unsigned integer "infect" count                       |
| crash_cnt     | 32-bit unsigned integer child process crash count            |
| parent_pid    | 32-bit unsigned integer parent pid of instance               |
| child_pid     | 32-bit unsigned integer child pid of instance                |
| hc_len        | 8-bit unsigned integer length of *hc* in octets              |
| arch          | 8-bit unsigned integer CPU architecture code                 |
| os            | 8-bit unsigned integer OS code                               |
| bf_len        | 8-bit unsigned integer bitfield length                       |
| hc            | host credential data                                         |
| bf            | bitfield data                                                |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_host_info_t`                                          |
| Init      | `prne_htbt_init_host_info()`                                     |
| Free      | `prne_htbt_free_host_info()`                                     |
| Ser       | `prne_htbt_ser_host_info()`                                      |
| Dser      | `prne_htbt_dser_host_info()`                                     |
| Eq        | `prne_htbt_eq_host_info()`                                       |
| Alloc     | `prne_htbt_alloc_host_info()`                                    |
| VLen      | **YES**                                                          |
| MinLen    | 104                                                              |
| MaxLen    | 614                                                              |

Hostinfo frames are used to carry diagnostic and statistic data on the instance.

**prog_ver** is a hardcoded uuid used to identify the version of Proone
instances. The submissive host should return the value of `PRNE_PROG_VER` in
this field.

**boot_id** is a uuid provided by the host
kernel(`/proc/sys/kernel/random/boot_id` on Linux). A zeroed-out uuid indicates
that the host platform provides no such identification or the instance has
failed to parse the data.

**instance_id** is a uuid generated when the instance is launched on the host
for the first time. The uuid is preserved across `exec()`(e.g. binary upgrade).

**org_id** is the *instance_id* of the Proone instance that infected the host. A
zeroed-out uuid indicates that the *org_id* is not specified.

**parent_uptime** is the number of seconds elapsed since the parent process has
started. **child_uptime** is the numer of seconds elapsed since the child
process has been spawned by the parent process. The value 0xFFFFFFFF is used to
indicate errors like integer overflow or unset value.

**bne_cnt** is the number of times the instance has breached a host. This
includes the number of successful logins and the number of successful breaches
using vulnerabilities.

**infect_cnt** is the number of times the instance has infected a host. The
instance increments the value every time it successfully launches the Proone
executable("successful": Proone process exited with exit code 0 meaning that it
has successfully daemonised a process).

**crash_cnt** is the number of times a child process crashed. The parent process
increments this value when it reaps a child process and determines that the
process has been terminated by a signal.

**parent_pid** is the process id of the parent process. This should also be the
process group id and the process session id of the parent process since Proone
instance runs as a daemon. **child_pid** is the process id of the child process.

**arch** and **os** correspond to the value of `PRNE_HOST_ARCH`(CPU Architecture
Code) and `PRNE_HOST_OS`(OS Code) value of the instance respectively.

**hc** contains the credential used to break into the host. The data could be
empty(*hc_len* is zero and there's no *hc* after the fixed-length part of the
frame) since hosts can be breached by means other than brute foce login attacks.
The format of the data is specified in the [separate document](fmts.md).

**bf** contains the flag bits to describe the attributes of the instance. The
bits used are specified in the following section.

**hc_len** is the length of the host credential data that follows after the
fixed-length part of the frame. **bf_len** is the length of the bitfield data
that follows after the host credential data.

#### Instance Flags(Bitfield Bits)
* Type: `prne_iflag_t`

| Enum       | Bit | Mask | Meaning                                            |
| ---------- | --- | ---- | -------------------------------------------------- |
| BA         | 0   | 0x01 | The instance has successfully initialised a binary |
|            |     |      | archive ready for use                              |
| INIT_RUN   | 1   | 0x02 | The instance is run for the first time on the      |
|            |     |      | host. This flag will be unset after a successful   |
|            |     |      | Binary Upgrade Session                             |
| WKR_RCN    | 2   | 0x04 | The Recon worker is initialised and running        |
| WKR_RESOLV | 3   | 0x08 | The Resolv worker is initialised and running       |
| WKR_HTBT   | 4   | 0x10 | The Heartbeat worker is initialised and running    |

These flags are diagnostic flags. They are designed to examine the health of
instances. For example, a bug in the BNE worker may cause a malformed executable
on the target host, rendering the binary archive appended to the executable
useless. `WKR_*` flags are used to determine if the host is runnning low on
memory. Other examples are ...

* Without the Recon worker(WKR_RCN unset), the instance cannot infect other
  hosts
* Without the Resolv worker(WKR_RESOLV unset), the instance cannot receive CNC
* Without the Heartbeat worker(WKR_HTBT unset), the instance cannot perform M2M
  communication with other hosts

#### Bitfield Format
The bitfield carries bits in octet units starting from the least significant
byte. For example, the bitfield of 1 octet carries up to 8 bits and 2 octets 16
bits and so on. The bits from 0th to 7th are placed in the first byte, bits from
8th to 15th in the second and so on. The bitfield is little-endian unlike the
protocol itself because the implementation is simplest this way. See
[/src/bitfield.h](/src/bitfield.h) header, which defines intuitive interfaces
for facilitating the use of bitfields.

### Hand-over Frame
```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            addr_4                             |
  4 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            port_4             |                               |
  8 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                                                               |
    +                                                               +
    |                            addr_6                             |
    +                                                               +
    |                                                               |
    +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               |            port_6             |
 24 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field  | Description                                                         |
| ------ | ------------------------------------------------------------------- |
| addr_4 | 32-bit IPv4 address of the authoritive host                         |
| port_4 | 16-bit unsigned integer IPv4 port of the authoritive host           |
| addr_6 | 128-bit IPv6 address of the authoritive host                        |
| port_6 | 16-bit unsigned integer IPv6 port of the authoritive host           |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_hover_t`                                              |
| Init      | `prne_htbt_init_hover()`                                         |
| Free      | `prne_htbt_free_hover()`                                         |
| Ser       | `prne_htbt_ser_hover()`                                          |
| Dser      | `prne_htbt_dser_hover()`                                         |
| Eq        | `prne_htbt_eq_hover()`                                           |
| Alloc     | -                                                                |
| VLen      | no                                                               |
| MinLen    | 24                                                               |
| MaxLen    | -                                                                |

The hand-over frame is used to represent the socket addresses of another
authoritive host. Zeroed-out addresses(0.0.0.0 and ::) are used to represent
that the address is unspecified. If both IPv4 and IPv6 addresses are specified,
the IPv6 address takes the precedence. This means that the use of IPv6 is
favoured whenever IPv6 connectivity is available.

### Command Frame
```
     0                   1
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
  0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   rsv   |D|     args_len      |
  2 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   args ...
    +-+-+-
```

| Field    | Description                                                       |
| -------- | ----------------------------------------------------------------- |
| rsv      | Not used                                                          |
| D        | Detach flag. 1 if the process has to be "detached". 0 Otherwise   |
| args_len | 10-bit unsigned integer length of args, in octets                 |
| args     | series of null-terminated strings                                 |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_cmd_t`                                                |
| Init      | `prne_htbt_init_cmd()`                                           |
| Free      | `prne_htbt_free_cmd()`                                           |
| Ser       | `prne_htbt_ser_cmd()`                                            |
| Dser      | `prne_htbt_dser_cmd()`                                           |
| Eq        | `prne_htbt_eq_cmd()`                                             |
| Alloc     | `prne_htbt_alloc_cmd()`, `prne_htbt_set_cmd()`                   |
| VLen      | **YES**                                                          |
| MinLen    | 2                                                                |
| MaxLen    | 1025                                                             |

The command frame is used to represent arguments to `exec()` syscall.

**D**("detach") is a flag used to indicate whether the process should be spawned
detached or not. A detached process should be set up such that ...

* The result of reading the standard input is always EOF
* Writing to the standard output or the standard error result in EPIPE and
  SIGPIPE sent to the process[^1]
* The process is made a "daemon"[^2]
  * The process is both a process group and a session leader
  * The parent process is a "system process" that reaps child processes in the
    background

**args_len** is the length of *args* in octets.

#### Args Data Format
The data in the args field represent a array of strings to be passed to `exec()`
syscall. The contents are the series of null-terminated strings in the order
they should appear in `char const *argv[]`. When the frame is used for UP_BIN
and RUN_BIN, the first element of the array is not used to represent the path to
the executable(the instance will prepend one). For this reason, the value of
*args_len* can be zero, meaning the frame has no argument strings.

The strings must be null-terminated. In other words, args data that does not end
with zero is illegal. Empty strings are permitted.

* Example 1
  * Command: "/bin/echo" "Hello" "world" "!"
  * Binary representation
```
00000000  2f 62 69 6e 2f 65 63 68  6f 00 48 65 6c 6c 6f 00  |/bin/echo.Hello.|
00000010  77 6f 72 6c 64 00 21 00                           |world.!.|
00000018
```
* Example 2
  * Command: "/bin/echo" "one" "" "three"
  * Binary representation
```
00000000  2f 62 69 6e 2f 65 63 68  6f 00 6f 6e 65 00 00 74  |/bin/echo.one..t|
00000010  68 72 65 65 00                                    |hree.|
00000015
```

### Bin Meta Frame
```
     0                   1                   2
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
  0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   alloc_len                   |
  3 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   rsv   |D|     args_len      |
  5 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  args ...
    +-+-+-
```

| Field     | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| alloc_len | 24-bit unsigned integer advisory preallocation length in octests |
| rsv       | Not used                                                         |
| D         | Detach flag. 1 if the process has to be "detached". 0 Otherwise  |
| args_len  | 10-bit unsigned integer length of args, in octets                |
| args      | series of null-terminated strings                                |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_bin_meta_t`                                           |
| Init      | `prne_htbt_init_bin_meta()`                                      |
| Free      | `prne_htbt_free_bin_meta()`                                      |
| Ser       | `prne_htbt_ser_bin_meta()`                                       |
| Dser      | `prne_htbt_dser_bin_meta()`                                      |
| Eq        | `prne_htbt_eq_bin_meta()`                                        |
| Alloc     | `prne_htbt_alloc_cmd()`, `prne_htbt_set_cmd()`                   |
| VLen      | **YES**                                                          |
| MinLen    | 5                                                                |
| MaxLen    | 1028                                                             |

The bin meta frame is an extension of the Command frames.

**alloc_len** is the length in octets advised by the authoritive implementation
for preallocation. The submissive implementation may choose to honor the field
to preallocate space on the file system using syscalls like `fallocate()`. The
implementations may choose to ignore the field. If the desired length cannot be
represented using the 24-bit field, the implementations may use the value
0xFFFFFF to indicate that the desired length is larger than 0xFFFFFF. Note that
the field does not represent the actual size of the executable. Therefore the
implementation must "dock" the file to the size of the actual data received if
it turns out to be shorter than *alloc_len*.

Refer to ###Command Frame section for furthur info.

### STDIO Frame
```
    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |E|F|rsv|          len          |
 2 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  data ...
   +-+-+-
```

| Field | Description                                                          |
| ----- | -------------------------------------------------------------------- |
| E     | Flag indicating whether the data is stderr output                    |
| F     | Flag indicating whether the frame is the final frame for the channel |
| rsv   | Not used                                                             |
| len   | 12-bit unsigned integer length of data that follows in octets        |
| data  | The data from/to the channel(stdin, stdout or stderr)                |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_stdio_t`                                              |
| Init      | `prne_htbt_init_stdio()`                                         |
| Free      | `prne_htbt_free_stdio()`                                         |
| Ser       | `prne_htbt_ser_stdio()`                                          |
| Dser      | `prne_htbt_dser_stdio()`                                         |
| Eq        | `prne_htbt_eq_stdio()`                                           |
| Alloc     | -                                                                |
| VLen      | no                                                               |
| MinLen    | 2                                                                |
| MaxLen    | -                                                                |

The STDIO frame is used for transmission of stdio data and arbitrary binary
data.

**E**("err") is a flag used to indicate whether the frame holds the output of
the standard error. This flag is only used by the submissive host in Execute and
Execute Binary sessions. The frame with the flag set is illegal if sent by the
authoritive host. The flag is ignored when used in Binary Upgrade and Binary
Recombination sessions.

**F**("fin") is a flag used to mark the final transmission of the channel. When
used in Execute or Execute Binary sessions, the flag indicates that the channel
has reached EOF and the corresponding file descriptors should be closed. When
used in Binary Upgrade or Binary Recombination sessions, the flag means that the
there are no more data to be transferred.

**len** is the octet length of the data that follows. Note that STDIO frames
with *fin* flag set and *len* > 0 are legal. The implementations should deliver
all the pending data of the channels including the data in these frames before
closing the file descriptors.

### RCB Frame
```
    0                   1                   2
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |C|S|    rsv    |      os       |     arch      |
 3 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Description                                                          |
| ----- | -------------------------------------------------------------------- |
| C     | Flag used to indicate use of compatible architecture is allowed      |
| S     | Flag used to instruct the submissive host to perform "self-copy"     |
| os    | 8-bit OS code                                                        |
| arch  | 8-bit architecture code                                              |

| Attribute | Value                                                            |
| --------- | ---------------------------------------------------------------- |
| Type      | `prne_htbt_rcb_t`                                                |
| Init      | `prne_htbt_init_rcb()`                                           |
| Free      | `prne_htbt_free_rcb()`                                           |
| Ser       | `prne_htbt_ser_rcb()`                                            |
| Dser      | `prne_htbt_dser_rcb()`                                           |
| Eq        | `prne_htbt_eq_rcb()`                                             |
| Alloc     | -                                                                |
| VLen      | no                                                               |
| MinLen    | 3                                                                |
| MaxLen    | -                                                                |

The RCB frame is used to instruct the submissive host to initiate binary
recombination.

The submissive host is allowed to choose an alternative architecture if the one
requested is unavailable when the **C**("compat") flag is set. The submissive
host is required to transmit the copy of its executable if **S**("self") is set.
The binary recombination target is specified in **os** and **arch** fields.
These fields are ignored if *S* is set.

## Enum Codes
### CPU Architecture Codes
| Enum    | Value | Description                                                |
| ------- | ----- | ---------------------------------------------------------- |
| NONE    | 0x00  | Special value used to indicate that the code is not used   |
| I686    | 0x01  | Intel P6 microarchitecture (Pentium Pro)                   |
| X86_64  | 0x02  | AMD64 Opteron "SledgeHammer"                               |
| ARMV4T  | 0x03  | ARM v4 w/ MMU, Thumb (ARM920T)                             |
| ARMV7   | 0x04  | ARM v7 w/ MMU, Thumb-2, VFPv4 FPU (Cortex-A5)              |
| AARCH64 | 0x05  | AArch64 (Cortex-A35)                                       |
| MIPS    | 0x06  | MIPS 1 (R3000) running in big-endian mode                  |
| MPSL    | 0x07  | MIPS 1 (R3000) running in little-endian mode               |
| PPC     | 0x08  | PowerPC 1                                                  |
| SH4     | 0x09  | Renesas SuperH 4                                           |
| M68K    | 0x0A  | Motorola 68040                                             |
| ARC     | 0x0B  | DesignWare ARC Processor running in little-endian mode     |
| ARCEB   | 0x0C  | DesignWare ARC Processor running in big-endian mode        |

The codes represent the target arch of the compiler output. They coincide with
the default target of modern compilers like GCC or Clang. For example, the I686
target("-m32") will run on later versions of x86 arches, say Pentium 4. But it
won't run on older version of x86 CPUs such as P5. I686 is chosen because the
Linux kernel dropped support for P5 and older arches a long time ago(hence
"-m32" target being P6). The same reasoning applies to other arches that the
Heartbeat protocol defines.

More on arch codes in [dev_notes](dev_notes.md).

### OS Codes
| Enum    | Value | Description                                                |
| ------- | ----- | ---------------------------------------------------------- |
| NONE    | 0x00  | Special value used to indicate that the code is not used   |
| LINUX   | 0x01  | Linux ABI                                                  |

The OS codes are used to represent the ABI the executable is compiled against.
Proone is designed with portability in mind and OS codes will be used to
distinguish the ABI of executables in the future.

## Sessions
All messages must start with a message header frame. The op code dictates the
type of the next frame. Some op codes define no next header nor following
messages. In this case the initial message header is the only frame that appears
in the session.

A new session is initiated when the authoritive host sends a message with a new
message id(randomly generated) and the I flag set. The hosts exchange messages
until the session is concluded.

### No Operation
```
     ┌─┐          ┌─┐
     │A│          │B│
     └┬┘          └┬┘
      │+0x00 NOOP  │
      │───────────>│
      │            │
      │ 0x00 NOOP  │
      │<─ ─ ─ ─ ─ ─│
     ┌┴┐          ┌┴┐
     │A│          │B│
     └─┘          └─┘
```

The No Operation is a special session used to perform "are you there"(AYT)
enquiry. It can be used by any host to check the health of the live TLS
connection. It can also be used to keep the connection alive for long-lived
sessions like Execute/Execute Binary sessions.

### Host Info Session
```
     ┌─┐             ┌─┐
     │A│             │S│
     └┬┘             └┬┘
      │  +HOST_INFO   │
      │──────────────>│
      │               │
      │  HOST_INFO    │
      │<─ ─ ─ ─ ─ ─ ─ │
      │               │
      │Hostinfo Frame │
      │<─ ─ ─ ─ ─ ─ ─ │
     ┌┴┐             ┌┴┐
     │A│             │S│
     └─┘             └─┘
```

The Host Info session is initiated by the authoritive host to query the
information of the submissive end(the instance). The possible response from the
submissive end can be following.

* A message w/ op code set to HOST_INFO and Hostinfo as next frame
* A message w/ op code set to STATUS and STATUS as next frame
  * Code UNIMPL if the submissive host does not implement the processing of Host
    Info requests
  * Code ERRNO if an internal error has occurred on the submissive host whilst
    processing the request. Err field is set to the errno returned

### Hand-over Session
```
     ┌─┐             ┌─┐
     │A│             │S│
     └┬┘             └┬┘
      │    +HOVER     │
      │──────────────>│
      │               │
      │Handover Frame │
      │──────────────>│
      │               │
      │               ────┐
      │                   │ queue request
      │               <───┘
      │               │
      │    STATUS     │
      │<─ ─ ─ ─ ─ ─ ─ │
      │               │
      │ Status Frame  │
      │<─ ─ ─ ─ ─ ─ ─ │
     ┌┴┐             ┌┴┐
     │A│             │S│
     └─┘             └─┘
```

The Hand-over session is initiated by the authoritive host when furthur the
subsmissive host should request further instructions from another authroitive
host. The request is served in the background and the connection continues. The
possible status response:

* OK if the request is queued successfully
* UNIMPL if the submissive host does not implement the request
* LIMIT if the maximum number of redirection is reached
* ERRNO for syscall errors except ...
  * EAGAIN if the request queue reached the maximum size

If the thread processing the request receives another Hand-over session sent by
another authoritive host, the thread increments the internal counter to enforce
the "redirection limit".

When the submissive host establishes a TLS connection to another authoritive
host, the submissive host is required to initiate a Solicit session to request
furthur instructions. Note that this is where the hosts switch places in the TLS
connection - the authoritive host becomes the server and the submissive host
client.

### Solicit Session
```
     ┌─┐          ┌─┐
     │S│          │A│
     └┬┘          └┬┘
      │ +SOLICIT   │
      │───────────>│
     ┌┴┐          ┌┴┐
     │S│          │A│
     └─┘          └─┘
```

The Solicit session is initiated by the subissive host after establishing a TLS
connection to another authoritive to carry out the Hand-over request. There is
no next frame that follows the message.

The authoritive host may choose to reuse the message id used for the request to
initiate request to the submissive host. This is not a requirement and
disregarding the message id in the Solicit message is not illegal.

### Execute Session
```
     ┌─┐                          ┌─┐
     │A│                          │S│
     └┬┘                          └┬┘
      │         +RUN_CMD           │
      │───────────────────────────>│
      │                            │
      │       Command Frame        │
      │───────────────────────────>│                │
      │                            │                │
      │                            │fork(), exec() ┌─┐
      │                            │──────────────>│P│
      │                            │               └┬┘
      │          +STDIO            │                │
      │───────────────────────────>│                │
      │                            │                │
      │        STDIO Frame         │                │
      │───────────────────────────>│                │
      │                            │                │
      │        STDIO Data          │                │
      │───────────────────────────>│                │
      │                            │                │
      │                            │  STDIO Data    │
      │                            │───────────────>│
      │                            │                │
      │                            │  STDIO Data    │
      │                            │<───────────────│
      │                            │                │
      │           STDIO            │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
      │        STDIO Frame         │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
      │        STDIO Data          │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
    ╔═╧════════════════════════════╧════════════════╧═╗
    ║Repeat ...                                      ░║
    ╚═╤════════════════════════════╤════════════════╤═╝
      │          +STDIO            │                │
      │───────────────────────────>│                │
      │                            │                │
      │  STDIO Frame len=0, fin    │                │
      │───────────────────────────>│                │
      │                            │                │
      │                            │   STDIN EOF    │
      │                            │───────────────>│
      │                            │                │
      │                            │  STDOUT EOF    │
      │                            │<───────────────│
      │                            │                │
      │           STDIO            │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
      │  STDIO Frame len=0, fin    │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
      │                            │  STDERR EOF    │
      │                            │<───────────────│
      │                            │                │
      │           STDIO            │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
      │STDIO Frame len=0, err, fin │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
      │                            │                │────┐
      │                            │               \│/   │ exit()
      │                            │                X<───┘
      │                            │               /│\
      │                            │   waitpid()    │
      │                            │<──────────────>│
      │                            │                │
      │                            │        ╔═══════╧════════╗
      │                            │        ║Process reaped ░║
      │                            │        ╚═══════╤════════╝
      │          Status            │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
      │                            │                │
      │       Status Frame         │                │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                │
     ┌┴┐                          ┌┴┐              ┌┴┐
     │A│                          │S│              │P│
     └─┘                          └─┘              └─┘
```

The Execute session is used to do exec() on the submissive host, similar to the
`system()` function. A Command frame is used to specify arguments to exec()
function. The first string in the *args* field must be the absolute path to an
executable on the host as per the usage of exec().

STDIO messages are used to transfer standard input and output data from and to
the child process. The authoritive host should send a STDIO frame with fin flag
so that `read()` on the standard input returns EOF in the child process. The
submissive host must notify the authoritive host with STDIO frames with fin flag
when the child process closes its standard output and standard error. Once both
outputs reached EOF, the submissive host reaps the child process to retrieve the
exit code, which is then sent over a Status frame to the authoritive host.

If an error occurs during the process, the submissive host will skip to sending
a status frame with errno. The authoritive host shouldn't expect and send
furthur STDIO messages. The submissive host may skip to sending a Status frame
with UNIMPL if it does not implement Execute sessions.

### Binary Upgrade Session
```
     ┌─┐                   ┌─┐
     │A│                   │S│
     └┬┘                   └┬┘
      │      +UP_BIN        │
      │────────────────────>│
      │                     │
      │ Binary Meta Frame   │
      │────────────────────>│
      │                     │
      │                     ────┐
      │                         │ open() tmpfile
      │                     <───┘
      │                     │
      │       +STDIO        │
      │────────────────────>│
      │                     │
      │    STDIO Frame      │
      │────────────────────>│
      │                     │
      │    Binary Data      │
      │────────────────────>│
      │                     │
      │                     ────┐
      │                         │ write()
      │                     <───┘
      │                     │
      │       +STDIO        │
      │────────────────────>│
      │                     │
      │    STDIO Frame      │
      │────────────────────>│
      │                     │
      │    Binary Data      │
      │────────────────────>│
      │                     │
      │                     ────┐
      │                         │ write()
      │                     <───┘
      │                     │
    ╔═╧═════════════════════╧═╗
    ║Repeat ...              ░║
    ╚═╤═════════════════════╤═╝
      │       +STDIO        │
      │────────────────────>│
      │                     │
      │  STDIO Frame, fin   │
      │────────────────────>│
      │                     │
      │                     ────┐
      │                         │ close(), rename()
      │                     <───┘
      │                     │
      │       Status        │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
      │                     │
     \│/   Status Frame     │
      X<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
     /│\                    │
      │Terminate connection │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
      │                     │
      │                     ────┐
      │                         │ clean up, exec()
      │                     <───┘
     ┌┴┐                   ┌┴┐
     │A│                   │S│
     └─┘                   └─┘
```

The Binary Upgrade session is used to replace the executable of a Proone
instance. The instance will simply change the image of its process to the new
executable using `exec()`. The Binary Meta frame contains the arguments to the
`exec()` syscall which are honoured by the submissive host. STDIO frames are
used for data transfer. The format of the new executable can be any format
recognised by the host kernel(ELF or #! if the kernel supports it). The
authoritive host is responsible for providing the suitable executable for the
submissive host. Usually, the Host Info is queried to prepare the right
executable for the host. The Status frame is used to deliver the result of the
data tranfer. In the event of an error, the submissive host does not wait for
the data transfer to finish before sending the Status frame.

Upon successful upload, the Proone instance will attempt to `exec()` to the
binary from the parent process. In the event of failure, Proone will continue to
function with the existing binary. The only way to check the result of the
operation is by reestablishing the connection to the Proone instance and
querying the version of the binary through `PRNE_HTBT_OP_HOST_INFO` request.

### Execute Binary Session
```
     ┌─┐                          ┌─┐
     │A│                          │S│
     └┬┘                          └┬┘
      │         +RUN_BIN           │
      │───────────────────────────>│
      │                            │
      │     Binary Meta Frame      │
      │───────────────────────────>│
      │                            │
      │                            ────┐
      │                                │ open() tmpfile
      │                            <───┘
      │                            │
      │          +STDIO            │
      │───────────────────────────>│
      │                            │
      │        STDIO Frame         │
      │───────────────────────────>│
      │                            │
      │        Binary Data         │
      │───────────────────────────>│
      │                            │
      │                            ────┐
      │                                │ write()
      │                            <───┘
      │                            │
      │          +STDIO            │
      │───────────────────────────>│
      │                            │
      │        STDIO Frame         │
      │───────────────────────────>│
      │                            │
      │        Binary Data         │
      │───────────────────────────>│
      │                            │
      │                            ────┐
      │                                │ write()
      │                            <───┘
      │                            │
    ╔═╧════════════════════════════╧═════════════════════╗
    ║Repeat ...                                         ░║
    ╚═╤════════════════════════════╤═════════════════════╝
      │          +STDIO            │
      │───────────────────────────>│
      │                            │
      │     STDIO Frame, fin       │
      │───────────────────────────>│
      │                            │
      │                            ────┐
      │                                │ close()
      │                            <───┘               │
      │                            │                   │
      │                            │ fork(), exec()   ┌─┐
      │                            │────────────────> │P│
      │                            │                  └┬┘
      │          +STDIO            │                   │
      │───────────────────────────>│                   │
      │                            │                   │
      │        STDIO Frame         │                   │
      │───────────────────────────>│                   │
      │                            │                   │
      │        STDIO Data          │                   │
      │───────────────────────────>│                   │
      │                            │                   │
      │                            │    STDIO Data     │
      │                            │──────────────────>│
      │                            │                   │
      │                            │    STDIO Data     │
      │                            │<──────────────────│
      │                            │                   │
      │           STDIO            │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
      │        STDIO Frame         │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
      │        STDIO Data          │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
    ╔═╧════════════════════════════╧═══════════════════╧═╗
    ║Repeat ...                                         ░║
    ╚═╤════════════════════════════╤═══════════════════╤═╝
      │          +STDIO            │                   │
      │───────────────────────────>│                   │
      │                            │                   │
      │  STDIO Frame len=0, fin    │                   │
      │───────────────────────────>│                   │
      │                            │                   │
      │                            │    STDIN EOF      │
      │                            │──────────────────>│
      │                            │                   │
      │                            │    STDOUT EOF     │
      │                            │<──────────────────│
      │                            │                   │
      │           STDIO            │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
      │  STDIO Frame len=0, fin    │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
      │                            │    STDERR EOF     │
      │                            │<──────────────────│
      │                            │                   │
      │           STDIO            │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
      │STDIO Frame len=0, err, fin │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
      │                            │                   ────┐
      │                            │                  \ /  │ exit()
      │                            │                   X───┘
      │                            │                  /│\
      │                            │    waitpid()      │
      │                            │<─────────────────>│
      │                            │                   │
      │                            │           ╔═══════╧════════╗
      │                            │           ║Process reaped ░║
      │                            │           ╚═══════╤════════╝
      │          Status            │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
      │                            │                   │
      │       Status Frame         │                   │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                   │
     ┌┴┐                          ┌┴┐                 ┌┴┐
     │A│                          │S│                 │P│
     └─┘                          └─┘                 └─┘
```

The Execute Binary session is used to execute an arbitrary executable on the
host. It's an extension of the Execute session with the extra step of binary
transmission. Refer to the description of the Binary Upgrade and Execute
sessions.

### Binary Recombination Session
```
     ┌─┐               ┌─┐
     │A│               │S│
     └┬┘               └┬┘
      │      +RCB       │
      │────────────────>│
      │                 │
      │   RCB Frame     │
      │────────────────>│
      │                 │
      │     STDIO       │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
      │                 │
      │  STDIO Frame    │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
      │                 │
      │   STDIO Data    │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
      │                 │
      │     STDIO       │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
      │                 │
      │  STDIO Frame    │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
      │                 │
      │   STDIO Data    │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
      │                 │
    ╔═╧═════════════════╧═╗
    ║Repeat ...          ░║
    ╚═╤═════════════════╤═╝
      │     STDIO       │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
      │                 │
      │STDIO Frame, fin │
      │<─ ─ ─ ─ ─ ─ ─ ─ │
     ┌┴┐               ┌┴┐
     │A│               │S│
     └─┘               └─┘
```

The Binary Recombination session is used to initiate binary recombination of
Proone. It is mainly used by the Proone instances for M2M binary upgrade. The
submissive host can send a Status message to report an error at any point of the
session. The Status message is then the final message that concludes the
session.

## Protocol Error
The protocol error is reported using a Status message. The status code PROTO_ERR
is used. If the error is encountered in mid-session, the message id for the
session is used for the Status mesage. Otherwise, the special message id 0x7FFF
is used.

A protocol error is raised when

* The serialisation function returns FMT_ERR
* An unexpected op code for the session is encountered

## Footnotes
[^1]: This is to avoid the use of the null device because the `/dev` pseudo file
      system can be disabled on Linux. Use the host shell directly to run binary
      or command that cannot be "shushed"

[^2]: This can be done by doing `fork()` again from the child process and then
      calling `setsid()`
