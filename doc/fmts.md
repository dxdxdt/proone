# Proone Data Format Spec

Copyright (c) 2019-2021 David Timber &lt;mieabby@gmail.com&gt;

## Structure of Entire Proone Executable

## Formats
### Data Vault
```
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                                                               |
             +                                                               +
             .                                                               .
             .                           mask key                            .
             .                                                               .
             +                                                               +
             |                                                               |
 256         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |            offset_1           |            offset_2           |
             .                                                               .
             .                                                               .
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |            offset_N           | data_entries
 256 + 2 * N +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-----
```

Where

* N: the number of data entries (`NB_PRNE_DATA_KEY`)

| Field        | Description                                                   |
| ------------ | ------------------------------------------------------------- |
| mask         | 256-octet data mask key                                       |
| offset_n     | 16-bit unsigned integer offset to start of a data entry       |
| data_entries | series of data entries                                        |

**mask key** is 256-octet long mask key for masking *data* as a whole. It is
randomly generated for each build(i.e. each time proone-mkdvault is invoked).
**offset_***n* is an offset to the start of the *n*th data entry.
**data_entries** is a series of data entries. The format of a data entry is
described blow.

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     salt      |     type      |           data_size           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | data ...
   +-----
```

| Field     | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| salt      | 8-bit unsigned integer XOR salt value                            |
| type      | 8-bit unsigned integer type number                               |
| data_size | 16-bit unsigned integer data size in octets                      |

**salt** is a randomly value for salting XOR masking operation. **data_size** is
the length of the data in octets. **type** is the enum value used to indicate
the data type of the entry data. The definition of the values is described blow.

| Enum  | Value | Definition                                                   |
| ----- | ----- | ------------------------------------------------------------ |
| CSTR  | 0x00  | 8-bit narrow character string (UTF-8)                        |
| BIN   | 0x02  | binary data in octet units                                   |

Entry data is masked so that it can be accessed and unmasked randomly and
possibly in parallel.

```c
for (size_t i = 0; i < size; i += 1) {
	((uint8_t*)m)[i] ^= mask[(i + salt) % 256];
}
```

Where

* size: the length of data to be XOR'd
* m: the pointer to the start of the data to be XOR'd
* mask: the mask key - the 256-elements-long array of 8-bit unsigned integers
* salt: the 8-bit unsigned integer salt value

As evident from the algorithm shown above, the salt value simply acts as a
offset to the start of the mask key for the entry. In order to unmask an entry,
the *data_size* field must be unmasked first to determine the length of the
data. Once the length of the data is unmasked, the data part of the masked entry
data can be unmasked using the same algorithm again. When the unmasked data
entry is referenced and no longer needed, the entirety of the data must be
masked back to the original form so that the data entries are kept obsecure in
memory. This should be done immediately by calling `prne_dvault_reset()`.

Note that the total length of entries can be up to **around** 65,535 octets
because offsets are represented in 16-bit unsigned integer values. Since DVault
is valid for a build of Proone only, the format does not include length of data,
the number of entry or the version of Proone the DVault is build for. A build of
DVault should not be used in another build. The DVault must be rebuilt if
there's change in the order of the entry keys or any data in the entries.

Implementations

* /src/proone-mkdvault.h, /src/proone-mkdvault.c: tool for building the dvault
  binary file. The contents of the file are written in memory and tested before
  being dumped to a file
* /src/dvault.h, /src/dvault.c: core algorithms for masking and unmasking DVault

### Binary Archive
```
            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         signature ...                         |
         4 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | ... signature |      rev      |            nb_bin             |
         8 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                             index                             .
           |                                                               |
 8 + 8 * N +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | data ...
           +-----
```

Where

* N: equal to *nb_bin*

| Field     | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| signature | 5-octet identity signature                                       |
| rev       | 8-bit unsigned integer revision number(0)                        |
| nb_bin    | 16-bit unsigned integer number of executables                    |
| index     | series of index entries of executables                           |
| data      | compressed octet stream of executables                           |

**signature** is the identity "magic" string `70 72 2d 62 61`("pr-ba"). **rev**
is the revision of the binary archive. For this version of format, zero is used.
**nb_bin** is the number of the executables that the binary archive contains.
**index** is the index of the executables. The format of one entry is described
below.

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              rsv              |    os_code    |   arch_code   |
 4 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      rsv      |                     size                      |
 8 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field     | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| rsv       | Zeroes                                                           |
| os_code   | 8-bit unsigned integer OS code                                   |
| arch_code | 16-bit unsigned integer arch code                                |
| size      | 24-bit unsigned integer size of uncompressed executable          |

**rsv** fields are zero-filled padding bits. Each index entry is padded with
zeroes so that the size is a multiple of 8 octets. See htbt.md for **os_code**
and **arch_code**. **size** is the size of the executable in the original
uncompressed form in octets. The offset to the start of the executable in the
compressed stream can be calculated by summing all the sizes of executable that
appear before the executable to be extracted.

Implementations

* /src/proone-pack.c: build tool for combining binary files to make target
  executables and nybin file
* /src/pack.h, /src/pack.c: indexing and binary recombination implementation

#### NYBIN
```
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |            dv_len             |         signature ...         |
     4 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                 signature ...                 |      rev      |
     8 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       .                                                               .
       .                            dv_data                            .
       .                                                               .
       |                                                               |
 8 + L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | ba ...
       +-----
```

Where:

* L: the length of the *dv_data* including the padding octets

| Field     | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| dv_len    | 16-bit unsigned integer length of data vault                     |
| signature | 5-octet identity signature                                       |
| rev       | 8-bit unsigned integer revision number                           |
| dv_data   | data vault padded to multiple of 8 bytes                         |
| ba        | binary archive                                                   |

The NYBIN format is for storing data necessary for launching a new instance of
Proone as a file on a file system. A NYBIN file can be used with maintenance
tools to upgrade the binary of instances or launching an index case instance.
The file extension ".nybin" is used. The magic for the file format is specified
below(magic(5)).

```mgc
2       string          nybin           Proone NYBIN file,
>7      byte            x               revision %u
```

Implementations

* /src/proone-pack: build tool for combining binary files to make target
  executables and nybin file
* /src/pack.h, /src/pack.c: indexing and binary recombination implementation

### Cred Dict
"Credential dictionary"("cred dict" for short) is a name of two different
formats. The one being the "source" text file format and the other being the
binary format, which is deserialised by the Proone instance for BNE parameter.

Implementations

* /src/proone-mkcdict.c: build tool for converting the text format cred dict to
  binary
* /src/cred_dict.h, /src/cred_dict.c: the core implementation

#### Text Format
The source cred dict text files contain the lines of user name and password
combination. The format of combo lines is specified below.

```
<WEIGHT>    <USERNAME>    [PW]
```

| Field    | Description                                                       |
| -------- | ----------------------------------------------------------------- |
| WEIGHT   | (required) weight value with range of 0 to 255                    |
| USERNAME | (required) username string                                        |
| PW       | (optional) password string                                        |

The *WEIGHT* field is a 8-bit unsigned integer used internally. The higher the
weight value, the higher chance of the combo being tried out of all the other
combos that have not been tried. This field can be used to reflect the
prevalence of certain devices. Refer to the source code for detail.

The encoding of the file is UTF-8. The file must not contain BOM(Byte Order
Mark). Each fields are separated one or more white spaces. Files are parsed line
by line. The leading and trailing white spaces are trimmed before the line is
interpreted. The lines that start with the character '#' are ignored. User name
and password combinations that contain white spaces are not supported.

Note that this format is likely to be replaced by more complex formats such as
XML and JSON as the format cannot represent combos with white space characters
or escaped characters.

#### Binary Format
```
      0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              cnt              |
 2 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |
   .                               .
   .            entries            .
   .                               .
   |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |
   .                               .
   .            strings            .
   .                               .
   |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 0 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            idx_id             |            idx_pw             |
 4 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    weight     |
 5 +-+-+-+-+-+-+-+-+
```

* Dictionary Structure

| Field   | Description                                                        |
| ------- | ------------------------------------------------------------------ |
| cnt     | 16-bit unsigned integer the number of entries                      |
| entries | array of 5-octet dictionary entry tuples                           |
| strings | series of null-terminated strings                                  |

* Entry Tuple Structure

| Field   | Description                                                        |
| ------- | ------------------------------------------------------------------ |
| idx_id  | Octet offset to the start of the string for the user name          |
| idx_pw  | Octet offset to the start of the string for the password           |
| weight  | 8-bit unsigned integer weight value                                |

The structure consists of two parts: the strings pool and the entries. One entry
represents the credentials of an account found in the vulnerable devices. The
string pool contains the strings used in the credentials.

The size of *entries* can be calculated using *cnt*. *entries* is followed
immediately by *strings*. *idx_id* and *idx_pw* are offsets to the strings in
the string pool, the value zero being the offset to the very first string in the
pool. The pool will contain an empty string if the dictionary contains an
account with no password.
