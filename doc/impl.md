# Proone Implementation Note
## Dynamic Memory Allocation
POSIX compliant dynamic memory functions may return a valid pointer that can be
passed to `free()`(MALLOC(3)). Proone does not appreciate this inconsistency as
it has to be tolerant to memory allocation failure.

Consider following snippet.

```c
int *get_int_arr (size_t n) {
  int *ret = (int*)calloc(sizeof(int), n);

  if (ret == NULL) {
    abort();
  }

  for (size_t i = 0; i < n; i += 1) {
    ret[i] = i % INT_MAX;
  }

  return ret;
}
```

The behaviour of this code depends on whether `calloc()` returns a null or valid
pointer for zero-length allocation. To avoid mistakes like this one, the memory
allocation functions of the Proone framework(prefixed `prne_`) always returns
NULL for zero-length allocation. This way, the implementation is forced to infer
memory allocation failure from the parameter and the return value.

```c
  if (n > 0 && ret == NULL) {
```

All the memory allocated using the framework allocation functions(`prne_*()`)
must be freed with `prne_free()`.

## Resource Allocation Hook
One of the purposes of `prne_free()` and `prne_close()` is to facilitate the
implementation of a framework-level resource debugging(like MSVC macros) in the
future. This may be useful when use of Valgrind becomes too cumbersome. Another
is to keep a registry of the file descriptors for use in `prefork()` and
`atfork()` equivalent.

## Resource Allocation
### Transparent Structures

```c
prne_init_llist()
prne_free_llist()
```

Transparent structures must be initialised and deinitialised using the functions
provided.

The initialisation functions set the members of the structures to their default
values and prepares the structures for the deinitialisation calls. This is
normally done by zeroing the entire structure, but there are exceptions where
values other than zero are used for default values.

The deinitialisation functions are like "desctructors" in other languages. The
functions free any dynamically allocated members. For the structures that have
no dynamic members, the functions have no effect.

All initialisation and deinitialisation functions must be used to ensure that
the members added in the future are initialised/freed. Are guaranteed to take
one argument.

Deinitialised structures are not reusable. The structures must be reinitialised
after being deinitialised.

### Opaque Types

```c
prne_rnd_alloc_well512()
prne_alloc_resolv()
```

Opaque types, usually poly-morphed objects(class), are dynamically allocated by
"instantiation functions". Examples include `resolv` and `rnd`. The destructor
functions are provided upon successful instantiation. The underlying abstraction
layer is responsible for the invocation of the destructor functions.

### Dynamic Members

```c
prne_htbt_alloc_host_info()
prne_alloc_iobuf()
```

Some types have dynamically allocated members and the dynamic member allocation
functions are defined for dynamic members. Dynamic members can be freed by
calling the functions with zero for the size argument. Dynamic members are freed
by the deinitialisation functions.

### Ownership of Dynamically Resources
Some structures have the `ownership` flag member so their dynamic members,
especially large memory, can be used with other instances. If the structure has
the flag and its value is set, it means that the structure is the owner of the
dynamically allocated memory and is responsible for freeing it upon destruction
by the deinitialisation function. If the flag is unset, the deinitialisation
function will not free the dynamic members.

The flag can be used to form a chain of structures with the same dynamic
members. The flag can also be used to use data from .bss or .data as dynamic
members.
