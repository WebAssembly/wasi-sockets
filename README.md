# [WASI Sockets]

A proposed [WebAssembly System Interface](https://github.com/WebAssembly/WASI) API.

### Current Phase

Phase 1

### Champions

- Dave Bakker (@badeend)

### Phase 4 Advancement Criteria

- At least two independent production implementations.
- Implementations available for at least Windows, Linux & MacOS.
- A testsuite that passes on the platforms and implementations mentioned above.

## Table of Contents [if the explainer is longer than one printed page]

- [Introduction](#introduction)
- [Goals](#goals-or-motivating-use-cases-or-scenarios)
- [Non-goals](#non-goals)
- [API walk-through](#api-walk-through)
  - [Use case 1](#use-case-1)
  - [Use case 2](#use-case-2)
- [Detailed design discussion](#detailed-design-discussion)
  - [Dualstack sockets](#dualstack-sockets)
  - [Modularity](#modularity)
  - [POSIX compatibility](#posix-compatibility)
  - [Why not getaddrinfo?](#why-not-getaddrinfo)
- [Considered alternatives](#considered-alternatives)
  - [[Alternative 1]](#alternative-1)
  - [[Alternative 2]](#alternative-2)
- [Stakeholder Interest & Feedback](#stakeholder-interest--feedback)
- [References & acknowledgements](#references--acknowledgements)

### Introduction

This proposal adds TCP & UDP sockets and domain name lookup to WASI. It adds the basic BSD socket interface with the intent to enable server and client networking software running on WebAssembly.

Unlike BSD sockets, WASI sockets require capability handles to create sockets and perform domain name lookups. On top of capability handles, WASI Socket implementations should implement deny-by-default firewalling.

The socket APIs have been split up into standalone protocol-specific WASI modules. Both current and future socket modules can then be tailored to the needs of that specific protocol and progress the standardization process independently.

This proposal introduces 4 new WASI modules:
- [wasi-socket.wit](./wasi-socket.wit)
- [wasi-socket-tcp.wit](./wasi-socket-tcp.wit)
- [wasi-socket-udp.wit](./wasi-socket-udp.wit)
- [wasi-ip-name-lookup.wit](./wasi-ip-name-lookup.wit)

### Goals

- Start out as an MVP; add the bare minimum amount of APIs required to create a basic functioning TCP/UDP application.
- Toolchains must be able to provide a POSIX compatible interface on top of the functions introduced in this proposal.

### Non-goals

- SSL/TLS support
- HTTP(S) support
- Retrieving network-related information of the executing machine, like: installed network interfaces and the computer hostname.

### API walk-through

[Walk through of how someone would use this API.]

#### Use case: Wasm module per connection

Due to the low startup cost of Wasm modules, its feasible for server software with Wasm integration to spawn a Wasm module for each inbound connection. Each module instance is passed only the accepted client socket. This way, all connection handlers are completely isolated from each other. This resembles PHP's "shared nothing" architecture.

#### [Use case 2]

[Provide example code snippets and diagrams explaining how the API would be used to solve the given problem]

### Detailed design discussion

[This section should mostly refer to the .wit.md file that specifies the API. This section is for any discussion of the choices made in the API which don't make sense to document in the spec file itself.]

#### Dualstack sockets

IPv6 sockets returned by this proposal are never dualstack because that can't easily be implemented in a cross platform manner. If an application wants to serve both IPv4 and IPv6 traffic, it should create two sockets; one for IPv4 traffic and one for IPv6 traffic.

This behaviour is deemed acceptable because all existing applications that are truly cross-platform must already handle this scenario. Dualstack support can be part of a future proposal adding it as an opt-in feature.

Related issue: [Emulate dualstack sockets in userspace](https://github.com/WebAssembly/wasi-sockets/issues/1)

#### Modularity

This proposal is not POSIX compatible by itself. The BSD sockets interface is highly generic. The same functions have different semantics depending on which kind of socket they're called on. The man-pages are riddled with conditional documentation. If this had been translated 1:1 into a WASI API using Interface Types, this would have resulted in a proliferation of optional parameters and result types.

Instead, the sockets API has been split up into protocol-specific modules. All BSD socket functions have been pushed into these protocol-specific modules and tailored to their specific needs. Functions, parameters and flags that did not apply within a specific context have been dropped.

A downside of this approach is that functions that do *not* differ per protocol (bind, local_address, connect, shutdown, ...) are duplicated as well.

#### POSIX compatibility

The [wasi-socket](./wasi-socket.wit) module exports a `kind` function that can be called on any kind of socket.
The return value can be used to dispatch calls to the correct WASI module.

In pseudo code:

```rs
fn socket(address_family: i32, socket_type: i32, protocol: i32) {

    let ambient_network_capability = // Pluck it out of thin air.

    match (socket_type, protocol) {
        (SOCK_STREAM, 0) => wasi_socket_tcp::create_tcp_socket(ambient_network_capability, address_family),
        (SOCK_DGRAM, 0) => wasi_socket_udp::create_udp_socket(ambient_network_capability, address_family),
        _ => EINVAL,
    }
}

fn recvfrom(socket: i32, flags: i32) {
    
    let kind = wasi_socket::kind(socket);
    let peek = flags & MSG_PEEK;

    match (kind, peek) {
        (Udp, false) => wasi_socket_udp::receive_from(socket),
        (Udp, true) => wasi_socket_udp::peek_from(socket),
        (Tcp, false) => (wasi_io_streams::read(socket), address: 0, truncated: false),
        (Tcp, true) => (wasi_socket_tcp::peek(socket), address: 0, truncated: false),
        _ => EBADF,
    }
}
```


#### Why not getaddrinfo?

The proposed [wasi-ip-name-lookup](./wasi-ip-name-lookup.wit) module focuses strictly on translating internet domain names to ip addresses and nothing else.

Like BSD sockets, `getaddrinfo` is very generic and multipurpose by design. The proposed WASI API is *not*. This eliminates many of the other "hats" getaddrinfo has (and potential security holes), like:
- Mapping service names to port numbers (`"https"` -> `443`)
- Mapping service names/ports to socket types (`"https"` -> `SOCK_STREAM`)
- Network interface name translation (`%eth0` -> `1`)
- IP address deserialization (`"127.0.0.1"` -> `Ipv4Address(127, 0, 0, 1)`)
- IP address string canonicalization (`"0:0:0:0:0:0:0:1"` -> `"::1"`)
- Constants lookup for `INADDR_ANY`, `INADDR_LOOPBACK`, `IN6ADDR_ANY_INIT` and `IN6ADDR_LOOPBACK_INIT`.

Many of these functionalities can be shimmed in the libc implementation. Though some require future WASI additions. An example is network interface name translation. That requires a future `if_nametoindex`-like syscall.


#### Security

Wasm modules can not open sockets by themselves without a network capability handle. Even with capability handles, WASI implementations should deny all network access by default. Access should be granted at the most granular level possible. See [Granting Access](./GrantingAccess.md) for examples. Whenever access is denied, the implementation should return EACCES.

This means Wasm modules will get a lot more EACCES errors compared to when running unsandboxed. This might break existing applications that, for example, don't expect creating a TCP client to require special permissions.

At the moment there is no way for a Wasm modules to query which network access permissions it has. The only thing it can do, is to just call the WASI functions it needs and see if they fail.


### Considered alternatives

[This section is not required if you already covered considered alternatives in the design discussion above.]

#### [Alternative 1]

[Describe an alternative which was considered, and why you decided against it.]

#### [Alternative 2]

[etc.]

### Stakeholder Interest & Feedback

TODO before entering Phase 3.

[This should include a list of implementers who have expressed interest in implementing the proposal]

### References & acknowledgements

Many thanks for valuable feedback and advice from:

- [Person 1]
- [Person 2]
- [etc.]
