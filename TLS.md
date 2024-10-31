## Examples (in pseudocode)

### Minimal client

```rs
// TCP setup:
let ip = wasi_sockets::resolve_addresses("example.com").await?[0];
let tcp_client = wasi_sockets::TcpSocket::new();
let (tcp_input, tcp_output) = tcp_client.connect(ip, 443).await;

// TLS setup:
let (tls_input, tls_output) = wasi_tls::ClientConnection::new(tcp_input, tcp_output)
    .connect("example.com")?
    .finish().await?;

// Usage:
tls_output.blocking_write_and_flush("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
let http_response = tls_input.blocking_read();

println!(http_response);
```

### Minimal server

```rs
// Prepare certificates + private key:
let id = wasi_tls::PrivateIdentity::parse(
    fs::read("private.key"),
    fs::read("public.crt"),
)?;

// TCP setup:
let tcp_server = wasi_sockets::TcpSocket::new();
tcp_server.bind(443);
tcp_server.listen();
loop {
    let (tcp_client, tcp_input, tcp_output) = tcp_server.accept().await?;

    // TLS setup:
    let handshake = wasi_tls::ServerConnection::new(tcp_input, tcp_output).accept();
    handshake.configure_server_identities([id]);
    let (tls_input, tls_output) = handshake.finish().await?;

    // Usage:
    let http_request = tls_input.blocking_read();
    println!(http_request);
    tls_output.blocking_write_and_flush("HTTP/1.1 200 OK\r\n\r\n");
}
```

### Client features showcase

```rs
let client_cert = wasi_tls::PrivateIdentity::parse(
    fs::read("private.key"),
    fs::read("public.crt"),
)?;

let ip = wasi_sockets::resolve_addresses("example.com").await?[0];

let tcp_client = wasi_sockets::TcpSocket::new();
let (tcp_input, tcp_output) = tcp_client.connect(ip, 443).await;

let tls_connection = wasi_tls::ClientConnection::new(tcp_input, tcp_output);
let handshake = tls_connection.connect("example.com")?;

// Configure settings:
{
    handshake.configure_alpn_ids(["h2"]);
}

// Receive and validate server certificate:
{
    let server_cert = handshake.verify_server_identity().await?;
    let parsed_cert = parse_der(server_cert.export_X509_chain()); // Note: certificate parsing must be done by the guest.
    println!(parsed_cert); 

    // At the time of writing, validations performed here are always *in addition*
    // to the TLS implementation's default validation.

    if (/* custom logic */) {
        handshake.abort();
        return;
    }
}

// Handle client certificate request:
match handshake.receive_client_identity_request().await? {
    Some(certificate_request) => certificate_request.respond([client_cert]), // TODO: add showcase on how to select a client cert based on server-indicated authorities.
    None => { /* No client certificate requested. */ }, 
}

let (tls_input, tls_output) = handshake.finish().await?;

// Display TLS connection status:
println!(tls_connection.server_name());
println!(tls_connection.alpn_id());
println!(tls_connection.client_identity());
println!(tls_connection.server_identity());
println!(tls_connection.protocol_version());
println!(tls_connection.cipher_suite());

tls_output.blocking_write_and_flush("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
let http_response = tls_input.blocking_read();

println!(http_response);
```

### Server features showcase

```rs
let id1 = wasi_tls::PrivateIdentity::parse(
    fs::read("private1.key"),
    fs::read("public1.crt"),
)?;
let id2 = wasi_tls::PrivateIdentity::parse(
    fs::read("private2.key"),
    fs::read("public2.crt"),
)?;

let tcp_server = wasi_sockets::TcpSocket::new();
tcp_server.bind(443);
tcp_server.listen();

loop {
    let (tcp_client, tcp_input, tcp_output) = tcp_server.accept().await?;

    let tls_connection = wasi_tls::ServerConnection::new(tcp_input, tcp_output);
    let handshake = tls_connection.accept();

    // Configure connection properties based on ClientHello:
    {
        let client_hello = handshake.receive_client_hello().await?;
        println!(client_hello.server_name());
        println!(client_hello.alpn_ids());
        println!(client_hello.cipher_suites());

        match client_hello.server_name() {
            Some("example.com") => {
                handshake.configure_alpn_ids(["h2"]);
                handshake.configure_server_identities([id1]);
            }
            _ => {
                handshake.configure_alpn_ids(["h2", "http/1.1"]);
                handshake.configure_server_identities([id2]);
            }
        }
    }

    // Request client certificate:
    {
        match handshake.request_client_identity().await? {
            Some(client_cert) => {
                let parsed_cert = parse_der(client_cert.export_X509_chain()); // Note: certificate parsing must be done by the guest.
                println!(parsed_cert); 

                // At the time of writing, validations performed here are always *in addition*
                // to the TLS implementation's default validation.

                if (/* custom logic */) {
                    handshake.abort();
                    return;
                }
            }
            None => {
                // Client didn't provide a certificate.
            }, 
        }
    }

    let (tls_input, tls_output) = handshake.finish().await?;

    // Display TLS connection status:
    println!(tls_connection.server_name());
    println!(tls_connection.alpn_id());
    println!(tls_connection.client_identity());
    println!(tls_connection.server_identity());
    println!(tls_connection.protocol_version());
    println!(tls_connection.cipher_suite());

    let http_request = tls_input.blocking_read();
    println!(http_request);

    // Perform post-handshake authentication based on HTTP path:
    if http_request.starts_with("GET /secure") && tls_connection.client_identity() == None {
        let _client_cert = tls_connection.request_client_identity().await;
    }

    tls_output.blocking_write_and_flush("HTTP/1.1 200 OK\r\n\r\n");
}
```

## Mapping to .NET types

### `SslStream`

| Member                             | WASI equivalent |
|------------------------------------|--|
| `CheckCertRevocationStatus`        | ⛔ Not supported. Can be faked to return `false`. |
| `CipherAlgorithm`                  | ⛔ Not supported. |
| `CipherStrength`                   | ⛔ Not supported. |
| `HashAlgorithm`                    | ⛔ Not supported. |
| `HashStrength`                     | ⛔ Not supported. |
| `IsAuthenticated`                  | ✅ `true` after the handshake finished successfully. |
| `IsEncrypted`                      | ✅ Alias for `IsAuthenticated` |
| `IsMutuallyAuthenticated`          | ✅ Check that the connection `IsAuthenticated`, and that both `client-identity` and `server-identity` are not null. |
| `IsServer`                         | ✅ To be maintained in userland |
| `IsSigned`                         | ✅ Alias for `IsAuthenticated` |
| `KeyExchangeAlgorithm`             | ⛔ Not supported. |
| `KeyExchangeStrength`              | ⛔ Not supported. |
| `LocalCertificate`                 | ✅ `client-connection::client-identity` / `server-connection::server-identity` |
| `NegotiatedApplicationProtocol`    | ✅ `client-connection::alpn-id` / `server-connection::alpn-id` |
| `NegotiatedCipherSuite`            | ✅ `client-connection::cipher-suite` / `server-connection::cipher-suite` |
| `RemoteCertificate`                | ✅ `client-connection::server-identity` / `server-connection::client-identity` |
| `SslProtocol`                      | ✅ `client-connection::protocol-version` / `server-connection::protocol-version` |
| `TargetHostName`                   | ✅ `client-connection::server-name` / `server-connection::server-name` |
| `TransportContext`                 | ❔ Unknown |
| `AuthenticateAsClient`, `AuthenticateAsClientAsync`, `BeginAuthenticateAsClient`, `EndAuthenticateAsClient` | ✅ `client-connection::connect`. See `SslClientAuthenticationOptions` table below for more details. |
| `AuthenticateAsServer`, `AuthenticateAsServerAsync`, `BeginAuthenticateAsServer`, `EndAuthenticateAsServer` | ✅ `server-connection::accept`. See `SslServerAuthenticationOptions` table below for more details. |
| `NegotiateClientCertificateAsync`  | ✅ `server-connection::request-client-identity` |
| `Read`, `ReadAsync`, `BeginRead`, `EndRead`, `ReadByte`, `ReadAtLeast`, `ReadAtLeastAsync`, `ReadExactly`, `ReadExactlyAsync` | ✅ Use the `input-stream` returned by the handshake `finish` method. |
| `Write`, `WriteAsync`, `BeginWrite`, `EndWrite`, `WriteByte` | ✅ Use the `output-stream` returned by the handshake `finish` method. |
| `CopyTo`, `CopyToAsync`            | ✅ Currently implemented in user space. Could be specialized as `output-stream::splice` in case both sides are WASI streams. |
| `Flush`, `FlushAsync`              | ✅ Use the `output-stream` returned by the handshake `finish` method. |
| `Dispose`, `DisposeAsync`, `Close`, `Finalize`, `ShutdownAsync` | ⛔ TODO: graceful shutdown |
| `CanRead`                          | ✅ Implemented in user space |
| `ReadTimeout`                      | ✅ Implemented in user space |
| `CanWrite`                         | ✅ Implemented in user space |
| `WriteTimeout`                     | ✅ Implemented in user space |
| `CanTimeout`                       | ✅ Implemented in user space |
| `Position`                         | ✅ Implemented in user space |
| `InnerStream`                      | ✅ Implemented in user space |
| `LeaveInnerStreamOpen`             | ✅ Implemented in user space |
| `CanSeek`                          | ✅ Not applicable to network streams. `false` |
| `Seek`                             | ✅ Not applicable to network streams. `throw new NotSupportedException()` |
| `Length`                           | ✅ Not applicable to network streams. `throw new NotSupportedException()` |
| `SetLength`                        | ✅ Not applicable to network streams. `throw new NotSupportedException()` |
| `ToString`, `Equals`, `GetHashCode`, `GetLifetimeService`, `GetType`, `InitializeLifetimeService`, `MemberwiseClone`, `ObjectInvariant`, `CreateObjRef`, `CreateWaitHandle` | ✅ Generic .NET methods. Not specific to TLS. Implemented in user space |


### `SslClientAuthenticationOptions`

| Member                                | WASI equivalent |
|---------------------------------------|--|
| `AllowRenegotiation`                  | ⛔ Not supported. |
| `AllowTlsResume`                      | ⛔ Not supported. |
| `ApplicationProtocols`                | ✅ `client-handshake::configure-alpn-ids` |
| `CertificateChainPolicy`              | ❔ Unknown |
| `CertificateRevocationCheckMode`      | ⚠️ Not supported. Or effectively: only `NoCheck` is supported. |
| `CipherSuitesPolicy`                  | ⚠️ Not supported. Or effectively: only `null` (== OS default) is supported. |
| `ClientCertificateContext`            | ✅ Use `client-identity-request::respond` returned by `client-handshake::receive-client-identity-request` |
| `ClientCertificates`                  | ✅ Use `client-identity-request::respond` returned by `client-handshake::receive-client-identity-request` |
| `EnabledSslProtocols`                 | ⚠️ Not supported. Or effectively: only `None` (== OS default) is supported. |
| `EncryptionPolicy`                    | ⚠️ (Obsolete) Not supported. Or effectively: only `RequireEncryption` is supported. |
| `LocalCertificateSelectionCallback`   | ✅ `client-handshake::receive-client-identity-request` |
| `RemoteCertificateValidationCallback` | ✅ `client-handshake::receive-server-identity` |
| `TargetHost`                          | ✅ The `server-name` parameter of `client-connection::connect` |


### `SslServerAuthenticationOptions`

| Member                                | WASI equivalent |
|---------------------------------------|--|
| `AllowRenegotiation`                  | ⛔ Not supported. |
| `AllowTlsResume`                      | ⛔ Not supported. |
| `ApplicationProtocols`                | ✅ `server-handshake::configure-alpn-ids` |
| `CertificateChainPolicy`              | ❔ Unknown |
| `CertificateRevocationCheckMode`      | ⚠️ Not supported. Or effectively: only `NoCheck` is supported. |
| `CipherSuitesPolicy`                  | ⚠️ Not supported. Or effectively: only `null` (== OS default) is supported. |
| `ClientCertificateRequired`           | ✅ `abort` the handshake if `server-handshake::request-client-identity` resolves with `none`. |
| `EnabledSslProtocols`                 | ⚠️ Not supported. Or effectively: only `None` (== OS default) is supported. |
| `EncryptionPolicy`                    | ⚠️ (Obsolete) Not supported. Or effectively: only `RequireEncryption` is supported. |
| `RemoteCertificateValidationCallback` | ✅ `server-handshake::request-client-identity` |
| `ServerCertificate`                   | ✅ `server-handshake::configure-identities` |
| `ServerCertificateContext`            | ✅ `server-handshake::configure-identities` |
| `ServerCertificateSelectionCallback`  | ✅ Wait for the ClientHello using `server-handshake::receive-client-hello` and call `server-handshake::configure-identities` after that. |


### `SslClientHelloInfo`

| Member         | WASI equivalent |
|----------------|--|
| `ServerName`   | ✅ `client-hello::server-name` |
| `SslProtocols` | ⛔ Not supported. |


## Mapping to Node.js `tls` module

### APIs

| API                                | WASI equivalent |
|------------------------------------|--|
| `TLSSocket.localAddress`, `TLSSocket.localPort`, `TLSSocket.remoteAddress`, `TLSSocket.remoteFamily`, `TLSSocket.remotePort`, `TLSSocket.address`, `Server.address`, `Server.listen`, `Server: 'connection' event`, `Server.close` | ✅ These APIs can be implemented using [wasi-sockets](https://github.com/WebAssembly/wasi-sockets). The WASI TLS interface does not do any I/O. |
| `connect`, `createSecureContext`, `createSecurePair`, `createServer`, `TLSSocket.constructor` | ✅ Use the `client-connection` or `server-connection` resource. See the connection options table below for a more detailed breakdown. |
| `checkServerIdentity`              | ✅ Implementable in user space. |
| `getCiphers`                       | ⛔ Not supported. |
| `rootCertificates`                 | ⛔ Not supported. |
| `CLIENT_RENEG_LIMIT`               | ⛔ Not supported. |
| `CLIENT_RENEG_WINDOW`              | ⛔ Not supported. |
| `DEFAULT_MAX_VERSION`              | ⛔ Not supported. Can be faked to return the highest known protocol of the compiled Node.JS version. |
| `DEFAULT_MIN_VERSION`              | ⛔ Not supported. Can be faked to return the lowest known protocol of the compiled Node.JS version. |
| `DEFAULT_ECDH_CURVE`               | ⚠️ Not supported. Or effectively: only `'auto'` is supported. |
| `DEFAULT_CIPHERS`                  | ⛔ Not supported. |
| `TLSSocket: 'keylog' event`, `Server: 'keylog' event` | ⛔ Not supported. |
| `TLSSocket: 'OCSPResponse' event`  | ⛔ Not supported. |
| `TLSSocket: 'secureConnect' event`, `Server: 'secureConnection' event` | ✅ Triggered when the handshake's `finish` future resolves successfully. |
| `TLSSocket: 'session' event`       | ⛔ Not supported. |
| `TLSSocket.alpnProtocol`           | ✅ `client-connection::alpn-id` / `server-connection::alpn-id` |
| `TLSSocket.authorizationError`     | ⚠️ See `TLSSocket.authorized`. |
| `TLSSocket.authorized`             | ⚠️ Peer certificate validation can not be disabled. So if the `client-connection::server-identity` or `server-connection::client-identity` is not null, the connection can be considered "authorized". |
| `TLSSocket.disableRenegotiation`   | ⛔ Not supported. |
| `TLSSocket.enableTrace`            | ⛔ Not supported. |
| `TLSSocket.encrypted`              | ✅ Always `true`. |
| `TLSSocket.exportKeyingMaterial`   | ⛔ Not supported. |
| `TLSSocket.getCertificate`         | ✅ `client-connection::client-identity` / `server-connection::server-identity` |
| `TLSSocket.getCipher`              | ✅ `client-connection::cipher-suite` / `server-connection::cipher-suite` |
| `TLSSocket.getEphemeralKeyInfo`    | ⛔ Not supported. |
| `TLSSocket.getFinished`            | ⛔ Not supported. |
| `TLSSocket.getPeerCertificate`     | ✅ `client-connection::server-identity` / `server-connection::client-identity` |
| `TLSSocket.getPeerFinished`        | ⛔ Not supported. |
| `TLSSocket.getPeerX509Certificate` | ✅ `client-connection::server-identity` / `server-connection::client-identity` |
| `TLSSocket.getProtocol`            | ✅ `client-connection::protocol-version` / `server-connection::protocol-version` |
| `TLSSocket.getSession`             | ⛔ Not supported. Can be faked to return `undefined`. |
| `TLSSocket.getSharedSigalgs`       | ⛔ Not supported. |
| `TLSSocket.getTLSTicket`           | ⛔ Not supported. Can be faked to return `undefined`. |
| `TLSSocket.getX509Certificate`     | ✅ `client-connection::client-identity` / `server-connection::server-identity` |
| `TLSSocket.isSessionReused`        | ⛔ Not supported. Can be faked to return `false`. |
| `TLSSocket.renegotiate`            | ⚠️ Partially supported. Only client certificate requests are supported post-handshake. See `server-connection::request-client-identity` |
| `TLSSocket.servername`             | ✅ `client-connection::server-name` / `server-connection::server-name` |
| `TLSSocket.setKeyCert`             | ✅ `server-handshake::configure-identities` |
| `TLSSocket.setMaxSendFragment`     | ⛔ Not supported. |
| `Server: 'newSession' event`       | ⛔ Not supported. |
| `Server: 'OCSPRequest' event`      | ⛔ Not supported. |
| `Server: 'resumeSession' event`    | ⛔ Not supported. |
| `Server: 'tlsClientError' event`   | ✅ To be implemented in user space. `'tlsClientError'` == any reason the `server-handshake` could not be `finish`ed successfully. |
| `Server.addContext`                | ✅ To be implemented in user space. Use `server-handshake::receive-client-hello` to wait for the ClientHello and then configure the `server-handshake` based on the registered contexts. |
| `Server.getTicketKeys`             | ⛔ Not supported. |
| `Server.setSecureContext`          | ✅ See `Server.addContext`. |
| `Server.setTicketKeys`             | ⛔ Not supported. |


### Connection options

| Option                 | WASI equivalent |
|------------------------|--|
| `ALPNProtocols`        | ✅ `client-handshake::configure-alpn-ids` / `server-handshake::configure-alpn-ids` |
| `ALPNCallback`         | ✅ Use `server-handshake::receive-client-hello` to receive the ClientHello. The return value of the callback can be passed as single item list into `server-handshake::configure-alpn-ids`. |
| `SNICallback`          | ✅ `server-handshake::receive-client-hello` |
| `ca`                   | ⛔ Not supported. |
| `cert`, `key`, `pfx`   | ✅ `client-identity-request::respond` / `server-handshake::configure-identities` |
| `passphrase`           | ⚠️ Not applicable. Only raw private key data is accepted by `private-identity::parse`. |
| `checkServerIdentity`  | ✅ `client-handshake::verify-server-identity` |
| `ciphers`              | ⛔ Not supported. |
| `clientCertEngine`     | ⛔ (Deprecated) Not supported. |
| `crl`                  | ⛔ Not supported. |
| `dhparam`              | ⛔ Not supported. |
| `ecdhCurve`            | ⛔ Not supported. |
| `enableTrace`          | ⛔ Not supported. |
| `handshakeTimeout`     | ✅ Implementable in user space |
| `honorCipherOrder`     | ⛔ Not supported. |
| `isServer`             | ✅ Indicates whether a `client-connection` or `server-connection` should be constructed. |
| `key`                  | ✅ `client-identity-request::respond` / `server-handshake::configure-identities` |
| `minDHSize`            | ⛔ Not supported. |
| `minVersion`, `maxVersion`, `secureProtocol` | ⛔ Not supported. |
| `privateKeyEngine`     | ⛔ (Deprecated) Not supported. |
| `privateKeyIdentifier` | ⛔ (Deprecated) Not supported. |
| `pskCallback`          | ⛔ Not supported. |
| `pskIdentityHint`      | ⛔ Not supported. |
| `rejectUnauthorized`   | ⚠️ Not supported. Certificates are always validated. Or effectively: only `true` is supported. |
| `requestCert`          | ✅ When `true`, use `server-handshake::receive-client-hello` |
| `requestOCSP`          | ⛔ Not supported. |
| `secureOptions`        | ⛔ Not supported. |
| `servername`           | ✅ The `server-name` parameter of `client-connection::connect` |
| `session`              | ⛔ Not supported. |
| `sessionIdContext`     | ⛔ Not supported. |
| `sessionTimeout`       | ⛔ Not supported. |
| `sigalgs`              | ⛔ Not supported. |
| `ticketKeys`           | ⛔ Not supported. |

