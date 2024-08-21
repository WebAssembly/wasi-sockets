## Mapping to .NET types

### `SslStream`

| Member                             | WASI equivalent |
|------------------------------------|--|
| `CheckCertRevocationStatus`        | ⛔ Not supported. Can be faked to return `false`. |
| `CipherAlgorithm`                  | ⛔ Not supported. |
| `CipherStrength`                   | ⛔ Not supported. |
| `HashAlgorithm`                    | ⛔ Not supported. |
| `HashStrength`                     | ⛔ Not supported. |
| `IsAuthenticated`                  | ✅ `true` after the `connected`/`accepted` suspension occurred. |
| `IsEncrypted`                      | ✅ Alias for `IsAuthenticated` |
| `IsMutuallyAuthenticated`          | ✅ Check that the connection `IsAuthenticated`, and that both `client-identity` and `server-identity` are not null. |
| `IsServer`                         | ✅ To be maintained in userland |
| `IsSigned`                         | ✅ Alias for `IsAuthenticated` |
| `KeyExchangeAlgorithm`             | ⛔ Not supported. |
| `KeyExchangeStrength`              | ⛔ Not supported. |
| `LocalCertificate`                 | ✅ `tls-client::client-identity` / `tls-server::server-identity` |
| `NegotiatedApplicationProtocol`    | ✅ `tls-client::alpn-id` / `tls-server::alpn-id` |
| `NegotiatedCipherSuite`            | ⛔ Not supported. |
| `RemoteCertificate`                | ✅ `tls-client::server-identity` / `tls-server::client-identity` |
| `SslProtocol`                      | ✅ `tls-client::protocol-version` / `tls-server::protocol-version` |
| `TargetHostName`                   | ✅ `tls-client::server-name` / `tls-server::server-name` |
| `TransportContext`                 | ❔ Unknown |
| `AuthenticateAsClient`, `AuthenticateAsClientAsync`, `BeginAuthenticateAsClient`, `EndAuthenticateAsClient` | ✅ Construct `tls-client` with at least the `connected` suspension enabled, configure it (see `SslClientAuthenticationOptions` table below), call `resume`, wait for the `connected` suspension. |
| `AuthenticateAsServer`, `AuthenticateAsServerAsync`, `BeginAuthenticateAsServer`, `EndAuthenticateAsServer` | ✅ Construct `tls-server` with at least the `accepted` suspension enabled, configure it (see `SslServerAuthenticationOptions` table below), call `resume`, wait for the `accepted` suspension. For the `ServerOptionsSelectionCallback` overload, enable `client-hello` suspension (see `SslClientHelloInfo` table below). |
| `NegotiateClientCertificateAsync`  | ⛔ Not supported. |
| `Read`, `ReadAsync`, `BeginRead`, `EndRead`, `ReadByte`, `ReadAtLeast`, `ReadAtLeastAsync`, `ReadExactly`, `ReadExactlyAsync` | ✅ `private-input::read` |
| `Write`, `WriteAsync`, `BeginWrite`, `EndWrite`, `WriteByte` | ✅ `private-output::write` |
| `CopyTo`, `CopyToAsync`            | ✅ Currently implemented in user space. Could be specialized as `output-stream::splice` in case both sides are WASI streams. |
| `Flush`, `FlushAsync`              | ✅ `private-output::flush` |
| `Dispose`, `DisposeAsync`, `Close`, `Finalize`, `ShutdownAsync` | ✅ Fully flush and drop the `private-output` |
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
| `ApplicationProtocols`                | ✅ `tls-client::configure-alpn-ids` |
| `CertificateChainPolicy`              | ❔ Unknown |
| `CertificateRevocationCheckMode`      | ⚠️ Not supported. Or effectively: only `NoCheck` is supported. |
| `CipherSuitesPolicy`                  | ⚠️ Not supported. Or effectively: only `null` (== OS default) is supported. |
| `ClientCertificateContext`            | ❔ Unknown |
| `ClientCertificates`                  | ✅ `tls-client::configure-identities` |
| `EnabledSslProtocols`                 | ⚠️ Not supported. Or effectively: only `None` (== OS default) is supported. |
| `EncryptionPolicy`                    | ⚠️ (Obsolete) Not supported. Or effectively: only `RequireEncryption` is supported. |
| `LocalCertificateSelectionCallback`   | ✅ Enable `select-client-identity` suspension, while suspended call `tls-client::configure-identities`, and then `resume` |
| `RemoteCertificateValidationCallback` | ✅ Enable `verify-server-identity` suspension, perform validation and then either `resume` or abort the connection. |
| `TargetHost`                          | ✅ The `server-name` parameter of the `tls-client` constructor. |


### `SslServerAuthenticationOptions`

| Member                                | WASI equivalent |
|---------------------------------------|--|
| `AllowRenegotiation`                  | ⛔ Not supported. |
| `AllowTlsResume`                      | ⛔ Not supported. |
| `ApplicationProtocols`                | ✅ `tls-server::configure-alpn-ids` |
| `CertificateChainPolicy`              | ❔ Unknown |
| `CertificateRevocationCheckMode`      | ⚠️ Not supported. Or effectively: only `NoCheck` is supported. |
| `CipherSuitesPolicy`                  | ⚠️ Not supported. Or effectively: only `null` (== OS default) is supported. |
| `ClientCertificateRequired`           | ⛔ Not supported. |
| `EnabledSslProtocols`                 | ⚠️ Not supported. Or effectively: only `None` (== OS default) is supported. |
| `EncryptionPolicy`                    | ⚠️ (Obsolete) Not supported. Or effectively: only `RequireEncryption` is supported. |
| `RemoteCertificateValidationCallback` | ✅ Enable `verify-client-identity` suspension, perform validation and then either `resume` or abort the connection. |
| `ServerCertificate`                   | ✅ `tls-server::configure-identities` |
| `ServerCertificateContext`            | ❔ Unknown |
| `ServerCertificateSelectionCallback`  | ✅ Enable `client-hello` suspension, while suspended call `tls-server::configure-identities`, and then `resume` |


### `SslClientHelloInfo`

| Member         | WASI equivalent |
|----------------|--|
| `ServerName`   | ✅ `server-suspension::requested-server-name` |
| `SslProtocols` | ✅ `server-suspension::requested-protocol-versions` |


## Mapping to Node.js `tls` module

### APIs

| API                                | WASI equivalent |
|------------------------------------|--|
| `TLSSocket.localAddress`, `TLSSocket.localPort`, `TLSSocket.remoteAddress`, `TLSSocket.remoteFamily`, `TLSSocket.remotePort`, `TLSSocket.address`, `Server.address`, `Server.listen`, `Server: 'connection' event`, `Server.close` | ✅ These APIs can be implemented using [wasi-sockets](https://github.com/WebAssembly/wasi-sockets). The WASI TLS interface does not do any I/O. |
| `connect`, `createSecureContext`, `createSecurePair`, `createServer`, `TLSSocket.constructor` | ✅ Use the `tls-client` or `tls-server` resource. See the connection options table below for a more detailed breakdown. |
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
| `TLSSocket: 'secureConnect' event`, `Server: 'secureConnection' event` | ✅ Use the `connected` or `accepted` suspension points. |
| `TLSSocket: 'session' event`       | ⛔ Not supported. |
| `TLSSocket.alpnProtocol`           | ✅ `tls-client::alpn-id` / `tls-server::alpn-id` |
| `TLSSocket.authorizationError`     | ⚠️ See `TLSSocket.authorized`. |
| `TLSSocket.authorized`             | ⚠️ Peer certificate validation can not be disabled. So if the `tls-client::server-identity` or `tls-server::client-identity` is not null, the connection can be considered "authorized". |
| `TLSSocket.disableRenegotiation`   | ⛔ Not supported. |
| `TLSSocket.enableTrace`            | ⚠️ Technically, the raw TLS data can be captured from the `public-input/output` streams and re-parsed into whatever format Node.JS/OpenSSL wants. However, it is unlikely this is worth the effort. |
| `TLSSocket.encrypted`              | ✅ Always `true`. |
| `TLSSocket.exportKeyingMaterial`   | ⛔ Not supported. |
| `TLSSocket.getCertificate`         | ✅ `tls-client::client-identity` / `tls-server::server-identity` |
| `TLSSocket.getCipher`              | ⛔ Not supported. |
| `TLSSocket.getEphemeralKeyInfo`    | ⛔ Not supported. |
| `TLSSocket.getFinished`            | ⛔ Not supported. |
| `TLSSocket.getPeerCertificate`     | ✅ `tls-client::server-identity` / `tls-server::client-identity` |
| `TLSSocket.getPeerFinished`        | ⛔ Not supported. |
| `TLSSocket.getPeerX509Certificate` | ✅ `tls-client::server-identity` / `tls-server::client-identity` |
| `TLSSocket.getProtocol`            | ✅ `tls-client::protocol-version` / `tls-server::protocol-version` |
| `TLSSocket.getSession`             | ⛔ Not supported. Can be faked to return `undefined`. |
| `TLSSocket.getSharedSigalgs`       | ⛔ Not supported. |
| `TLSSocket.getTLSTicket`           | ⛔ Not supported. Can be faked to return `undefined`. |
| `TLSSocket.getX509Certificate`     | ✅ `tls-client::client-identity` / `tls-server::server-identity` |
| `TLSSocket.isSessionReused`        | ⛔ Not supported. Can be faked to return `false`. |
| `TLSSocket.renegotiate`            | ⛔ Not supported. |
| `TLSSocket.servername`             | ✅ `tls-client::server-name` / `tls-server::server-name` |
| `TLSSocket.setKeyCert`             | ✅ `tls-server::configure-identities` |
| `TLSSocket.setMaxSendFragment`     | ⛔ Not supported. |
| `Server: 'newSession' event`       | ⛔ Not supported. |
| `Server: 'OCSPRequest' event`      | ⛔ Not supported. |
| `Server: 'resumeSession' event`    | ⛔ Not supported. |
| `Server: 'tlsClientError' event`   | ✅ If the `tls-server` is closed prematurely (i.e.: before receiving the `accepted` event), then that's a 'tlsClientError'. |
| `Server.addContext`                | ✅ To be implemented in user space. Activate the `client-hello` hook on the `tls-server`, and upon arrival of a client hello configure the `tls-server` based on the registered contexts. |
| `Server.getTicketKeys`             | ⛔ Not supported. |
| `Server.setSecureContext`          | ✅ See `Server.addContext`. |
| `Server.setTicketKeys`             | ⛔ Not supported. |


### Connection options

| Option                 | WASI equivalent |
|------------------------|--|
| `ALPNProtocols`        | ✅ `tls-client::configure-alpn-ids` / `tls-server::configure-alpn-ids` |
| `ALPNCallback`         | ✅ Activate `client-hello` hook. Use `server-suspension::requested-server-name` & `server-suspension::requested-alpn-ids` as parameters to the callback. The return value of the callback can be passed as single item list into `tls-server::configure-alpn-ids`. |
| `SNICallback`          | ✅ Activate `client-hello` hook. Use `server-suspension::requested-server-name` as parameter to the callback. |
| `ca`                   | ⛔ Not supported. |
| `cert`, `key`, `pfx`   | ✅ `tls-client::configure-identities` / `tls-server::configure-identities` |
| `passphrase`           | ⚠️ Not applicable. Only raw private key data is accepted by `private-identity::parse`. |
| `checkServerIdentity`  | ✅ Enable `verify-server-identity` suspension, perform validation and then either `resume` or abort the connection. |
| `ciphers`              | ⛔ Not supported. |
| `clientCertEngine`     | ⛔ (Deprecated) Not supported. |
| `crl`                  | ⛔ Not supported. |
| `dhparam`              | ⛔ Not supported. |
| `ecdhCurve`            | ⛔ Not supported. |
| `enableTrace`          | ⚠️ See `TLSSocket.enableTrace` |
| `handshakeTimeout`     | ✅ Implementable in user space |
| `honorCipherOrder`     | ⛔ Not supported. |
| `isServer`             | ✅ Indicates whether a `tls-client` or `tls-server` should be constructed. |
| `key`                  | ✅ `tls-client::configure-identities` / `tls-server::configure-identities` |
| `minDHSize`            | ⛔ Not supported. |
| `minVersion`, `maxVersion`, `secureProtocol` | ⛔ Not supported. |
| `privateKeyEngine`     | ⛔ (Deprecated) Not supported. |
| `privateKeyIdentifier` | ⛔ (Deprecated) Not supported. |
| `pskCallback`          | ⛔ Not supported. |
| `pskIdentityHint`      | ⛔ Not supported. |
| `rejectUnauthorized`   | ⚠️ Not supported. Certificates are always validated. Or effectively: only `true` is supported. |
| `requestCert`          | ⛔ Not supported. |
| `requestOCSP`          | ⛔ Not supported. |
| `secureOptions`        | ⛔ Not supported. |
| `servername`           | ✅ The `server-name` parameter of the `tls-client` constructor. |
| `session`              | ⛔ Not supported. |
| `sessionIdContext`     | ⛔ Not supported. |
| `sessionTimeout`       | ⛔ Not supported. |
| `sigalgs`              | ⛔ Not supported. |
| `ticketKeys`           | ⛔ Not supported. |

