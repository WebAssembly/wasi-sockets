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
| `CertificateRevocationCheckMode`      | ⛔ Not supported. Or effectively: only `NoCheck` is supported. |
| `CipherSuitesPolicy`                  | ⛔ Not supported. Or effectively: only `null` (== OS default) is supported. |
| `ClientCertificateContext`            | ❔ Unknown |
| `ClientCertificates`                  | ✅ `tls-client::configure-identities` |
| `EnabledSslProtocols`                 | ⛔ Not supported. Or effectively: only `None` (== OS default) is supported. |
| `EncryptionPolicy`                    | ⛔ (Obsolete) Not supported. Or effectively: only `RequireEncryption` is supported. |
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
| `CertificateRevocationCheckMode`      | ⛔ Not supported. Or effectively: only `NoCheck` is supported. |
| `CipherSuitesPolicy`                  | ⛔ Not supported. Or effectively: only `null` (== OS default) is supported. |
| `ClientCertificateRequired`           | ⛔ Not supported. |
| `EnabledSslProtocols`                 | ⛔ Not supported. Or effectively: only `None` (== OS default) is supported. |
| `EncryptionPolicy`                    | ⛔ (Obsolete) Not supported. Or effectively: only `RequireEncryption` is supported. |
| `RemoteCertificateValidationCallback` | ✅ Enable `verify-client-identity` suspension, perform validation and then either `resume` or abort the connection. |
| `ServerCertificate`                   | ✅ `tls-server::configure-identities` |
| `ServerCertificateContext`            | ❔ Unknown |
| `ServerCertificateSelectionCallback`  | ✅ Enable `client-hello` suspension, while suspended call `tls-server::configure-identities`, and then `resume` |


### `SslClientHelloInfo`

| Member         | WASI equivalent |
|----------------|--|
| `ServerName`   | ✅ `server-suspension::requested-server-name` |
| `SslProtocols` | ✅ `server-suspension::requested-protocol-versions` |