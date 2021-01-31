# HTTP/2

> Hypertext Transfer Protocol Version 2 (HTTP/2) [原文链接](https://tools.ietf.org/html/rfc7540)

### 摘要

本规范描述了超文本传输​​协议（HTTP）的优化表达语义，称为HTTP第二版（HTTP/2）。 HTTP/2通过引入header字段压缩和多路复用可以更有效地利用网络资源并减少延迟感知。还引入了主动从服务器推送到客户端的表示形式。

本规范是HTTP/1.1的补充，但并不作废。 HTTP的现有语义保持不变。

<details>
<summary>原文</summary>
<pre>
<code>

Abstract

This specification describes an optimized expression of the semantics
of the Hypertext Transfer Protocol (HTTP), referred to as HTTP
version 2 (HTTP/2).  HTTP/2 enables a more efficient use of network
resources and a reduced perception of latency by introducing header
field compression and allowing multiple concurrent exchanges on the
same connection.  It also introduces unsolicited push of
representations from servers to clients.

This specification is an alternative to, but does not obsolete, the
HTTP/1.1 message syntax.  HTTP's existing semantics remain unchanged.

</code>
</pre>
</details>

### 备忘录状态

这是Internet标准跟踪文档。

本文档是Internet工程任务组（IETF）的产品。它代表了IETF社区的共识。它已经接受了公众审查，并已被Internet工程指导小组（IESG）批准发布。有关Internet标准的更多信息，请参见RFC 5741的第2节。

有关本文档当前状态，任何勘误以及如何提供反馈的信息，请访问[http://www.rfc-editor.org/info/rfc7230](http://www.rfc-editor.org/info/rfc7230)。

<details>
<summary>原文</summary>
<pre>
<code>

Status of This Memo

This is an Internet Standards Track document.

This document is a product of the Internet Engineering Task Force
(IETF).  It represents the consensus of the IETF community.  It has
received public review and has been approved for publication by the
Internet Engineering Steering Group (IESG).  Further information on
Internet Standards is available in [Section 2 of RFC 5741](https://tools.ietf.org/html/rfc5741#section-2).

Information about the current status of this document, any errata,
and how to provide feedback on it may be obtained at
http://www.rfc-editor.org/info/rfc7540.

</code>
</pre>
</details>


### 版权声明

版权所有（c）2015 IETF Trust和确定为文档作者的人员。版权所有。

本文档受[BCP 78](https://tools.ietf.org/html/bcp78)和IETF Trust关于IETF文档的法律规定（[http://trustee.ietf.org/license-info](http://trustee.ietf.org/license-info)）的约束，自本文档发布之日起生效。请仔细阅读这些文档，因为它们描述了您对本文档的权利和限制。从本文档中摘录的代码组件必须包含《信托法律条款》第4.e节中所述的BSD简化许可证文本，并且如BSD简化许可证中所述，提供的内容不附带任何保证。

<details>
<summary>原文</summary>
<pre>
<code>

Copyright Notice

Copyright (c) 2015 IETF Trust and the persons identified as the
document authors.  All rights reserved.

This document is subject to [BCP 78](https://tools.ietf.org/html/bcp78) and the IETF Trust's Legal
Provisions Relating to IETF Documents
([http://trustee.ietf.org/license-info](http://trustee.ietf.org/license-info)) in effect on the date of
publication of this document.  Please review these documents
carefully, as they describe your rights and restrictions with respect
to this document.  Code Components extracted from this document must
include Simplified BSD License text as described in Section 4.e of
the Trust Legal Provisions and are provided without warranty as
described in the Simplified BSD License.

</code>
</pre>
</details>


### 目录

.

<details>
<summary>原文</summary>
<pre>
<code>

Table of Contents

</code>
</pre>
</details>


## 1. 介绍

超文本传输​​协议（HTTP）是非常成功的协议。但是，HTTP/1.1使用基础传输的方式（[[RFC7230]，第6节](https://tools.ietf.org/html/rfc7230#section-6)）具有几个对当今的应用程序性能产生负面影响的特征。 

特别是，HTTP/1.0在给定的TCP连接上一次只允许一个未完成的请求。 HTTP/1.1添加了请求流水线处理，但这仅部分解决了请求并发问题，并且仍然受到队头阻塞的困扰。因此，需要发出许多请求的HTTP/1.0和HTTP/1.1客户端使用与服务器的多个连接以实现并发性，从而减少延迟。

此外，HTTP header字段通常是重复的和冗长的，从而导致不必要的网络流量，并导致初始TCP [[TCP](https://tools.ietf.org/html/rfc7540#ref-TCP)]拥塞窗口快速填充。当在一个新的TCP连接上进行多个请求时，这可能导致过多的延迟。

HTTP/2通过定义HTTP语义到基础连接的优化映射来解决这些问题。具体来说，它允许在同一连接上交织请求和响应消息，并对HTTP header字段使用有效的编码。它还允许对请求进行优先级排序，使更重要的请求更快地完成，从而进一步提高性能。

生成的协议对网络更友好，因为与HTTP/1.x相比，可以使用更少的TCP连接。这意味着与其他流量的竞争减少，连接寿命更长，进而可以更好地利用可用网络容量。

最后，HTTP/2还可以通过使用二进制消息帧来更有效地处理消息。


<details>
<summary>原文</summary>
<pre>
<code>

1. Introduction

The Hypertext Transfer Protocol (HTTP) is a wildly successful
protocol.  However, the way HTTP/1.1 uses the underlying transport
([[RFC7230], Section 6](https://tools.ietf.org/html/rfc7230#section-6)) has several characteristics that have a
negative overall effect on application performance today.

In particular, HTTP/1.0 allowed only one request to be outstanding at
a time on a given TCP connection.  HTTP/1.1 added request pipelining,
but this only partially addressed request concurrency and still
suffers from head-of-line blocking.  Therefore, HTTP/1.0 and HTTP/1.1
clients that need to make many requests use multiple connections to a
server in order to achieve concurrency and thereby reduce latency.

Furthermore, HTTP header fields are often repetitive and verbose,
causing unnecessary network traffic as well as causing the initial
TCP [[TCP](https://tools.ietf.org/html/rfc7540#ref-TCP)] congestion window to quickly fill.  This can result in
excessive latency when multiple requests are made on a new TCP
connection.

HTTP/2 addresses these issues by defining an optimized mapping of
HTTP's semantics to an underlying connection.  Specifically, it
allows interleaving of request and response messages on the same
connection and uses an efficient coding for HTTP header fields.  It
also allows prioritization of requests, letting more important
requests complete more quickly, further improving performance.

The resulting protocol is more friendly to the network because fewer
TCP connections can be used in comparison to HTTP/1.x.  This means
less competition with other flows and longer-lived connections, which
in turn lead to better utilization of available network capacity.

Finally, HTTP/2 also enables more efficient processing of messages
through use of binary message framing.

</code>
</pre>
</details>



## 2. HTTP/2协议概述

HTTP/2为HTTP语义提供了传输优化。HTTP/2支持HTTP/1.1的所有核心功能，但旨在通过多种方式提高效率。

HTTP/2中的基本协议单元是帧（第4.1节）。每种帧类型都有不同的用途。例如，HEADERS帧和DATA帧构成了HTTP请求和响应的基础（第8.1节）；其他帧类型（如SETTINGS，WINDOW_UPDATE和PUSH_PROMISE）用于支持其他HTTP/2功能。

通过使每个HTTP请求/响应交换与其自己的流相关联来实现请求的复用（第5节）。流在很大程度上彼此独立，因此被阻塞或停止的请求或响应不会阻止其他流的进度。

流控制和优先级确保可以有效地使用多路复用流。流控制（第5.2节）有助于确保仅传输接收机可以使用的数据。优先级（第5.3节）确保可以将有限的资源首先定向到最重要的流。

HTTP/2添加了新的交互模式，服务器可以通过该模式将响应推送到客户端（第8.2节）。服务器推送允许服务器推测性地将数据发送到服务器，服务器预期该客户端将需要，从而权衡了一些网络使用量和潜在的延迟增加。服务器通过合成请求来完成此任务，并以PUSH_PROMISE帧的形式发送。然后，服务器可以在单独的流上发送对合成请求的响应。

由于连接中使用的HTTP标头字段可能包含大量冗余数据，因此包含它们的帧将被压缩（第4.3节）。在通常情况下，这对请求大小具有特别有利的影响，允许将许多请求压缩到一个数据包中。

<details>
<summary>原文</summary>
<pre>
<code>

2.  HTTP/2 Protocol Overview

HTTP/2 provides an optimized transport for HTTP semantics.  HTTP/2
supports all of the core features of HTTP/1.1 but aims to be more
efficient in several ways.

The basic protocol unit in HTTP/2 is a frame (Section 4.1).  Each
frame type serves a different purpose.  For example, HEADERS and DATA
frames form the basis of HTTP requests and responses (Section 8.1);
other frame types like SETTINGS, WINDOW_UPDATE, and PUSH_PROMISE are
used in support of other HTTP/2 features.

Multiplexing of requests is achieved by having each HTTP request/
response exchange associated with its own stream (Section 5).
Streams are largely independent of each other, so a blocked or
stalled request or response does not prevent progress on other
streams.

Flow control and prioritization ensure that it is possible to
efficiently use multiplexed streams.  Flow control (Section 5.2)
helps to ensure that only data that can be used by a receiver is
transmitted.  Prioritization (Section 5.3) ensures that limited
resources can be directed to the most important streams first.

HTTP/2 adds a new interaction mode whereby a server can push
responses to a client (Section 8.2).  Server push allows a server to
speculatively send data to a client that the server anticipates the
client will need, trading off some network usage against a potential
latency gain.  The server does this by synthesizing a request, which
it sends as a PUSH_PROMISE frame.  The server is then able to send a
response to the synthetic request on a separate stream.

Because HTTP header fields used in a connection can contain large
amounts of redundant data, frames that contain them are compressed
(Section 4.3).  This has especially advantageous impact upon request
sizes in the common case, allowing many requests to be compressed
into one packet.


</code>
</pre>
</details>

### 2.1 文档组织

HTTP/2规范分为四个部分：

- 启用HTTP/2（第3节）介绍如何初始化HTTP/2连接。
- 帧（第4节）和流（第5节）层描述了HTTP/2帧的结构和形成多路复用流的方式。
- 帧（第6节）和错误（第7节）定义包括HTTP/2中使用的帧和错误类型的详细信息。 
- HTTP映射（第8节）和其他要求（第9节）描述了如何使用帧和流来表示HTTP语义。

尽管某些帧和流层概念与HTTP隔离，但此规范并未定义完全通用的流层。帧和流层是根据HTTP协议和服务器推送的需求量身定制的。


<details>
<summary>原文</summary>
<pre>
<code>

2.1.  Document Organization

The HTTP/2 specification is split into four parts:

o  Starting HTTP/2 (Section 3) covers how an HTTP/2 connection is
    initiated.

o  The frame (Section 4) and stream (Section 5) layers describe the
    way HTTP/2 frames are structured and formed into multiplexed
    streams.

o  Frame (Section 6) and error (Section 7) definitions include
    details of the frame and error types used in HTTP/2.

o  HTTP mappings (Section 8) and additional requirements (Section 9)
    describe how HTTP semantics are expressed using frames and
    streams.

While some of the frame and stream layer concepts are isolated from
HTTP, this specification does not define a completely generic frame
layer.  The frame and stream layers are tailored to the needs of the
HTTP protocol and server push.


</code>
</pre>
</details>


### 2.2 约定和术语

本文档中的关键字"MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL"将按照RFC 2119 [RFC2119]中的说明进行解释。

所有数值均以网络字节顺序排列。除非另有说明，否则值是无符号的。适当时以十进制或十六进制提供文字值。十六进制文字以“0x”为前缀，以区别于十进制文字。

使用以下术语：

客户端(client)：启用HTTP/2连接的端点。客户端发送HTTP请求并接收HTTP响应。

连接(connection)：两个端点之间的传输层连接。

连接错误(connection error)：影响整个HTTP/2连接的错误。

端点(point)：连接的客户端或服务器。

帧(frame)：HTTP / 2连接中的最小通信单元，由标头和根据帧类型构成的八位字节的可变长度序列组成。 

对等(peer)：在讨论特定端点时，“对等”是指远离讨论的主要主题的端点。

接收器(receiver)：正在接收帧的端点。

发送方(sender)：正在传输帧的端点。

服务器(server)：接受HTTP/2连接的端点。服务器接收HTTP请求并发送HTTP响应。

流(stream)：HTTP/2连接内的双向帧流。

流错误(stream error)：单个HTTP/2流上的错误。

最后，在[RFC7230]的第2.3节中定义了术语“网关”，“中介”，“代理”和“隧道”。中介在不同时间充当客户端和服务器。 

[RFC7230]第3.3节定义了术语“有效载荷主体”。

<details>
<summary>原文</summary>
<pre>
<code>

2.2.  Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [RFC2119].

All numeric values are in network byte order.  Values are unsigned
unless otherwise indicated.  Literal values are provided in decimal
or hexadecimal as appropriate.  Hexadecimal literals are prefixed
with "0x" to distinguish them from decimal literals.

The following terms are used:

client:  The endpoint that initiates an HTTP/2 connection.  Clients
    send HTTP requests and receive HTTP responses.

connection:  A transport-layer connection between two endpoints.

connection error:  An error that affects the entire HTTP/2
    connection.

endpoint:  Either the client or server of the connection.

frame:  The smallest unit of communication within an HTTP/2
    connection, consisting of a header and a variable-length sequence
    of octets structured according to the frame type.

peer:  An endpoint.  When discussing a particular endpoint, "peer"
    refers to the endpoint that is remote to the primary subject of
    discussion.

receiver:  An endpoint that is receiving frames.

sender:  An endpoint that is transmitting frames.

server:  The endpoint that accepts an HTTP/2 connection.  Servers
    receive HTTP requests and send HTTP responses.

stream:  A bidirectional flow of frames within the HTTP/2 connection.

stream error:  An error on the individual HTTP/2 stream.

Finally, the terms "gateway", "intermediary", "proxy", and "tunnel"
are defined in Section 2.3 of [RFC7230].  Intermediaries act as both
client and server at different times.

The term "payload body" is defined in Section 3.3 of [RFC7230].

</code>
</pre>
</details>

## 3. 启用HTTP/2

HTTP/2连接是在TCP连接（[TCP]）之上运行的应用层协议。客户端是TCP连接启用器。

HTTP/2使用与HTTP / 1.1相同的“http”和“https”URI方案。HTTP/2共享相同的默认端口号：“http”URI为80，“https”URI为443。结果，需要处理诸如“http://example.org/foo”或“https://example.com/bar”之类的对目标资源URI的请求的实现，以便首先发现上游服务器（客户端希望建立连接）支持HTTP/2。

“http”和“https”URI对HTTP/2的支持是不同的。3.2节中介绍了“http”URI的发现。第3.3节介绍了“https”URI的发现。

<details>
<summary>原文</summary>
<pre>
<code>

3.  Starting HTTP/2

An HTTP/2 connection is an application-layer protocol running on top
of a TCP connection ([TCP]).  The client is the TCP connection
initiator.

HTTP/2 uses the same "http" and "https" URI schemes used by HTTP/1.1.
HTTP/2 shares the same default port numbers: 80 for "http" URIs and
443 for "https" URIs.  As a result, implementations processing
requests for target resource URIs like "http://example.org/foo" or
"https://example.com/bar" are required to first discover whether the
upstream server (the immediate peer to which the client wishes to
establish a connection) supports HTTP/2.

The means by which support for HTTP/2 is determined is different for
"http" and "https" URIs.  Discovery for "http" URIs is described in
Section 3.2.  Discovery for "https" URIs is described in Section 3.3.

</code>
</pre>
</details>

### 3.1 HTTP/2版本标识

本文档中定义的协议具有两个标识符。

- 字符串“h2”标识HTTP/2使用传输层安全（TLS）[TLS12]。该标识符用于TLS应用程序层协议协商（ALPN）扩展[TLS-ALPN]字段中，以及标识TLS上的HTTP/2的任何地方。

  “h2”字符串被序列化为一个ALPN协议标识符，为两个八位字节序列：0x68、0x32。

- 字符串“h2c”标识HTTP/2在明文TCP上运行的协议。此标识符用于HTTP/1.1升级标头字段中，以及在标识HTTP/2 over TCP的任何地方。
  
  “h2c”字符串是从ALPN标识符空间保留的，但是描述了不使用TLS的协议。

协商“h2”或“h2c”意味着使用本文档中描述的传输、安全性、成帧和消息语义。

<details>
<summary>原文</summary>
<pre>
<code>

3.1.  HTTP/2 Version Identification

The protocol defined in this document has two identifiers.

o  The string "h2" identifies the protocol where HTTP/2 uses
    Transport Layer Security (TLS) [TLS12].  This identifier is used
    in the TLS application-layer protocol negotiation (ALPN) extension
    [TLS-ALPN] field and in any place where HTTP/2 over TLS is
    identified.

    The "h2" string is serialized into an ALPN protocol identifier as
    the two-octet sequence: 0x68, 0x32.

o  The string "h2c" identifies the protocol where HTTP/2 is run over
    cleartext TCP.  This identifier is used in the HTTP/1.1 Upgrade
    header field and in any place where HTTP/2 over TCP is identified.

    The "h2c" string is reserved from the ALPN identifier space but
    describes a protocol that does not use TLS.

Negotiating "h2" or "h2c" implies the use of the transport, security,
framing, and message semantics described in this document.

</code>
</pre>
</details>

### 3.2 使用"http"URI启用HTTP/2

客户端请求“http”URI时，如果不具有有关下一跳对HTTP/2支持的先验知识，则使用HTTP升级机制（[RFC7230]的6.7节）。客户端通过发出HTTP/1.1请求来做到这一点，该请求包括带有“h2c”令牌的Upgrade标头字段。这样的HTTP/1.1请求务必包含一个HTTP2-Settings（第3.2.1节）header字段。

例如：

```
GET / HTTP/1.1
Host: server.example.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: <base64url encoding of HTTP/2 SETTINGS payload>
```

在客户端可以发送HTTP/2帧之前，必须完整发送包含有效内容主体的请求。这意味着较大的请求可能会阻止连接的使用，直到完全发送为止。

如果初始请求与后续请求的并发性很重要，则可以使用OPTIONS请求执行到HTTP/2的升级，但要付出额外的往返消耗。

不支持HTTP/2的服务器可以响应该请求，就像缺少升级header字段一样：

```
HTTP/1.1 200 OK
Content-Length: 243
Content-Type: text/html

...
```

服务器必须忽略升级头字段中的“h2”令牌。带有“h2”的令牌的存在意味着基于TLS的HTTP/2，而是按照3.3节中的说明进行协商。

支持HTTP/2的服务器以`101 (Switching Protocols) `响应接受升级。在空行终止101响应之后，服务器可以开始发送HTTP/2帧。这些帧必须包括对发起升级请求的响应。

例如：

```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: h2c

[ HTTP/2 connection ...
```

服务器发送的第一个HTTP/2帧必须是一个由SETTINGS帧（第6.5节）组成的服务器连接前言（第3.5节）。收到101响应后，客户端必须发送一个包括一个SETTINGS帧的连接前言（第3.5节），

在升级之前发送的HTTP/1.1请求被分配了具有默认优先级值（第5.3.5节）的流标识符1（请参阅第5.1.1节）。由于请求是作为HTTP/1.1请求完成的，因此流1是从客户端到服务器的隐式“半封闭”（请参阅​​第5.1节）。开始HTTP/2连接后，流1用于响应。

<details>
<summary>原文</summary>
<pre>
<code>

3.2.  Starting HTTP/2 for "http" URIs

A client that makes a request for an "http" URI without prior
knowledge about support for HTTP/2 on the next hop uses the HTTP
Upgrade mechanism (Section 6.7 of [RFC7230]).  The client does so by
making an HTTP/1.1 request that includes an Upgrade header field with
the "h2c" token.  Such an HTTP/1.1 request MUST include exactly one
HTTP2-Settings (Section 3.2.1) header field.

For example:

    GET / HTTP/1.1
    Host: server.example.com
    Connection: Upgrade, HTTP2-Settings
    Upgrade: h2c
    HTTP2-Settings: <base64url encoding of HTTP/2 SETTINGS payload>

Requests that contain a payload body MUST be sent in their entirety
before the client can send HTTP/2 frames.  This means that a large
request can block the use of the connection until it is completely
sent.

If concurrency of an initial request with subsequent requests is
important, an OPTIONS request can be used to perform the upgrade to
HTTP/2, at the cost of an additional round trip.

A server that does not support HTTP/2 can respond to the request as
though the Upgrade header field were absent:

    HTTP/1.1 200 OK
    Content-Length: 243
    Content-Type: text/html

    ...

A server MUST ignore an "h2" token in an Upgrade header field.
Presence of a token with "h2" implies HTTP/2 over TLS, which is
instead negotiated as described in Section 3.3.

A server that supports HTTP/2 accepts the upgrade with a 101
(Switching Protocols) response.  After the empty line that terminates
the 101 response, the server can begin sending HTTP/2 frames.  These
frames MUST include a response to the request that initiated the
upgrade.

For example:

    HTTP/1.1 101 Switching Protocols
    Connection: Upgrade
    Upgrade: h2c

    [ HTTP/2 connection ...

The first HTTP/2 frame sent by the server MUST be a server connection
preface (Section 3.5) consisting of a SETTINGS frame (Section 6.5).
Upon receiving the 101 response, the client MUST send a connection
preface (Section 3.5), which includes a SETTINGS frame.

The HTTP/1.1 request that is sent prior to upgrade is assigned a
stream identifier of 1 (see Section 5.1.1) with default priority
values (Section 5.3.5).  Stream 1 is implicitly "half-closed" from
the client toward the server (see Section 5.1), since the request is
completed as an HTTP/1.1 request.  After commencing the HTTP/2
connection, stream 1 is used for the response.

</code>
</pre>
</details>

### 3.2.1 HTTP2-Settings 头字段

从HTTP/1.1升级到HTTP/2的请求务必包含一个“HTTP2-Settings”头字段。HTTP2-Settings头字段是特定于连接的头字段，其中包含控制HTTP/2连接的参数，这些参数是在服务器接受升级请求的前提下提供的。

```
HTTP2-Settings    = token68
```

如果此标头字段不存在或存在多个，则服务器不得将连接升级到HTTP/2。服务器不得发送此头字段。

HTTP2-Settings头字段的内容是SETTINGS帧的有效负载（第6.5节），编码为base64url字符串（即[RFC4648]第5节中描述的URL和文件名安全的Base64编码，包括末尾的'='字符被省略）[token68]的ABNF[RFC5234]生成在[RFC7235]的2.1节中定义。

由于升级仅适用于直接连接，因此发送HTTP2-Settings头字段的客户端还必须在Connection头字段中发送“HTTP2-Settings”作为连接选项以防止转发（参见第6.1节[RFC7230]。

服务器将对这些值进行解码和解释，就像处理其他任何SETTINGS帧一样。不需要显式确认这些设置（第6.5.3节），因为101响应用作隐式确认。在升级请求中提供这些值将使客户端有机会在从服务器接收任何帧之前提供参数。

<details>
<summary>原文</summary>
<pre>
<code>

3.2.1.  HTTP2-Settings Header Field

A request that upgrades from HTTP/1.1 to HTTP/2 MUST include exactly
one "HTTP2-Settings" header field.  The HTTP2-Settings header field
is a connection-specific header field that includes parameters that
govern the HTTP/2 connection, provided in anticipation of the server
accepting the request to upgrade.

    HTTP2-Settings    = token68

A server MUST NOT upgrade the connection to HTTP/2 if this header
field is not present or if more than one is present.  A server MUST
NOT send this header field.

The content of the HTTP2-Settings header field is the payload of a
SETTINGS frame (Section 6.5), encoded as a base64url string (that is,
the URL- and filename-safe Base64 encoding described in Section 5 of
[RFC4648], with any trailing '=' characters omitted).  The ABNF
[RFC5234] production for "token68" is defined in Section 2.1 of
[RFC7235].

Since the upgrade is only intended to apply to the immediate
connection, a client sending the HTTP2-Settings header field MUST
also send "HTTP2-Settings" as a connection option in the Connection
header field to prevent it from being forwarded (see Section 6.1 of
[RFC7230]).

A server decodes and interprets these values as it would any other
SETTINGS frame.  Explicit acknowledgement of these settings
(Section 6.5.3) is not necessary, since a 101 response serves as
implicit acknowledgement.  Providing these values in the upgrade
request gives a client an opportunity to provide parameters prior to
receiving any frames from the server.

</code>
</pre>
</details>

### 3.3 使用"https"URI启用HTTP/2

向“https”URI发出请求的客户端使用带有应用程序层协议协商（ALPN）扩展名[TLS-ALPN]的TLS [TLS12]。

TLS上的HTTP/2使用“h2”协议标识符。“h2c”协议标识符不得由客户端发送或由服务器选择；“h2c”协议标识符描述了不使用TLS的协议。

TLS协商完成后，客户端和服务器都必须发送连接序言（第3.5节）。

<details>
<summary>原文</summary>
<pre>
<code>

3.3.  Starting HTTP/2 for "https" URIs

A client that makes a request to an "https" URI uses TLS [TLS12] with
the application-layer protocol negotiation (ALPN) extension
[TLS-ALPN].

HTTP/2 over TLS uses the "h2" protocol identifier.  The "h2c"
protocol identifier MUST NOT be sent by a client or selected by a
server; the "h2c" protocol identifier describes a protocol that does
not use TLS.

Once TLS negotiation is complete, both the client and the server MUST
send a connection preface (Section 3.5).

</code>
</pre>
</details>

### 3.4 先知情况下启用HTTP/2

客户端可以通过其他方式得知特定服务器支持HTTP/2。例如，[ALT-SVC]描述了一种用于宣传此功能的机制。

客户端可以通过其他方式得知特定服务器支持HTTP/2。例如，[ALT-SVC]描述了一种用于宣传此功能的机制。

客户端必须发送连接前言（第3.5节），然后可以立即向该服务器发送HTTP/2帧；服务器可以通过存在连接前言来识别这些连接。这仅影响通过明文TCP的HTTP/2连接的建立。在TLS上支持HTTP/2的实现必须在TLS [TLS-ALPN]中使用协议协商。

同样，服务器必须发送连接前言（第3.5节）。

如果没有其他信息，先前对HTTP/2的支持并不是一个强信号，即给定的服务器将为将来的连接支持HTTP/2。例如，服务器配置可能会更改，集群服务器中实例之间的配置可能会更改，或者网络条件可能会更改。

<details>
<summary>原文</summary>
<pre>
<code>

3.4.  Starting HTTP/2 with Prior Knowledge

A client can learn that a particular server supports HTTP/2 by other
means.  For example, [ALT-SVC] describes a mechanism for advertising
this capability.

A client MUST send the connection preface (Section 3.5) and then MAY
immediately send HTTP/2 frames to such a server; servers can identify
these connections by the presence of the connection preface.  This
only affects the establishment of HTTP/2 connections over cleartext
TCP; implementations that support HTTP/2 over TLS MUST use protocol
negotiation in TLS [TLS-ALPN].

Likewise, the server MUST send a connection preface (Section 3.5).

Without additional information, prior support for HTTP/2 is not a
strong signal that a given server will support HTTP/2 for future
connections.  For example, it is possible for server configurations
to change, for configurations to differ between instances in
clustered servers, or for network conditions to change.

</code>
</pre>
</details>

### 3.5。HTTP/2连接序言

在HTTP/2中，要求每个端点发送一个连接序言作为对所使用协议的最终确认，并为HTTP/2连接建立初始设置。客户端和服务器各自发送不同的连接序言。

客户端连接序言以24个八位位组的序列开头，十六进制表示为：

```
0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a
```

即，连接序言以字符串"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"开头。这个序列之后必须是一个SETTINGS帧（第6.5节），该帧可以为空。客户端在收到101(Switching Protocols)响应（表示升级成功）或作为TLS连接的第一个应用程序数据八位字节后立即发送客户端连接序言。如果使用服务器对协议的先知开始HTTP/2连接，则在建立连接时发送客户端连接序言。

注意：选择客户端连接前言是为了使大部分HTTP/1.1或HTTP/1.0服务器和中介都不会尝试处理其他帧。请注意，这不能解决在[通话]中提出的问题。

服务器连接序言由可能为空的SETTINGS帧（第6.5节）组成，该帧必须是服务器在HTTP/2连接中发送的第一帧。

发送连接序言后，必须确认从对等方收到的作为连接序言一部分的SETTINGS帧（请参阅第6.5.3节）。

为了避免不必要的延迟，允许客户端在发送客户端连接序言之后立即向服务器发送其他帧，而不必等待接收服务器连接序言。但是，请务必注意，服务器连接前言SETTINGS帧可能包含一些参数，这些参数必定会更改期望客户端与服务器通信的方式。在接收到SETTINGS帧后，客户端应遵守所有已建立的参数。在某些配置中，服务器有可能在客户端发送其他帧之前传输设置，从而提供了避免此问题的机会。

客户端和服务器必须将无效的连接前言视为PROTOCOL_ERROR类型的连接错误（第5.4.1节）。在这种情况下，可以忽略GOAWAY帧（第6.8节），因为无效的前言表示对等方未使用HTTP/2。

<details>
<summary>原文</summary>
<pre>
<code>

3.5.  HTTP/2 Connection Preface

In HTTP/2, each endpoint is required to send a connection preface as
a final confirmation of the protocol in use and to establish the
initial settings for the HTTP/2 connection.  The client and server
each send a different connection preface.

The client connection preface starts with a sequence of 24 octets,
which in hex notation is:

    0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a

That is, the connection preface starts with the string "PRI *
HTTP/2.0\r\n\r\nSM\r\n\r\n").  This sequence MUST be followed by a
SETTINGS frame (Section 6.5), which MAY be empty.  The client sends
the client connection preface immediately upon receipt of a 101
(Switching Protocols) response (indicating a successful upgrade) or
as the first application data octets of a TLS connection.  If
starting an HTTP/2 connection with prior knowledge of server support
for the protocol, the client connection preface is sent upon
connection establishment.

    Note: The client connection preface is selected so that a large
    proportion of HTTP/1.1 or HTTP/1.0 servers and intermediaries do
    not attempt to process further frames.  Note that this does not
    address the concerns raised in [TALKING].

The server connection preface consists of a potentially empty
SETTINGS frame (Section 6.5) that MUST be the first frame the server
sends in the HTTP/2 connection.

The SETTINGS frames received from a peer as part of the connection
preface MUST be acknowledged (see Section 6.5.3) after sending the
connection preface.

To avoid unnecessary latency, clients are permitted to send
additional frames to the server immediately after sending the client
connection preface, without waiting to receive the server connection
preface.  It is important to note, however, that the server
connection preface SETTINGS frame might include parameters that
necessarily alter how a client is expected to communicate with the
server.  Upon receiving the SETTINGS frame, the client is expected to
honor any parameters established.  In some configurations, it is
possible for the server to transmit SETTINGS before the client sends
additional frames, providing an opportunity to avoid this issue.

Clients and servers MUST treat an invalid connection preface as a
connection error (Section 5.4.1) of type PROTOCOL_ERROR.  A GOAWAY
frame (Section 6.8) MAY be omitted in this case, since an invalid
preface indicates that the peer is not using HTTP/2.

</code>
</pre>
</details>
