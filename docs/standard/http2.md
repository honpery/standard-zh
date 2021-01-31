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

1. Introduction ....................................................4
2. HTTP/2 Protocol Overview ........................................5
    2.1. Document Organization ......................................6
    2.2. Conventions and Terminology ................................6
3. Starting HTTP/2 .................................................7
    3.1. HTTP/2 Version Identification ..............................8
    3.2. Starting HTTP/2 for "http" URIs ............................8
        3.2.1. HTTP2-Settings Header Field .........................9
    3.3. Starting HTTP/2 for "https" URIs ..........................10
    3.4. Starting HTTP/2 with Prior Knowledge ......................10
    3.5. HTTP/2 Connection Preface .................................11
4. HTTP Frames ....................................................12
    4.1. Frame Format ..............................................12
    4.2. Frame Size ................................................13
    4.3. Header Compression and Decompression ......................14
5. Streams and Multiplexing .......................................15
    5.1. Stream States .............................................16
        5.1.1. Stream Identifiers .................................21
        5.1.2. Stream Concurrency .................................22
    5.2. Flow Control ..............................................22
        5.2.1. Flow-Control Principles ............................23
        5.2.2. Appropriate Use of Flow Control ....................24
    5.3. Stream Priority ...........................................24
        5.3.1. Stream Dependencies ................................25
        5.3.2. Dependency Weighting ...............................26
        5.3.3. Reprioritization ...................................26
        5.3.4. Prioritization State Management ....................27
        5.3.5. Default Priorities .................................28
    5.4. Error Handling ............................................28
        5.4.1. Connection Error Handling ..........................29
        5.4.2. Stream Error Handling ..............................29
        5.4.3. Connection Termination .............................30
    5.5. Extending HTTP/2 ..........................................30
6. Frame Definitions ..............................................31
    6.1. DATA ......................................................31
    6.2. HEADERS ...................................................32
    6.3. PRIORITY ..................................................34
    6.4. RST_STREAM ................................................36
    6.5. SETTINGS ..................................................36
        6.5.1. SETTINGS Format ....................................38
        6.5.2. Defined SETTINGS Parameters ........................38
        6.5.3. Settings Synchronization ...........................39
    6.6. PUSH_PROMISE ..............................................40
    6.7. PING ......................................................42
    6.8. GOAWAY ....................................................43
    6.9. WINDOW_UPDATE .............................................46
        6.9.1. The Flow-Control Window ............................47
        6.9.2. Initial Flow-Control Window Size ...................48
        6.9.3. Reducing the Stream Window Size ....................49
    6.10. CONTINUATION .............................................49
7. Error Codes ....................................................50
8. HTTP Message Exchanges .........................................51
    8.1. HTTP Request/Response Exchange ............................52
        8.1.1. Upgrading from HTTP/2 ..............................53
        8.1.2. HTTP Header Fields .................................53
        8.1.3. Examples ...........................................57
        8.1.4. Request Reliability Mechanisms in HTTP/2 ...........60
    8.2. Server Push ...............................................60
        8.2.1. Push Requests ......................................61
        8.2.2. Push Responses .....................................63
    8.3. The CONNECT Method ........................................64
9. Additional HTTP Requirements/Considerations ....................65
    9.1. Connection Management .....................................65
        9.1.1. Connection Reuse ...................................66
        9.1.2. The 421 (Misdirected Request) Status Code ..........66
    9.2. Use of TLS Features .......................................67
        9.2.1. TLS 1.2 Features ...................................67
        9.2.2. TLS 1.2 Cipher Suites ..............................68
10. Security Considerations .......................................69
    10.1. Server Authority .........................................69
    10.2. Cross-Protocol Attacks ...................................69
    10.3. Intermediary Encapsulation Attacks .......................70
    10.4. Cacheability of Pushed Responses .........................70
    10.5. Denial-of-Service Considerations .........................70
        10.5.1. Limits on Header Block Size .......................71
        10.5.2. CONNECT Issues ....................................72
    10.6. Use of Compression .......................................72
    10.7. Use of Padding ...........................................73
    10.8. Privacy Considerations ...................................73
11. IANA Considerations ...........................................74
    11.1. Registration of HTTP/2 Identification Strings ............74
    11.2. Frame Type Registry ......................................75
    11.3. Settings Registry ........................................75
    11.4. Error Code Registry ......................................76
    11.5. HTTP2-Settings Header Field Registration .................77
    11.6. PRI Method Registration ..................................78
    11.7. The 421 (Misdirected Request) HTTP Status Code ...........78
    11.8. The h2c Upgrade Token ....................................78
12. References ....................................................79
    12.1. Normative References .....................................79
    12.2. Informative References ...................................81
Appendix A. TLS 1.2 Cipher Suite Black List .......................83
Acknowledgements ..................................................95
Authors' Addresses ................................................96

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

#### 3.2.1 HTTP2-Settings 头字段

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

### 3.5 HTTP/2连接序言

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

## 4. HTTP帧

一旦HTTP / 2连接建立，端点就可以开始交换帧。

<details>
<summary>原文</summary>
<pre>
<code>

4.  HTTP Frames

Once the HTTP/2 connection is established, endpoints can begin
exchanging frames.

</code>
</pre>
</details>

### 4.1 帧格式

所有帧均以固定的9字节首部开头，后跟可变长度的有效载荷。

```
+-----------------------------------------------+
|                 Length (24)                   |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (31)                      |
+=+=============================================================+
|                   Frame Payload (0...)                      ...
+---------------------------------------------------------------+

                        Figure 1: Frame Layout
```

帧头的字段定义为：

- 长度(Length)：帧有效载荷的长度，表示为无符号的24位整数。除非接收者为SETTINGS_MAX_FRAME_SIZE设置了更大的值，否则不得发送大于2^14（16,384）的值。

  帧头的9个八位位组不包含在该值中。
- 类型(Type)：帧的8位类型。帧类型决定了框架的格式和语义。实现必须忽略并丢弃任何类型未知的帧。

- 标志(Flags)：一个8位字段，为特定于帧类型的布尔标志保留。
  
  为标志分配特定于所指示帧类型的语义。对于特定帧类型，没有定义语义的标记必须被忽略，并且在发送时必须置为未设置（0x0）。

- R：保留的1位字段。该位的语义是不确定的，发送时该位必须保持未设置状态（0x0），而接收时该位必须忽略。

- 流标识符(Stream Identifier)：流标识符（请参阅第5.1.1节），表示为无符号的31位整数。值0x0保留给与整个连接（而不是单个流）相关联的帧。

帧有效负载的结构和内容完全取决于帧类型。

<details>
<summary>原文</summary>
<pre>
<code>

4.1.  Frame Format

All frames begin with a fixed 9-octet header followed by a variable-
length payload.

+-----------------------------------------------+
|                 Length (24)                   |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (31)                      |
+=+=============================================================+
|                   Frame Payload (0...)                      ...
+---------------------------------------------------------------+

                        Figure 1: Frame Layout

The fields of the frame header are defined as:

Length:  The length of the frame payload expressed as an unsigned
    24-bit integer.  Values greater than 2^14 (16,384) MUST NOT be
    sent unless the receiver has set a larger value for
    SETTINGS_MAX_FRAME_SIZE.

    The 9 octets of the frame header are not included in this value.

Type:  The 8-bit type of the frame.  The frame type determines the
    format and semantics of the frame.  Implementations MUST ignore
    and discard any frame that has a type that is unknown.

Flags:  An 8-bit field reserved for boolean flags specific to the
    frame type.

    Flags are assigned semantics specific to the indicated frame type.
    Flags that have no defined semantics for a particular frame type
    MUST be ignored and MUST be left unset (0x0) when sending.

R: A reserved 1-bit field.  The semantics of this bit are undefined,
    and the bit MUST remain unset (0x0) when sending and MUST be
    ignored when receiving.

Stream Identifier:  A stream identifier (see Section 5.1.1) expressed
    as an unsigned 31-bit integer.  The value 0x0 is reserved for
    frames that are associated with the connection as a whole as
    opposed to an individual stream.

The structure and content of the frame payload is dependent entirely
on the frame type.

</code>
</pre>
</details>

### 4.2 帧大小

帧有效负载的大小受接收者在SETTINGS_MAX_FRAME_SIZE设置中发布的最大大小限制。此设置的值可以介于2^14（16,384）和2^24-1（16,777,215）个八位字节之间（包括两端）。

所有实现都必须能够接收和最小处理长度最大为2^14个八位字节的帧，以及9个八位字节的帧头（第4.1节）。说明帧大小时，不包括帧头的大小。

注：某些帧类型（例如PING（第6.7节））对允许的有效载荷数据量施加了其他限制。

如果帧超出了帧头的大小，则端点必须发送错误代码FRAME_SIZE_ERROR。在SETTINGS_MAX_FRAME_SIZE中定义的大小，超出为帧类型定义的任何限制，或者太小而无法包含必需的帧数据。可能会改变整个连接状态的帧中的帧大小错误必须视为连接错误（第5.4.1节）；这包括任何带有标题块（第4.3节）（即HEADERS，PUSH_PROMISE和CONTINUATION），SETTINGS的帧，以及流标识符为0的任何帧。

端点没有义务使用帧中的所有可用空间。通过使用小于允许的最大尺寸的框架进行了改进。发送大帧会导致延迟时间敏感帧（例如RST_STREAM，WINDOW_UPDATE或PRIORITY），如果发送大帧会阻止它们，则可能会影响性能。

<details>
<summary>原文</summary>
<pre>
<code>

4.2.  Frame Size

The size of a frame payload is limited by the maximum size that a
receiver advertises in the SETTINGS_MAX_FRAME_SIZE setting.  This
setting can have any value between 2^14 (16,384) and 2^24-1
(16,777,215) octets, inclusive.

All implementations MUST be capable of receiving and minimally
processing frames up to 2^14 octets in length, plus the 9-octet frame
header (Section 4.1).  The size of the frame header is not included
when describing frame sizes.

    Note: Certain frame types, such as PING (Section 6.7), impose
    additional limits on the amount of payload data allowed.

An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame
exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any
limit defined for the frame type, or is too small to contain
mandatory frame data.  A frame size error in a frame that could alter
the state of the entire connection MUST be treated as a connection
error (Section 5.4.1); this includes any frame carrying a header
block (Section 4.3) (that is, HEADERS, PUSH_PROMISE, and
CONTINUATION), SETTINGS, and any frame with a stream identifier of 0.

Endpoints are not obligated to use all available space in a frame.
Responsiveness can be improved by using frames that are smaller than
the permitted maximum size.  Sending large frames can result in
delays in sending time-sensitive frames (such as RST_STREAM,
WINDOW_UPDATE, or PRIORITY), which, if blocked by the transmission of
a large frame, could affect performance.

</code>
</pre>
</details>

### 4.3 头部压缩和解压缩

与HTTP/1中一样，HTTP/2中的头字段是具有一个或多个关联值的名称。头字段用于HTTP请求和响应消息以及服务器推送操作中（请参见8.2节）。

标头列表是零个或多个标头字段的集合。通过连接传输时，头文件列表会使用HTTP头文件压缩[COMPRESSION]序列化到前面的块中。然后将这些序列化的报头块划分为一个或多个八位字节序列，称为报头块片段，并在HEADERS（第6.2节），PUSH_PROMISE（第6.6节）或CONTINUATION（第6.10节）帧的有效载荷内传输。

处理Cookie头字段[COOKIE]特别是通过HTTPmapping（请参阅第8.1.2.5节）。

接收端点通过连接其片段重新组合头块，然后解压缩该块以重建头列表。

完整的头块由以下组成：

- 单个HEADERS或PUSH_PROMISE帧以及END_HEADERS标志集。

- 或者清除了ENDERS标记的HEADERS或PUSH_PROMISE帧以及一个或多个CONTINUATION帧，其中最后一个CONTINUATION帧设置了END_HEADERS标记。

标头压缩是有状态的。一个压缩上下文和一个解压缩上下文用于整个连接。头块中的解码错误必须被视为COMPRESSION_ERROR类型的连接错误（第5.4.1节），

每个头块都作为离散单元处理。报头块必须作为连续的帧序列发送，没有任何其他类型的交错帧或来自任何其他流的帧。 HEADERS或CONTINUATION帧序列中的最后一个帧设置了END_HEADERS标志。 PUSH_PROMISEor CONTINUATION帧序列中的最后一个帧设置了END_HEADERS标志。这使得前导块在逻辑上等效于单个帧。

头块片段只能作为HEADERS，PUSH_PROMISE或CONTINUATION帧的有效负载发送，因为这些帧承载的数据可以修改接收机维护的压缩上下文。接收HEADERS，PUSH_PROMISE或CONTINUATION帧的端点需要重新组合头块并执行解压缩，即使要丢弃这些帧也是如此。如果接收方未解压缩头块，则必须以COMPRESSION_ERROR类型的连接错误（第5.4.1节）终止连接。

<details>
<summary>原文</summary>
<pre>
<code>

4.3.  Header Compression and Decompression

Just as in HTTP/1, a header field in HTTP/2 is a name with one or
more associated values.  Header fields are used within HTTP request
and response messages as well as in server push operations (see
Section 8.2).

Header lists are collections of zero or more header fields.  When
transmitted over a connection, a header list is serialized into a
header block using HTTP header compression [COMPRESSION].  The
serialized header block is then divided into one or more octet
sequences, called header block fragments, and transmitted within the
payload of HEADERS (Section 6.2), PUSH_PROMISE (Section 6.6), or
CONTINUATION (Section 6.10) frames.

The Cookie header field [COOKIE] is treated specially by the HTTP
mapping (see Section 8.1.2.5).

A receiving endpoint reassembles the header block by concatenating
its fragments and then decompresses the block to reconstruct the
header list.

A complete header block consists of either:

o  a single HEADERS or PUSH_PROMISE frame, with the END_HEADERS flag
    set, or

o  a HEADERS or PUSH_PROMISE frame with the END_HEADERS flag cleared
    and one or more CONTINUATION frames, where the last CONTINUATION
    frame has the END_HEADERS flag set.

Header compression is stateful.  One compression context and one
decompression context are used for the entire connection.  A decoding
error in a header block MUST be treated as a connection error
(Section 5.4.1) of type COMPRESSION_ERROR.

Each header block is processed as a discrete unit.  Header blocks
MUST be transmitted as a contiguous sequence of frames, with no
interleaved frames of any other type or from any other stream.  The
last frame in a sequence of HEADERS or CONTINUATION frames has the
END_HEADERS flag set.  The last frame in a sequence of PUSH_PROMISE
or CONTINUATION frames has the END_HEADERS flag set.  This allows a
header block to be logically equivalent to a single frame.

Header block fragments can only be sent as the payload of HEADERS,
PUSH_PROMISE, or CONTINUATION frames because these frames carry data
that can modify the compression context maintained by a receiver.  An
endpoint receiving HEADERS, PUSH_PROMISE, or CONTINUATION frames
needs to reassemble header blocks and perform decompression even if
the frames are to be discarded.  A receiver MUST terminate the
connection with a connection error (Section 5.4.1) of type
COMPRESSION_ERROR if it does not decompress a header block.

</code>
</pre>
</details>

# 5. 流和多路复用

`流(stream)`是HTTP/2连接中客户端和服务器之间交换的独立的双向帧序列。

流具有几个重要的特征：

- 单个HTTP/2连接可以包含多个并发打开的流，其中任一端点都可以交错多个流中的帧。

- 流可以被单方面建立和使用，也可以由客户端或服务器共享。 

- 任一端点均可关闭流。 

- 在流上发送帧的顺序很重要。接受者按接收顺序处理帧。特别是，`HEADERS`和`DATA`帧的顺序在语义上很重要。 

- 流由整数标识。通过端点启动流，将流标识符分配给流。

<details>
<summary>原文</summary>
<pre>
<code>

5.  Streams and Multiplexing

A "stream" is an independent, bidirectional sequence of frames
exchanged between the client and server within an HTTP/2 connection.
Streams have several important characteristics:

o  A single HTTP/2 connection can contain multiple concurrently open
    streams, with either endpoint interleaving frames from multiple
    streams.

o  Streams can be established and used unilaterally or shared by
    either the client or server.

o  Streams can be closed by either endpoint.

o  The order in which frames are sent on a stream is significant.
    Recipients process frames in the order they are received.  In
    particular, the order of HEADERS and DATA frames is semantically
    significant.

o  Streams are identified by an integer.  Stream identifiers are
    assigned to streams by the endpoint initiating the stream.

</code>
</pre>
</details>


### 5.1 流状态

流的生命周期如图2所示。

```
                                +--------+
                        send PP |        | recv PP
                       ,--------|  idle  |--------.
                      /         |        |         \
                     v          +--------+          v
              +----------+          |           +----------+
              |          |          | send H /  |          |
       ,------| reserved |          | recv H    | reserved |------.
       |      | (local)  |          |           | (remote) |      |
       |      +----------+          v           +----------+      |
       |          |             +--------+             |          |
       |          |     recv ES |        | send ES     |          |
       |   send H |     ,-------|  open  |-------.     | recv H   |
       |          |    /        |        |        \    |          |
       |          v   v         +--------+         v   v          |
       |      +----------+          |           +----------+      |
       |      |   half   |          |           |   half   |      |
       |      |  closed  |          | send R /  |  closed  |      |
       |      | (remote) |          | recv R    | (local)  |      |
       |      +----------+          |           +----------+      |
       |           |                |                 |           |
       |           | send ES /      |       recv ES / |           |
       |           | send R /       v        send R / |           |
       |           | recv R     +--------+   recv R   |           |
       | send R /  `----------->|        |<-----------'  send R / |
       | recv R                 | closed |               recv R   |
       `----------------------->|        |<----------------------'
                                +--------+

          send:   endpoint sends this frame
          recv:   endpoint receives this frame

          H:  HEADERS frame (with implied CONTINUATIONs)
          PP: PUSH_PROMISE frame (with implied CONTINUATIONs)
          ES: END_STREAM flag
          R:  RST_STREAM frame

                          Figure 2: Stream States

```

请注意，此图显示了流状态转换以及仅影响这些转换的帧和标志。在这方面，`CONTINUATION`帧不会导致状态转换。它们实际上是它们遵循的`HEADERS`或`PUSH_PROMISE`的一部分。

为了进行状态转换，将`END_STREAM`标志作为对其承载帧的单独事件进行处理。设置了`END_STREAM`标志的`HEADERS`帧可能导致两个状态转换。

两个端点都具有流状态的主观视图，当传输帧时，状态可能会有所不同。端点不协调流的创建；它们是由任一端点单方面创建的。状态不匹配的负面影响仅限于发送`RST_STREAM`之后的“关闭”状态，其中在关闭后的一段时间内可能会接收到帧。

流具有以下状态：

- idle(空闲)：
  
  所有流均以`idle`状态开始。
  
  从此状态开始，以下转换有效：

<details>
<summary>原文</summary>
<pre>
<code>

5.1.  Stream States

The lifecycle of a stream is shown in Figure 2.
                                +--------+
                        send PP |        | recv PP
                       ,--------|  idle  |--------.
                      /         |        |         \
                     v          +--------+          v
              +----------+          |           +----------+
              |          |          | send H /  |          |
       ,------| reserved |          | recv H    | reserved |------.
       |      | (local)  |          |           | (remote) |      |
       |      +----------+          v           +----------+      |
       |          |             +--------+             |          |
       |          |     recv ES |        | send ES     |          |
       |   send H |     ,-------|  open  |-------.     | recv H   |
       |          |    /        |        |        \    |          |
       |          v   v         +--------+         v   v          |
       |      +----------+          |           +----------+      |
       |      |   half   |          |           |   half   |      |
       |      |  closed  |          | send R /  |  closed  |      |
       |      | (remote) |          | recv R    | (local)  |      |
       |      +----------+          |           +----------+      |
       |           |                |                 |           |
       |           | send ES /      |       recv ES / |           |
       |           | send R /       v        send R / |           |
       |           | recv R     +--------+   recv R   |           |
       | send R /  `----------->|        |<-----------'  send R / |
       | recv R                 | closed |               recv R   |
       `----------------------->|        |<----------------------'
                                +--------+

          send:   endpoint sends this frame
          recv:   endpoint receives this frame

          H:  HEADERS frame (with implied CONTINUATIONs)
          PP: PUSH_PROMISE frame (with implied CONTINUATIONs)
          ES: END_STREAM flag
          R:  RST_STREAM frame

                          Figure 2: Stream States

Note that this diagram shows stream state transitions and the frames
and flags that affect those transitions only.  In this regard,
CONTINUATION frames do not result in state transitions; they are
effectively part of the HEADERS or PUSH_PROMISE that they follow.

For the purpose of state transitions, the END_STREAM flag is
processed as a separate event to the frame that bears it; a HEADERS
frame with the END_STREAM flag set can cause two state transitions.

Both endpoints have a subjective view of the state of a stream that
could be different when frames are in transit.  Endpoints do not
coordinate the creation of streams; they are created unilaterally by
either endpoint.  The negative consequences of a mismatch in states
are limited to the "closed" state after sending RST_STREAM, where
frames might be received for some time after closing.

Streams have the following states:

idle:
    All streams start in the "idle" state.

    The following transitions are valid from this state:

    *  Sending or receiving a HEADERS frame causes the stream to
        become "open".  The stream identifier is selected as described
        in Section 5.1.1.  The same HEADERS frame can also cause a
        stream to immediately become "half-closed".

    *  Sending a PUSH_PROMISE frame on another stream reserves the
        idle stream that is identified for later use.  The stream state
        for the reserved stream transitions to "reserved (local)".

    *  Receiving a PUSH_PROMISE frame on another stream reserves an
        idle stream that is identified for later use.  The stream state
        for the reserved stream transitions to "reserved (remote)".

    *  Note that the PUSH_PROMISE frame is not sent on the idle stream
        but references the newly reserved stream in the Promised Stream
        ID field.

    Receiving any frame other than HEADERS or PRIORITY on a stream in
    this state MUST be treated as a connection error (Section 5.4.1)
    of type PROTOCOL_ERROR.

reserved (local):
    A stream in the "reserved (local)" state is one that has been
    promised by sending a PUSH_PROMISE frame.  A PUSH_PROMISE frame
    reserves an idle stream by associating the stream with an open
    stream that was initiated by the remote peer (see Section 8.2).

    In this state, only the following transitions are possible:

    *  The endpoint can send a HEADERS frame.  This causes the stream
        to open in a "half-closed (remote)" state.

    *  Either endpoint can send a RST_STREAM frame to cause the stream
        to become "closed".  This releases the stream reservation.


    An endpoint MUST NOT send any type of frame other than HEADERS,
    RST_STREAM, or PRIORITY in this state.

    A PRIORITY or WINDOW_UPDATE frame MAY be received in this state.
    Receiving any type of frame other than RST_STREAM, PRIORITY, or
    WINDOW_UPDATE on a stream in this state MUST be treated as a
    connection error (Section 5.4.1) of type PROTOCOL_ERROR.

reserved (remote):
    A stream in the "reserved (remote)" state has been reserved by a
    remote peer.

    In this state, only the following transitions are possible:

    *  Receiving a HEADERS frame causes the stream to transition to
        "half-closed (local)".

    *  Either endpoint can send a RST_STREAM frame to cause the stream
        to become "closed".  This releases the stream reservation.

    An endpoint MAY send a PRIORITY frame in this state to
    reprioritize the reserved stream.  An endpoint MUST NOT send any
    type of frame other than RST_STREAM, WINDOW_UPDATE, or PRIORITY in
    this state.

    Receiving any type of frame other than HEADERS, RST_STREAM, or
    PRIORITY on a stream in this state MUST be treated as a connection
    error (Section 5.4.1) of type PROTOCOL_ERROR.

open:
    A stream in the "open" state may be used by both peers to send
    frames of any type.  In this state, sending peers observe
    advertised stream-level flow-control limits (Section 5.2).

    From this state, either endpoint can send a frame with an
    END_STREAM flag set, which causes the stream to transition into
    one of the "half-closed" states.  An endpoint sending an
    END_STREAM flag causes the stream state to become "half-closed
    (local)"; an endpoint receiving an END_STREAM flag causes the
    stream state to become "half-closed (remote)".

    Either endpoint can send a RST_STREAM frame from this state,
    causing it to transition immediately to "closed".

half-closed (local):
    A stream that is in the "half-closed (local)" state cannot be used
    for sending frames other than WINDOW_UPDATE, PRIORITY, and
    RST_STREAM.

    A stream transitions from this state to "closed" when a frame that
    contains an END_STREAM flag is received or when either peer sends
    a RST_STREAM frame.

    An endpoint can receive any type of frame in this state.
    Providing flow-control credit using WINDOW_UPDATE frames is
    necessary to continue receiving flow-controlled frames.  In this
    state, a receiver can ignore WINDOW_UPDATE frames, which might
    arrive for a short period after a frame bearing the END_STREAM
    flag is sent.

    PRIORITY frames received in this state are used to reprioritize
    streams that depend on the identified stream.

half-closed (remote):
    A stream that is "half-closed (remote)" is no longer being used by
    the peer to send frames.  In this state, an endpoint is no longer
    obligated to maintain a receiver flow-control window.

    If an endpoint receives additional frames, other than
    WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in
    this state, it MUST respond with a stream error (Section 5.4.2) of
    type STREAM_CLOSED.

    A stream that is "half-closed (remote)" can be used by the
    endpoint to send frames of any type.  In this state, the endpoint
    continues to observe advertised stream-level flow-control limits
    (Section 5.2).

    A stream can transition from this state to "closed" by sending a
    frame that contains an END_STREAM flag or when either peer sends a
    RST_STREAM frame.

closed:
    The "closed" state is the terminal state.

    An endpoint MUST NOT send frames other than PRIORITY on a closed
    stream.  An endpoint that receives any frame other than PRIORITY
    after receiving a RST_STREAM MUST treat that as a stream error
    (Section 5.4.2) of type STREAM_CLOSED.  Similarly, an endpoint
    that receives any frames after receiving a frame with the
    END_STREAM flag set MUST treat that as a connection error
    (Section 5.4.1) of type STREAM_CLOSED, unless the frame is
    permitted as described below.

    WINDOW_UPDATE or RST_STREAM frames can be received in this state
    for a short period after a DATA or HEADERS frame containing an
    END_STREAM flag is sent.  Until the remote peer receives and
    processes RST_STREAM or the frame bearing the END_STREAM flag, it
    might send frames of these types.  Endpoints MUST ignore
    WINDOW_UPDATE or RST_STREAM frames received in this state, though
    endpoints MAY choose to treat frames that arrive a significant
    time after sending END_STREAM as a connection error
    (Section 5.4.1) of type PROTOCOL_ERROR.

    PRIORITY frames can be sent on closed streams to prioritize
    streams that are dependent on the closed stream.  Endpoints SHOULD
    process PRIORITY frames, though they can be ignored if the stream
    has been removed from the dependency tree (see Section 5.3.4).

    If this state is reached as a result of sending a RST_STREAM
    frame, the peer that receives the RST_STREAM might have already
    sent -- or enqueued for sending -- frames on the stream that
    cannot be withdrawn.  An endpoint MUST ignore frames that it
    receives on closed streams after it has sent a RST_STREAM frame.
    An endpoint MAY choose to limit the period over which it ignores
    frames and treat frames that arrive after this time as being in
    error.

    Flow-controlled frames (i.e., DATA) received after sending
    RST_STREAM are counted toward the connection flow-control window.
    Even though these frames might be ignored, because they are sent
    before the sender receives the RST_STREAM, the sender will
    consider the frames to count against the flow-control window.

    An endpoint might receive a PUSH_PROMISE frame after it sends
    RST_STREAM.  PUSH_PROMISE causes a stream to become "reserved"
    even if the associated stream has been reset.  Therefore, a
    RST_STREAM is needed to close an unwanted promised stream.

In the absence of more specific guidance elsewhere in this document,
implementations SHOULD treat the receipt of a frame that is not
expressly permitted in the description of a state as a connection
error (Section 5.4.1) of type PROTOCOL_ERROR.  Note that PRIORITY can
be sent and received in any stream state.  Frames of unknown types
are ignored.

An example of the state transitions for an HTTP request/response
exchange can be found in Section 8.1.  An example of the state
transitions for server push can be found in Sections 8.2.1 and 8.2.2.

</code>
</pre>
</details>
