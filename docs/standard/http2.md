---
sidebarDepth: 4
---

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

## 5. 流和多路复用

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

  - idle:
  
    所有流均以`idle`状态开始。
  
    从此状态开始，以下转换有效：

    - 发送或接收`HEADERS`帧会使流变为`open`状态。如第5.1.1节所述选择流标识符。相同的`HEADERS`帧还可以使流立即变为`half-closed`。
    - 在另一个流上发送`PUSH_PROMISE`帧保留标识为以后使用的空闲流。保留流的流状态转换为`reserved (local)`。
    - 在另一个流上接收`PUSH_PROMISE`帧将保留一个空闲流，该空闲流将被标识以供以后使用。保留流的流状态转换为`reserved (remote)`。
    - 请注意，`PUSH_PROMISE`帧不是在空闲流上发送的，而是在Promised Stream ID字段中引用新保留的流。

    在这种状态下，在流上接收到除`HEADERS`或`PRIORITY`以外的任何帧，都必须视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。


  - reserved (local):

    处于`reserved (local)`状态的流是通过发送`PUSH_PROMISE`帧承诺的。`PUSH_PROMISE`帧通过将流与远程对等方启动的开放流相关联来保留空闲流（请参见第8.2节）。
    
    在这种状态下，只能进行以下转换：
      
    - 端点可以发送HEADERS帧。这将导致流以`half-closed (remote)`状态打开。
    - 任一端点均可发送`RST_STREAM`帧以使流转为`closed`。这将释放流保留。
    
    在这种状态下，端点不得发送除`HEADERS`、`RST_STREAM`或`PRIORITY`以外的任何类型的帧。
    
    在这种状态下可以接收一个`PRIORITY`或`WINDOW_UPDATE`帧。在这种状态下，在流上接收除`RST_STREAM`、`PRIORITY`或`WINDOW_UPDATE`以外的任何类型的帧，都必须视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。
  
  - reserved (remote):
  
    处于`reserved (remote)`状态的流已被远程对等方保留。
    
    在这种状态下，只能进行以下转换：
    
    - 接收`HEADERS`帧会使流转换为`half-closed (local)`。
    - 任一端点均可发送`RST_STREAM`帧以使流`closed`。这将释放流保留。
    
    端点可以在这种状态下发送一个`PRIORITY`帧来重新排序保留流的优先级。在这种状态下，端点不得发送除`RST_STREAM`，`WINDOW_UPDATE`或`PRIORITY`以外的任何类型的帧。
    
    在这种状态下，在流上接收除`HEADERS`，`RST_STREAM`或`PRIORITY`以外的任何类型的帧，都必须视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。

  - open:
    
    处于`open`状态的流可被两个对等方用来发送任何类型的帧。在这种状态下，发送对等方遵守通告的流级别流控制限制（第5.2节）。
    
    从此状态，任一端点都可以发送设置了`END_STREAM`标志的帧，这会使流转换为`half-closed`状态之一。发送`END_STREAM`标志的端点使流状态变为`half-closed (local)`；接收到`END_STREAM`标志的端点使流状态变为`half-closed (remote)`。

    任何一个端点都可以从该状态发送`RST_STREAM`帧，从而使其立即转换为`closed`状态。

  - half-closed (local):
  
    处于`half-closed (local)`状态的流不能用于发送`WINDOW_UPDATE`，`PRIORITY`和`RST_STREAM`以外的帧。
    
    当收到包含`END_STREAM`标志的帧或任一对等方发送`RST_STREAM`帧时，流将从此状态转换为`closed`。
    
    端点可以在此状态下接收任何类型的帧。要继续接收流控制的帧，必须使用`WINDOW_UPDATE`帧提供流控制信用。在这种状态下，接收器可以忽略`WINDOW_UPDATE`帧，这些帧可能在发送带有`END_STREAM`标志的帧之后的短时间内到达。
    
    在此状态下接收的`PRIORITY`帧用于重新确定依赖于已标识流的流的优先级。

  - half-closed (remote):
  
    对等方不再使用`half-closed (remote):`流发送帧。在这种状态下，端点不再必须维护接收器流控制窗口。
    
    如果端点收到处于此状态的流的`WINDOW_UPDATE`，`PRIORITY`或`RST_STREAM`以外的其他帧，则它必须以`STREAM_CLOSED`类型的流错误（第5.4.2节）作出响应。
    
    端点可以使用`half-closed (remote)`流来发送任何类型的帧。在这种状态下，端点继续遵守通告的流级流量控制限制（第5.2节）。
    
    通过发送包含`END_STREAM`标志的帧或任何一个对等方发送`RST_STREAM`帧，流都可以从此状态转换为`closed`。

  - closed:
    
    `closed`状态是终止状态。

    端点不得在封闭流上发送除`PRIORITY`以外的帧。接收到`RST_STREAM`之后接收到除`PRIORITY`以外的任何帧的端点必须将其视为`STREAM_CLOSED`类型的流错误（5.4.2节）。类似地，在接收到设置了`END_STREAM`标志的帧之后接收任何帧的端点务必将其视为`STREAM_CLOSED`类型的连接错误（第5.4.1节），除非如下所述允许该帧。

    发送包含`END_STREAM`标志的`DATA`或`HEADERS`帧后，可以在此状态下短时间内接收`WINDOW_UPDATE`或`RST_STREAM`帧。在远程对等方接收并处理`RST_STREAM`或带有`END_STREAM`标志的帧之前，它可能会发送这些类型的帧。端点必须忽略在这种状态下接收到的`WINDOW_UPDATE`或`RST_STREAM`帧，尽管端点可以选择将发送`END_STREAM`之后很长时间到达的帧视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。

    可以在封闭流上发送`PRIORITY`帧，以区分依赖于封闭流的流的优先级。端点应该处理`PRIORITY`帧，但是如果从依赖关系树中删除了流，则可以忽略它们（参见第5.3.4节）。

    如果由于发送`RST_STREAM`帧而达到此状态，则接收`RST_STREAM`的对等端可能已经发送了（或已排队发送）无法撤消的流上的帧。端点发送`RST_STREAM`帧后，必须忽略其在关闭流上接收的帧。端点可以选择限制其忽略帧的时间段，并将在此时间之后到达的帧视为错误。

    发送`RST_STREAM`之后收到的流控制帧（即`DATA`）计入连接流控制窗口。即使这些帧可能会被忽略，因为它们是在发送方接收`RST_STREAM`之前发送的，因此发送方将考虑将这些帧计入流控制窗口。

    端点在发送`RST_STREAM`之后可能会收到`PUSH_PROMISE`帧。即使相关联的流已被重置，`PUSH_PROMISE`也会使流变为`reserved`。因此，需要`RST_STREAM`来关闭不需要的承诺流。

在本文档其他地方没有更具体的指导的情况下，实现应将状态描述中未明确允许的帧接收视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。请注意，可以在任何流状态下发送和接收`PRIORITY`。未知类型的帧将被忽略。 

HTTP请求/响应交换的状态转换示例可以在第8.1节中找到。有关服务器推送的状态转换的示例，请参见第8.2.1和8.2.2节。



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

#### 5.1.1 流标识符

用无符号31位整数来标识流。由客户端发起的流必须使用奇数流标识符。由服务器发起的流必须使用偶数流标识符。流标识符零（0x0）用于连接控制消息。流标识符零不能用于建立新流。

升级到HTTP/2（请参阅第3.2节）的HTTP/1.1请求将以流标识符1（0x1）进行响应。升级完成后，流0x1被`half-closed (local)`到客户端。因此，从HTTP/1.1升级的客户端无法将流0x1选择为新的流标识符。

新建立的流的标识符必须在数值上大于发起端点已打开或保留的所有流。这控制使用`HEADERS`帧打开的流和使用`PUSH_PROMISE`保留的流。收到未知流标识符的端点必须以`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）做出响应。

首次使用新的流标识符会隐式关闭处于`idle`状态的所有流，该流可能已由该对等方使用值较低的流标识符启动。例如，如果客户端在流7上发送`HEADERS`帧而没有在流5上发送帧，则当发送或接收流7的第一个帧时，流5转换为`closed`状态。

流标识符不能重复使用。长期存在的连接可能导致端点耗尽可用范围的流标识符。无法建立新的流标识符的客户端可以为新的流建立新的连接。无法建立新流标识符的服务器可以发送`GOAWAY`帧，以便客户端被迫为新流打开新连接。

<details>
<summary>原文</summary>
<pre>
<code>

5.1.1.  Stream Identifiers

Streams are identified with an unsigned 31-bit integer.  Streams
initiated by a client MUST use odd-numbered stream identifiers; those
initiated by the server MUST use even-numbered stream identifiers.  A
stream identifier of zero (0x0) is used for connection control
messages; the stream identifier of zero cannot be used to establish a
new stream.

HTTP/1.1 requests that are upgraded to HTTP/2 (see Section 3.2) are
responded to with a stream identifier of one (0x1).  After the
upgrade completes, stream 0x1 is "half-closed (local)" to the client.
Therefore, stream 0x1 cannot be selected as a new stream identifier
by a client that upgrades from HTTP/1.1.

The identifier of a newly established stream MUST be numerically
greater than all streams that the initiating endpoint has opened or
reserved.  This governs streams that are opened using a HEADERS frame
and streams that are reserved using PUSH_PROMISE.  An endpoint that
receives an unexpected stream identifier MUST respond with a
connection error (Section 5.4.1) of type PROTOCOL_ERROR.

The first use of a new stream identifier implicitly closes all
streams in the "idle" state that might have been initiated by that
peer with a lower-valued stream identifier.  For example, if a client
sends a HEADERS frame on stream 7 without ever sending a frame on
stream 5, then stream 5 transitions to the "closed" state when the
first frame for stream 7 is sent or received.

Stream identifiers cannot be reused.  Long-lived connections can
result in an endpoint exhausting the available range of stream
identifiers.  A client that is unable to establish a new stream
identifier can establish a new connection for new streams.  A server
that is unable to establish a new stream identifier can send a GOAWAY
frame so that the client is forced to open a new connection for new
streams.

</code>
</pre>
</details>

#### 5.1.2 流并发性

对等方可以使用`SETTINGS`帧内的`SETTINGS_MAX_CONCURRENT_STREAMS`参数（请参阅第6.5.2节）来限制并发活动流的数量。最大并发流设置特定于每个端点，并且仅适用于接收该设置的对等方。即，客户端指定服务器可以启动的并发流的最大数量，服务器指定客户端可以启动的并发流的最大数量。

处于`open`状态或处于`half-closed`状态中的任一状态的流均计入允许端点打开的最大流数。这三种状态中任何一种的流都将计入`SETTINGS_MAX_CONCURRENT_STREAMS`设置中公布的限制。处于任何`reserved`状态的流均不会计入流限制。

端点不得超过其对等方设置的限制。接收到导致其通告的并发流限制被超过的`HEADERS`帧的端点必须将此视为`PROTOCOL_ERROR`或`REFUSED_STREAM`类型的流错误（第5.4.2节）。错误代码的选择确定端点是否希望启用自动重试（有关详细信息，请参见第8.1.4节）。

希望将`SETTINGS_MAX_CONCURRENT_STREAMS`的值减小到当前打开流的数量以下的端点可以关闭超过新值的流，或者允许流完成。


<details>
<summary>原文</summary>
<pre>
<code>

5.1.2.  Stream Concurrency

A peer can limit the number of concurrently active streams using the
SETTINGS_MAX_CONCURRENT_STREAMS parameter (see Section 6.5.2) within
a SETTINGS frame.  The maximum concurrent streams setting is specific
to each endpoint and applies only to the peer that receives the
setting.  That is, clients specify the maximum number of concurrent
streams the server can initiate, and servers specify the maximum
number of concurrent streams the client can initiate.

Streams that are in the "open" state or in either of the "half-
closed" states count toward the maximum number of streams that an
endpoint is permitted to open.  Streams in any of these three states
count toward the limit advertised in the
SETTINGS_MAX_CONCURRENT_STREAMS setting.  Streams in either of the
"reserved" states do not count toward the stream limit.

Endpoints MUST NOT exceed the limit set by their peer.  An endpoint
that receives a HEADERS frame that causes its advertised concurrent
stream limit to be exceeded MUST treat this as a stream error
(Section 5.4.2) of type PROTOCOL_ERROR or REFUSED_STREAM.  The choice
of error code determines whether the endpoint wishes to enable
automatic retry (see Section 8.1.4) for details).

An endpoint that wishes to reduce the value of
SETTINGS_MAX_CONCURRENT_STREAMS to a value that is below the current
number of open streams can either close streams that exceed the new
value or allow streams to complete.

</code>
</pre>
</details>

### 5.2 流控制

使用流进行多路复用会引起TCP连接使用方面的争用，从而导致流阻塞。流控制方案可确保同一连接上的流不会造成相消干扰。流控制既用于单个流，也用于整个连接。 

HTTP/2通过使用`WINDOW_UPDATE`框架提供流控制（第6.9节）。

<details>
<summary>原文</summary>
<pre>
<code>

5.2.  Flow Control

Using streams for multiplexing introduces contention over use of the
TCP connection, resulting in blocked streams.  A flow-control scheme
ensures that streams on the same connection do not destructively
interfere with each other.  Flow control is used for both individual
streams and for the connection as a whole.

HTTP/2 provides for flow control through use of the WINDOW_UPDATE
frame (Section 6.9).

</code>
</pre>
</details>

#### 5.2.1 流控制原理

HTTP/2流流控制旨在允许使用各种流控制算法而无需更改协议。 HTTP/2中的流控制具有以下特征：

  1. 流控制特定于连接。两种类型的流控制都在单跳的端点之间，而不是在整个端到端路径上。
  
  2. 流控制基于`WINDOW_UPDATE`帧。接收方通告它们准备在流上以及整个连接中接收多少个八位位组。这是基于信用的方案。
  
  3. 流量控制是方向性的，由接收器提供总体控制。接收者可以选择设置每个流和整个连接所需的任何窗口大小。发送方必须遵守接收方施加的流量控制限制。客户端，服务器和中介都独立地将其流控制窗口发布为接收方，并在发送时遵守其对等方设置的流控制限制。
  
  4. 对于新流和整个连接，流控制窗口的初始值为65,535个八位位组。
  
  5. 帧类型确定流控制是否适用于帧。在本文档中指定的帧中，只有`DATA`帧要进行流控制；否则，仅对`DATA`帧进行流控制。所有其他帧类型都不会占用广告流控制窗口中的空间。这确保了重要的控制帧不会被流控制阻塞。
  
  6. 无法禁用流控制。
  
  7. HTTP/2仅定义`WINDOW_UPDATE`帧的格式和语义（第6.9节）。该文件没有规定接收者如何决定何时发送该帧或它发送的值，也没有规定发送者如何选择发送分组。实现者可以选择任何适合其需求的算法。
  
实现还负责管理如何根据优先级发送请求和响应，选择如何避免对请求的行头阻塞以及管理新流的创建。这些算法的选择可以与任何流控制算法交互。

<details>
<summary>原文</summary>
<pre>
<code>

5.2.1.  Flow-Control Principles

HTTP/2 stream flow control aims to allow a variety of flow-control
algorithms to be used without requiring protocol changes.  Flow
control in HTTP/2 has the following characteristics:

1.  Flow control is specific to a connection.  Both types of flow
    control are between the endpoints of a single hop and not over
    the entire end-to-end path.

2.  Flow control is based on WINDOW_UPDATE frames.  Receivers
    advertise how many octets they are prepared to receive on a
    stream and for the entire connection.  This is a credit-based
    scheme.

3.  Flow control is directional with overall control provided by the
    receiver.  A receiver MAY choose to set any window size that it
    desires for each stream and for the entire connection.  A sender
    MUST respect flow-control limits imposed by a receiver.  Clients,
    servers, and intermediaries all independently advertise their
    flow-control window as a receiver and abide by the flow-control
    limits set by their peer when sending.

4.  The initial value for the flow-control window is 65,535 octets
    for both new streams and the overall connection.

5.  The frame type determines whether flow control applies to a
    frame.  Of the frames specified in this document, only DATA
    frames are subject to flow control; all other frame types do not
    consume space in the advertised flow-control window.  This
    ensures that important control frames are not blocked by flow
    control.

6.  Flow control cannot be disabled.

7.  HTTP/2 defines only the format and semantics of the WINDOW_UPDATE
    frame (Section 6.9).  This document does not stipulate how a
    receiver decides when to send this frame or the value that it
    sends, nor does it specify how a sender chooses to send packets.
    Implementations are able to select any algorithm that suits their
    needs.

Implementations are also responsible for managing how requests and
responses are sent based on priority, choosing how to avoid head-of-
line blocking for requests, and managing the creation of new streams.
Algorithm choices for these could interact with any flow-control
algorithm.


</code>
</pre>
</details>

#### 5.2.2 适当使用流控制

定义流控制以保护在资源约束下运行的端点。例如，代理需要在许多连接之间共享内存，并且可能具有较慢的上游连接和较快的下游连接。流控制解决了以下情况：接收器无法处理一个流上的数据，但希望继续处理同一连接中的其他流。

不需要此功能的部署可以通告最大大小的流控制窗口（2^31-1），并在接收到任何数据时通过发送`WINDOW_UPDATE`帧来维护此窗口。这有效地禁用了该接收器的流控制。相反，发送方始终要遵守接收方通告的流控制窗口。

资源受限（例如，内存）的部署可以采用流控制来限制对等方可以消耗的内存量。但是请注意，如果在不了解带宽延迟乘积的情况下启用了流控制，则会导致可用网络资源的最佳使用（请参阅[RFC7323]）。

即使完全了解当前的带宽延迟产品，执行流控制也可能很困难。使用流控制时，接收者务必及时从TCP接收缓冲区中读取。如果未读取并执行诸如`WINDOW_UPDATE`之类的关键帧，则可能会导致死锁。

<details>
<summary>原文</summary>
<pre>
<code>

5.2.2.  Appropriate Use of Flow Control

Flow control is defined to protect endpoints that are operating under
resource constraints.  For example, a proxy needs to share memory
between many connections and also might have a slow upstream
connection and a fast downstream one.  Flow-control addresses cases
where the receiver is unable to process data on one stream yet wants
to continue to process other streams in the same connection.

Deployments that do not require this capability can advertise a flow-
control window of the maximum size (2^31-1) and can maintain this
window by sending a WINDOW_UPDATE frame when any data is received.
This effectively disables flow control for that receiver.
Conversely, a sender is always subject to the flow-control window
advertised by the receiver.

Deployments with constrained resources (for example, memory) can
employ flow control to limit the amount of memory a peer can consume.
Note, however, that this can lead to suboptimal use of available
network resources if flow control is enabled without knowledge of the
bandwidth-delay product (see [RFC7323]).

Even with full awareness of the current bandwidth-delay product,
implementation of flow control can be difficult.  When using flow
control, the receiver MUST read from the TCP receive buffer in a
timely fashion.  Failure to do so could lead to a deadlock when
critical frames, such as WINDOW_UPDATE, are not read and acted upon.

</code>
</pre>
</details>

### 5.3 流优先级

客户端可以通过在打开流的`HEADERS`帧（第6.2节）中包括优先级信息来为新流分配优先级。在任何其他时间，可以使用`PRIORITY`帧（第6.3节）来更改流的优先级。

优先级划分的目的是允许端点表达在管理并发流时希望其对等方分配资源的方式。最重要的是，当发送容量有限时，可以使用优先级来选择传输帧的流。

可以通过将流标记为依赖于其他流的完成来对流进行优先级排序（第5.3.1节）。每个依赖项都分配了一个相对权重，该数字用于确定分配给依赖于同一流的流的可用资源的相对比例。

明确设置流的优先级输入到优先级处理中。它不保证该流相对于任何其他流的任何特定处理或传输顺序。端点不能强制对等方使用优先级按特定顺序处理并发流。因此，表达优先级只是一个建议。

可以从消息中省略优先级信息。在提供任何显式值之前使用默认值（第5.3.5节）。

<details>
<summary>原文</summary>
<pre>
<code>

5.3.  Stream Priority

A client can assign a priority for a new stream by including
prioritization information in the HEADERS frame (Section 6.2) that
opens the stream.  At any other time, the PRIORITY frame
(Section 6.3) can be used to change the priority of a stream.

The purpose of prioritization is to allow an endpoint to express how
it would prefer its peer to allocate resources when managing
concurrent streams.  Most importantly, priority can be used to select
streams for transmitting frames when there is limited capacity for
sending.

Streams can be prioritized by marking them as dependent on the
completion of other streams (Section 5.3.1).  Each dependency is
assigned a relative weight, a number that is used to determine the
relative proportion of available resources that are assigned to
streams dependent on the same stream.

Explicitly setting the priority for a stream is input to a
prioritization process.  It does not guarantee any particular
processing or transmission order for the stream relative to any other
stream.  An endpoint cannot force a peer to process concurrent
streams in a particular order using priority.  Expressing priority is
therefore only a suggestion.

Prioritization information can be omitted from messages.  Defaults
are used prior to any explicit values being provided (Section 5.3.5).

</code>
</pre>
</details>

#### 5.3.1 流依赖关系

每个流都可以被赋予对另一个流的显式依赖关系，包括一个依赖关系表示优先向标识的流而不是依赖流分配资源;

不依赖任何其他流的流的流依赖关系为0x0。换句话说，不存在的流0构成树的根。

依赖于另一个流的流是从属流。流所依赖的流是父流。对当前不在树中的流的依赖性（例如处于`idle`状态的流）会导致该流被赋予默认优先级（第5.3.5节）。

在分配对另一个流的依赖性时，该流为作为父流的新依赖项添加。共享同一父对象的从属流不会相对于彼此排序。例如，如果流B和C依赖于流A，并且如果创建的流D依赖于流A，则这将导致A的依赖顺序，然后是B，C和D的任何顺序。

```

       A                 A
      / \      ==>      /|\
     B   C             B D C

Figure 3: Example of Default Dependency Creation

```

排他标志允许插入新级别的依赖关系。独占标志导致流成为其父流的唯一依赖项，从而导致其他依赖项变为依赖于独占流。在前面的示例中，如果创建的流D具有对流A的排他性依赖关系，则结果D将成为B和C的依赖关系父级。

```
                         A
       A                 |
      / \      ==>       D
     B   C              / \
                       B   C

Figure 4: Example of Exclusive Dependency Creation
```

在依赖关系树内部，从属流仅应在其所依赖的所有流（父流链最高为0x0）关闭或无法在其上取得进展时才分配资源。

流不能依靠自己。端点必须将此视为`PROTOCOL_ERROR`类型的流错误（5.4.2节）。

<details>
<summary>原文</summary>
<pre>
<code>

5.3.1.  Stream Dependencies

   Each stream can be given an explicit dependency on another stream.
   Including a dependency expresses a preference to allocate resources
   to the identified stream rather than to the dependent stream.

   A stream that is not dependent on any other stream is given a stream
   dependency of 0x0.  In other words, the non-existent stream 0 forms
   the root of the tree.

   A stream that depends on another stream is a dependent stream.  The
   stream upon which a stream is dependent is a parent stream.  A
   dependency on a stream that is not currently in the tree -- such as a
   stream in the "idle" state -- results in that stream being given a
   default priority (Section 5.3.5).

   When assigning a dependency on another stream, the stream is added as
   a new dependency of the parent stream.  Dependent streams that share
   the same parent are not ordered with respect to each other.  For
   example, if streams B and C are dependent on stream A, and if stream
   D is created with a dependency on stream A, this results in a
   dependency order of A followed by B, C, and D in any order.

       A                 A
      / \      ==>      /|\
     B   C             B D C

             Figure 3: Example of Default Dependency Creation

   An exclusive flag allows for the insertion of a new level of
   dependencies.  The exclusive flag causes the stream to become the
   sole dependency of its parent stream, causing other dependencies to
   become dependent on the exclusive stream.  In the previous example,
   if stream D is created with an exclusive dependency on stream A, this
   results in D becoming the dependency parent of B and C.

                         A
       A                 |
      / \      ==>       D
     B   C              / \
                       B   C

            Figure 4: Example of Exclusive Dependency Creation

   Inside the dependency tree, a dependent stream SHOULD only be
   allocated resources if either all of the streams that it depends on
   (the chain of parent streams up to 0x0) are closed or it is not
   possible to make progress on them.

   A stream cannot depend on itself.  An endpoint MUST treat this as a
   stream error (Section 5.4.2) of type PROTOCOL_ERROR.

</code>
</pre>
</details>

#### 5.3.2 依赖权重

所有依赖流都被分配1到256（含）之间的整数权重。

具有相同父流的流应根据其权重按比例分配资源。因此，如果流B依赖权重为4的流A，流C依赖权重为12的流A，并且流A上无法进行任何处理，则流B理想地接收分配给流C的资源的三分之一。

<details>
<summary>原文</summary>
<pre>
<code>

5.3.2.  Dependency Weighting

   All dependent streams are allocated an integer weight between 1 and
   256 (inclusive).

   Streams with the same parent SHOULD be allocated resources
   proportionally based on their weight.  Thus, if stream B depends on
   stream A with weight 4, stream C depends on stream A with weight 12,
   and no progress can be made on stream A, stream B ideally receives
   one-third of the resources allocated to stream C.

</code>
</pre>
</details>

#### 5.3.3 重新排序

流优先级使用`PRIORITY`帧进行更改。设置独立性会导致流变得依赖于已标识的父流。

如果父级被重新初始化，则从属流将与其父级流一起移动。为排定优先级的流设置具有独占标志的依赖关系会导致新的父流的所有依赖关系都变为已排定优先级的流。

如果使流依赖于其自己的依赖关系之一，则首先移动以前依赖的流以使其依赖于优先流的先前父对象。移动的依赖项保持其权重。

例如，考虑原始的依赖关系树，其中B和C依赖于A，D和E依赖于C，F依赖于D.如果使A依赖于D，则D代替A.全部其他依赖关系保持不变，但F除外，如果重新优先级排他，则F依赖于A。

```
       x                x                x                 x
       |               / \               |                 |
       A              D   A              D                 D
      / \            /   / \            / \                |
     B   C     ==>  F   B   C   ==>    F   A       OR      A
        / \                 |             / \             /|\
       D   E                E            B   C           B C F
       |                                     |             |
       F                                     E             E
                  (intermediate)   (non-exclusive)    (exclusive)

                Figure 5: Example of Dependency Reordering
```


<details>
<summary>原文</summary>
<pre>
<code>

5.3.3.  Reprioritization

   Stream priorities are changed using the PRIORITY frame.  Setting a
   dependency causes a stream to become dependent on the identified
   parent stream.

   Dependent streams move with their parent stream if the parent is
   reprioritized.  Setting a dependency with the exclusive flag for a
   reprioritized stream causes all the dependencies of the new parent
   stream to become dependent on the reprioritized stream.

   If a stream is made dependent on one of its own dependencies, the
   formerly dependent stream is first moved to be dependent on the
   reprioritized stream's previous parent.  The moved dependency retains
   its weight.

   For example, consider an original dependency tree where B and C
   depend on A, D and E depend on C, and F depends on D.  If A is made
   dependent on D, then D takes the place of A.  All other dependency
   relationships stay the same, except for F, which becomes dependent on
   A if the reprioritization is exclusive.

       x                x                x                 x
       |               / \               |                 |
       A              D   A              D                 D
      / \            /   / \            / \                |
     B   C     ==>  F   B   C   ==>    F   A       OR      A
        / \                 |             / \             /|\
       D   E                E            B   C           B C F
       |                                     |             |
       F                                     E             E
                  (intermediate)   (non-exclusive)    (exclusive)

                Figure 5: Example of Dependency Reordering

</code>
</pre>
</details>

#### 5.3.4 优先级状态管理

当从依赖关系树中删除流时，可以将其依赖关系移动为依赖于封闭流的父级。通过根据封闭流的权重按比例分配封闭流的依赖关系权重，可以重新计算新依赖关系的权重。

从依赖关系树中删除的流会导致某些优先级信息丢失。资源在具有相同父流的流之间共享，这意味着如果该流中的某个流关闭或被阻塞，则分配给该流的任何备用容量都将分配给该流的直接邻居。但是，如果从树中删除了公共依赖项，则这些流与下一个最高级别的流共享资源。

例如，假设流A和B共享父级，而流C和D都依赖流A。在删除流A之前，如果流A和D无法进行，则流C接收所有专用于流A的资源。如果从树中删除了流A，则流A的权重将在流C和D之间分配。如果流D仍然无法进行，则导致流C接收减少了资源。对于相等的起始权重，C接收的是可用资源的三分之一而不是一半。

如果在依赖项中标识的流没有关联的优先级信息，则在依赖该优先级的信息正在传输时，该流可能会关闭。 然后为依存流分配默认优先级（第5.3.5节）。由于可能会给流一个与预期的优先级不同的优先级，因此可能会产生次优的优先级。

为避免这些问题，端点应在流关闭后的一段时间内保留流优先级状态。状态保留的时间越长，分配区域的流分配不正确或默认优先级值的机会就越少。

类似地，处于`idle`状态的流可以被分配优先级或成为其他流的父级。这允许在依赖关系树中创建分组节点，从而实现更灵活的优先级表达。空闲流以默认优先级开头（第5.3.5节）。

对于未计入`SETTINGS_MAX_CONCURRENT_STREAMS`设置的限制的流，优先级信息的保留可能会给端点造成很大的状态负担。因此，保留的优先级状态数量可能会受到限制。

端点为优先级保留的其他状态数量可能取决于负载；在高负载下，可以丢弃优先级状态以限制资源承诺。在极端情况下，端点甚至可以丢弃活动或保留流的优先级状态。如果应用了限制，则端点SHOULD至少应保持其`SETTINGS_MAX_CONCURRENT_STREAMS`设置所允许的流数量。实施还应尝试为优先级树中处于活动状态的流保留状态。

如果保留的状态足以保留该状态，则接收`PRIORITY`帧的端点将更改关闭流的优先级，应改变依赖于此流的流的依赖关系。

<details>
<summary>原文</summary>
<pre>
<code>

5.3.4.  Prioritization State Management

   When a stream is removed from the dependency tree, its dependencies
   can be moved to become dependent on the parent of the closed stream.
   The weights of new dependencies are recalculated by distributing the
   weight of the dependency of the closed stream proportionally based on
   the weights of its dependencies.

   Streams that are removed from the dependency tree cause some
   prioritization information to be lost.  Resources are shared between
   streams with the same parent stream, which means that if a stream in
   that set closes or becomes blocked, any spare capacity allocated to a
   stream is distributed to the immediate neighbors of the stream.
   However, if the common dependency is removed from the tree, those
   streams share resources with streams at the next highest level.

   For example, assume streams A and B share a parent, and streams C and
   D both depend on stream A.  Prior to the removal of stream A, if
   streams A and D are unable to proceed, then stream C receives all the
   resources dedicated to stream A.  If stream A is removed from the
   tree, the weight of stream A is divided between streams C and D.  If
   stream D is still unable to proceed, this results in stream C
   receiving a reduced proportion of resources.  For equal starting
   weights, C receives one third, rather than one half, of available
   resources.

   It is possible for a stream to become closed while prioritization
   information that creates a dependency on that stream is in transit.
   If a stream identified in a dependency has no associated priority
   information, then the dependent stream is instead assigned a default
   priority (Section 5.3.5).  This potentially creates suboptimal
   prioritization, since the stream could be given a priority that is
   different from what is intended.

   To avoid these problems, an endpoint SHOULD retain stream
   prioritization state for a period after streams become closed.  The
   longer state is retained, the lower the chance that streams are
   assigned incorrect or default priority values.

   Similarly, streams that are in the "idle" state can be assigned
   priority or become a parent of other streams.  This allows for the
   creation of a grouping node in the dependency tree, which enables
   more flexible expressions of priority.  Idle streams begin with a
   default priority (Section 5.3.5).

   The retention of priority information for streams that are not
   counted toward the limit set by SETTINGS_MAX_CONCURRENT_STREAMS could
   create a large state burden for an endpoint.  Therefore, the amount
   of prioritization state that is retained MAY be limited.

   The amount of additional state an endpoint maintains for
   prioritization could be dependent on load; under high load,
   prioritization state can be discarded to limit resource commitments.
   In extreme cases, an endpoint could even discard prioritization state
   for active or reserved streams.  If a limit is applied, endpoints
   SHOULD maintain state for at least as many streams as allowed by
   their setting for SETTINGS_MAX_CONCURRENT_STREAMS.  Implementations
   SHOULD also attempt to retain state for streams that are in active
   use in the priority tree.

   If it has retained enough state to do so, an endpoint receiving a
   PRIORITY frame that changes the priority of a closed stream SHOULD
   alter the dependencies of the streams that depend on it.

</code>
</pre>
</details>

#### 5.3.5 默认优先级

最初为所有流分配了对流0x0的非排他性依赖关系。推送的流（第8.2节）最初取决于它们的关联流。在这两种情况下，流均被分配默认权重16。

<details>
<summary>原文</summary>
<pre>
<code>

5.3.5.  Default Priorities

   All streams are initially assigned a non-exclusive dependency on
   stream 0x0.  Pushed streams (Section 8.2) initially depend on their
   associated stream.  In both cases, streams are assigned a default
   weight of 16.

</code>
</pre>
</details>

### 5.4 错误处理

HTTP/2帧允许两种错误：

- 使整个连接不可用的错误条件是连接错误。
- 单个流中的错误是流错误。

第7节中包含错误代码列表。

<details>
<summary>原文</summary>
<pre>
<code>

5.4.  Error Handling

   HTTP/2 framing permits two classes of error:

   o  An error condition that renders the entire connection unusable is
      a connection error.

   o  An error in an individual stream is a stream error.

   A list of error codes is included in Section 7.

</code>
</pre>
</details>

#### 5.4.1 连接错误处理

连接错误是指阻止帧层进一步处理或破坏任何连接状态的任何错误。

遇到连接错误的端点应首先发送一个`GOAWAY`帧（第6.8节），该帧带有从其成功接收到的最后一个流的流标识符同行。 `GOAWAY`帧包含一个错误代码，该错误代码指示为什么会终止连接。发送出现错误情况的`GOAWAY`帧后，端点必须关闭TCP连接。

接收端点可能无法可靠地接收`GOAWAY`（[RFC7230]，第6.6节描述了立即连接关闭如何导致数据丢失）。如果发生连接错误，`GOAWAY`只提供尽力尝试与对等方进行通信，说明终止连接的原因。

端点可以随时终止连接。特别是，端点可以选择将流错误视为连接错误。端点应在结束连接时发送`GOAWAY`帧，前提是情况允许。

<details>
<summary>原文</summary>
<pre>
<code>

5.4.1.  Connection Error Handling

   A connection error is any error that prevents further processing of
   the frame layer or corrupts any connection state.

   An endpoint that encounters a connection error SHOULD first send a
   GOAWAY frame (Section 6.8) with the stream identifier of the last
   stream that it successfully received from its peer.  The GOAWAY frame
   includes an error code that indicates why the connection is
   terminating.  After sending the GOAWAY frame for an error condition,
   the endpoint MUST close the TCP connection.

   It is possible that the GOAWAY will not be reliably received by the
   receiving endpoint ([RFC7230], Section 6.6 describes how an immediate
   connection close can result in data loss).  In the event of a
   connection error, GOAWAY only provides a best-effort attempt to
   communicate with the peer about why the connection is being
   terminated.

   An endpoint can end a connection at any time.  In particular, an
   endpoint MAY choose to treat a stream error as a connection error.
   Endpoints SHOULD send a GOAWAY frame when ending a connection,
   providing that circumstances permit it.

</code>
</pre>
</details>

#### 5.4.2 流错误处理

流错误是与不影响其他流处理的特定流相关的错误。

检测到流错误的端点发送`RST_STREAM`帧（第6.4节），该帧包含发生错误的流的流标识符。 `RST_STREAM`帧包含指示错误类型的错误代码。

`RST_STREAM`是端点可以在流上发送的最后一个帧。发送RST_STREAM帧的对等端必须准备好接收任何已发送或排队等待发送的帧。这些帧可以被忽略，除非它们修改了连接状态（例如为报头压缩（第4.3节）或流控制而维护的状态）。

通常，端点不应为任何流发送多个`RST_STREAM`帧。但是，如果端点在超过行程时间之后收到封闭流上的帧，则端点可以发送其他`RST_STREAM`帧。允许这种行为处理行为错误的实现。

为避免循环，端点不得发送`RST_STREAM`来响应`RST_STREAM`帧。

<details>
<summary>原文</summary>
<pre>
<code>

5.4.2.  Stream Error Handling

   A stream error is an error related to a specific stream that does not
   affect processing of other streams.

   An endpoint that detects a stream error sends a RST_STREAM frame
   (Section 6.4) that contains the stream identifier of the stream where
   the error occurred.  The RST_STREAM frame includes an error code that
   indicates the type of error.

   A RST_STREAM is the last frame that an endpoint can send on a stream.
   The peer that sends the RST_STREAM frame MUST be prepared to receive
   any frames that were sent or enqueued for sending by the remote peer.
   These frames can be ignored, except where they modify connection
   state (such as the state maintained for header compression
   (Section 4.3) or flow control).

   Normally, an endpoint SHOULD NOT send more than one RST_STREAM frame
   for any stream.  However, an endpoint MAY send additional RST_STREAM
   frames if it receives frames on a closed stream after more than a
   round-trip time.  This behavior is permitted to deal with misbehaving
   implementations.

   To avoid looping, an endpoint MUST NOT send a RST_STREAM in response
   to a RST_STREAM frame.

</code>
</pre>
</details>

#### 5.4.3 连接终止

如果在流保持`open`或`half-closed`状态的同时关闭或重置TCP连接，则无法自动重试受影响的流（有关详细信息，请参阅第8.1.4节）。


<details>
<summary>原文</summary>
<pre>
<code>

5.4.3.  Connection Termination

   If the TCP connection is closed or reset while streams remain in
   "open" or "half-closed" state, then the affected streams cannot be
   automatically retried (see Section 8.1.4 for details).

</code>
</pre>
</details>

### 5.5 扩展HTTP/2

HTTP/2允许扩展协议。在本节描述的限制内，协议扩展可用于提供其他服务或更改协议的任何方面。扩展仅在单个HTTP/2连接的范围内有效。

这适用于本文档中定义的协议元素。这不会影响扩展HTTP的现有选项，例如定义新方法，状态代码或标头字段。

扩展名允许使用新的帧类型（第4.1节），新设置（第6.5.2节）或新的错误代码（第7节）。建立用于管理这些扩展点的注册表：帧类型（第11.2节），设置（第11.3节）和错误代码（第11.4节）。

实现必须忽略所有可扩展协议元素中未知或不受支持的值。实现必须丢弃类型未知或不受支持的帧。这意味着这些扩展点中的任何一个都可以被扩展安全地使用，而无需事先安排或协商。但是，不允许出现在标头块中间的扩展帧（第4.3节）。这些必须被视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。

可能会更改现有协议组件语义的扩展必须在使用前进行协商。例如，无法更改`HEADERS`帧布局的扩展名，直到对等端发出肯定的信号表明可以接受为止。在这种情况下，可能还需要在建议的布局生效时进行协调。请注意，将除`DATA`帧以外的任何帧视为流控制是这种语义变化，只能通过协商来完成。

本文档未强制要求使用扩展名进行协商的特定方法，但请注意设置（第6.5.2节）可以用于该目的。如果两个对等方都设置了表示愿意使用该扩展名的值，则可以使用该扩展名。

如果将设置用于扩展协商，则必须以初始禁用扩展的方式定义初始值。

<details>
<summary>原文</summary>
<pre>
<code>

5.5.  Extending HTTP/2

   HTTP/2 permits extension of the protocol.  Within the limitations
   described in this section, protocol extensions can be used to provide
   additional services or alter any aspect of the protocol.  Extensions
   are effective only within the scope of a single HTTP/2 connection.

   This applies to the protocol elements defined in this document.  This
   does not affect the existing options for extending HTTP, such as
   defining new methods, status codes, or header fields.

   Extensions are permitted to use new frame types (Section 4.1), new
   settings (Section 6.5.2), or new error codes (Section 7).  Registries
   are established for managing these extension points: frame types
   (Section 11.2), settings (Section 11.3), and error codes
   (Section 11.4).

   Implementations MUST ignore unknown or unsupported values in all
   extensible protocol elements.  Implementations MUST discard frames
   that have unknown or unsupported types.  This means that any of these
   extension points can be safely used by extensions without prior
   arrangement or negotiation.  However, extension frames that appear in
   the middle of a header block (Section 4.3) are not permitted; these
   MUST be treated as a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.

   Extensions that could change the semantics of existing protocol
   components MUST be negotiated before being used.  For example, an
   extension that changes the layout of the HEADERS frame cannot be used
   until the peer has given a positive signal that this is acceptable.
   In this case, it could also be necessary to coordinate when the
   revised layout comes into effect.  Note that treating any frames
   other than DATA frames as flow controlled is such a change in
   semantics and can only be done through negotiation.

   This document doesn't mandate a specific method for negotiating the
   use of an extension but notes that a setting (Section 6.5.2) could be
   used for that purpose.  If both peers set a value that indicates
   willingness to use the extension, then the extension can be used.  If

   a setting is used for extension negotiation, the initial value MUST
   be defined in such a fashion that the extension is initially
   disabled.

</code>
</pre>
</details>

## 6. 帧定义

本规范定义了许多帧类型，每种类型均由唯一的8位类型代码标识。每种帧类型在整个连接或单个流的建立和管理中都有不同的用途。

特定帧类型的传输可以更改连接的状态。如果端点无法维持连接状态的同步视图，则将无法再成功进行连接内的通信。因此，重要的一点是，端点必须对状态如何受到给定帧的使用产生共同的理解。

<details>
<summary>原文</summary>
<pre>
<code>

6.  Frame Definitions

   This specification defines a number of frame types, each identified
   by a unique 8-bit type code.  Each frame type serves a distinct
   purpose in the establishment and management either of the connection
   as a whole or of individual streams.

   The transmission of specific frame types can alter the state of a
   connection.  If endpoints fail to maintain a synchronized view of the
   connection state, successful communication within the connection will
   no longer be possible.  Therefore, it is important that endpoints
   have a shared comprehension of how the state is affected by the use
   any given frame.

</code>
</pre>
</details>

### 6.1 DATA

DATA帧（类型=0x0）传达与流相关的任意可变长度的八位字节序列。例如，一个或多个DATA帧用于承载HTTP请求或响应有效负载。

DATA帧还可以包含填充。可以将填充添加到DATA帧中以掩盖消息的大小。填充是一种安全功能；参见10.7节。

```
    +---------------+
    |Pad Length? (8)|
    +---------------+-----------------------------------------------+
    |                            Data (*)                         ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+

                       Figure 6: DATA Frame Payload
```

DATA帧包含以下字段：

  - 填充长度(Pad Length)：8位字段，包含以八位字节为单位的帧填充的长度。该字段是有条件的（在图中用`?`表示），仅当设置了`PADDED`标志时才存在。
  - 数据(Data)：应用程序数据。数据量是减去存在的其他字段的长度后剩余的帧有效负载。
  - 填充(Padding)：不包含应用程序语义值的填充八位字节。发送时，填充八位字节必须设置为零。接收者没有义务验证填充，但是可以将非零填充视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。

DATA帧定义以下标志：

  - END_STREAM (0x1): 置位时，位0指示该帧是端点将向所标识的流发送的最后一个帧。设置该标志会使流进入`half-closed`或`closed`状态（第5.1节）- PADDED (0x8): 设置后，位3指示“填充长度”字段及其描述的任何填充都存在。

DATA帧必须与流关联。如果接收到一个其流标识符字段为0x0的DATA帧，则接收者必须以`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）进行响应。

数据帧受流量控制，并且仅在流处于`open`或`half-closed (remote)`状态时才能发送。整个DATA帧有效负载都包含在流控制中，包括`Pad Length`和`Padding`字段（如果存在）。如果接收到的DATA帧的流不处于`open`或`half-closed (local)`状态，则接收方务必以`STREAM_CLOSED`类型的流错误（第5.4.2节）做出响应。

填充字节的总数由`Pad Length`字段的值确定。如果填充的长度是帧有效载荷的长度或更大，则接收者必须将此视为`PROTOCOL_ERROR`类型的连接错误（5.4.1节）。

  注意：通过包含值为零的`Pad Length`字段，可以将帧的大小增加一个八位位组。

<details>
<summary>原文</summary>
<pre>
<code>

6.1.  DATA

   DATA frames (type=0x0) convey arbitrary, variable-length sequences of
   octets associated with a stream.  One or more DATA frames are used,
   for instance, to carry HTTP request or response payloads.

   DATA frames MAY also contain padding.  Padding can be added to DATA
   frames to obscure the size of messages.  Padding is a security
   feature; see Section 10.7.

    +---------------+
    |Pad Length? (8)|
    +---------------+-----------------------------------------------+
    |                            Data (*)                         ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+

                       Figure 6: DATA Frame Payload

   The DATA frame contains the following fields:

   Pad Length:  An 8-bit field containing the length of the frame
      padding in units of octets.  This field is conditional (as
      signified by a "?" in the diagram) and is only present if the
      PADDED flag is set.

   Data:  Application data.  The amount of data is the remainder of the
      frame payload after subtracting the length of the other fields
      that are present.

   Padding:  Padding octets that contain no application semantic value.
      Padding octets MUST be set to zero when sending.  A receiver is
      not obligated to verify padding but MAY treat non-zero padding as
      a connection error (Section 5.4.1) of type PROTOCOL_ERROR.

   The DATA frame defines the following flags:

   END_STREAM (0x1):  When set, bit 0 indicates that this frame is the
      last that the endpoint will send for the identified stream.
      Setting this flag causes the stream to enter one of the "half-
      closed" states or the "closed" state (Section 5.1).

   PADDED (0x8):  When set, bit 3 indicates that the Pad Length field
      and any padding that it describes are present.

   DATA frames MUST be associated with a stream.  If a DATA frame is
   received whose stream identifier field is 0x0, the recipient MUST
   respond with a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.

   DATA frames are subject to flow control and can only be sent when a
   stream is in the "open" or "half-closed (remote)" state.  The entire
   DATA frame payload is included in flow control, including the Pad
   Length and Padding fields if present.  If a DATA frame is received
   whose stream is not in "open" or "half-closed (local)" state, the
   recipient MUST respond with a stream error (Section 5.4.2) of type
   STREAM_CLOSED.

   The total number of padding octets is determined by the value of the
   Pad Length field.  If the length of the padding is the length of the
   frame payload or greater, the recipient MUST treat this as a
   connection error (Section 5.4.1) of type PROTOCOL_ERROR.

      Note: A frame can be increased in size by one octet by including a
      Pad Length field with a value of zero.

</code>
</pre>
</details>

### 6.2 HEADERS

HEADERS帧（类型=0x1）用于打开流（第5.1节），并附加一个header块片段。可以在`idle`、`reserved(local)`、`open`或`half-closed(remot)`状态下在流上发送HEADERS帧。

```
    +---------------+
    |Pad Length? (8)|
    +-+-------------+-----------------------------------------------+
    |E|                 Stream Dependency? (31)                     |
    +-+-------------+-----------------------------------------------+
    |  Weight? (8)  |
    +-+-------------+-----------------------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+

                      Figure 7: HEADERS Frame Payload
```

HEADERS帧有效载荷具有以下字段：

  - Pad Length：一个8位字段，包含以八位字节为单位的帧填充长度。仅当设置了`PADDED`标志时，此字段才存在。
  - E：一位标志，指示流依赖性是排他性的（请参阅第5.3节）。仅当设置了`PRIORITY`标志时，此字段才存在。
  - Stream Dependency：此流所依赖的流的31位流标识符（请参阅第5.3节）。仅当设置了`PRIORITY`标志时，此字段才存在。
  - Weight：表示流优先级权重的无符号8位整数（请参阅第5.3节）。将值加1以获得介于1和256之间的权重。仅当设置了`PRIORITY`标志时，才显示此字段。
  - Header Block Fragment：标头块片段（第4.3节）。
  - Padding：填充八位字节。 

HEADERS帧定义以下标志：
  - END_STREAM（0x1）：设置后，位0指示标头块（第4.3节）是端点将向标识流发送的最后一个块。 
    HEADERS帧带有`END_STREAM`标志，该标志指示流的结尾。但是，设置了`END_STREAM`标志的HEADERS帧之后可以是同一流上的CONTINUATION帧。从逻辑上讲，CONTINUATION帧是HEADERS帧的一部分。
  - END_HEADERS（0x4）：置位时，位2指示该帧包含整个标题块（第4.3节），并且之后没有任何CONTINUATION帧。
    没有设置`END_HEADERS`标志的HEADERS帧之后必须是同一流的CONTINUATION帧。接收者必须将接收到的任何其他类型的帧或不同流上的帧视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）
  - PADDED（0x8）：置位时，第3位指示`Pad Length`字段以及任何存在它描述的填充。
  - PRIORITY（0x20）：置位时，位5表示存在独占标志（E），流相关性和权重字段；参见第5.3节。 
  
HEADERS帧的有效载荷包含一个头块片段（第4.3节）。不适合HEADERS框架的标题块在CONTINUATION框架中继续（第6.10节）。

HEADERS帧必须与流关联。如果收到的HEADERS帧的流标识符字段为0x0，则接收者务必以`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）进行响应。 

HEADERS帧如第4.3节所述更改连接状态。 

HEADERS框架可以包含填充。填充字段和标志与为DATA帧定义的填充字段和标志相同（第6.1节）。超出标题块片段剩余大小的填充必须被视为`PROTOCOL_ERROR`。

HEADERS帧中的优先级信息在逻辑上等效于单独的PRIORITY帧，但是包含在HEADERS中避免了在创建新流时流优先级流失的可能性。在第一个流之后的HEADERS帧中的优先级字段将对流进行优先级排序（第5.3.3节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.2.  HEADERS

   The HEADERS frame (type=0x1) is used to open a stream (Section 5.1),
   and additionally carries a header block fragment.  HEADERS frames can
   be sent on a stream in the "idle", "reserved (local)", "open", or
   "half-closed (remote)" state.

    +---------------+
    |Pad Length? (8)|
    +-+-------------+-----------------------------------------------+
    |E|                 Stream Dependency? (31)                     |
    +-+-------------+-----------------------------------------------+
    |  Weight? (8)  |
    +-+-------------+-----------------------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+

                      Figure 7: HEADERS Frame Payload

   The HEADERS frame payload has the following fields:

   Pad Length:  An 8-bit field containing the length of the frame
      padding in units of octets.  This field is only present if the
      PADDED flag is set.

   E: A single-bit flag indicating that the stream dependency is
      exclusive (see Section 5.3).  This field is only present if the
      PRIORITY flag is set.

   Stream Dependency:  A 31-bit stream identifier for the stream that
      this stream depends on (see Section 5.3).  This field is only
      present if the PRIORITY flag is set.

   Weight:  An unsigned 8-bit integer representing a priority weight for
      the stream (see Section 5.3).  Add one to the value to obtain a
      weight between 1 and 256.  This field is only present if the
      PRIORITY flag is set.

   Header Block Fragment:  A header block fragment (Section 4.3).

   Padding:  Padding octets.

   The HEADERS frame defines the following flags:

   END_STREAM (0x1):  When set, bit 0 indicates that the header block
      (Section 4.3) is the last that the endpoint will send for the
      identified stream.

      A HEADERS frame carries the END_STREAM flag that signals the end
      of a stream.  However, a HEADERS frame with the END_STREAM flag
      set can be followed by CONTINUATION frames on the same stream.
      Logically, the CONTINUATION frames are part of the HEADERS frame.

   END_HEADERS (0x4):  When set, bit 2 indicates that this frame
      contains an entire header block (Section 4.3) and is not followed
      by any CONTINUATION frames.

      A HEADERS frame without the END_HEADERS flag set MUST be followed
      by a CONTINUATION frame for the same stream.  A receiver MUST
      treat the receipt of any other type of frame or a frame on a
      different stream as a connection error (Section 5.4.1) of type
      PROTOCOL_ERROR.

   PADDED (0x8):  When set, bit 3 indicates that the Pad Length field
      and any padding that it describes are present.

   PRIORITY (0x20):  When set, bit 5 indicates that the Exclusive Flag
      (E), Stream Dependency, and Weight fields are present; see
      Section 5.3.

   The payload of a HEADERS frame contains a header block fragment
   (Section 4.3).  A header block that does not fit within a HEADERS
   frame is continued in a CONTINUATION frame (Section 6.10).

   HEADERS frames MUST be associated with a stream.  If a HEADERS frame
   is received whose stream identifier field is 0x0, the recipient MUST
   respond with a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.

   The HEADERS frame changes the connection state as described in
   Section 4.3.

   The HEADERS frame can include padding.  Padding fields and flags are
   identical to those defined for DATA frames (Section 6.1).  Padding
   that exceeds the size remaining for the header block fragment MUST be
   treated as a PROTOCOL_ERROR.

   Prioritization information in a HEADERS frame is logically equivalent
   to a separate PRIORITY frame, but inclusion in HEADERS avoids the
   potential for churn in stream prioritization when new streams are
   created.  Prioritization fields in HEADERS frames subsequent to the
   first on a stream reprioritize the stream (Section 5.3.3).

</code>
</pre>
</details>

### 6.3 PRIORITY

PRIORITY帧（类型=0x2）指定发送方建议的流优先级（第5.3节）。它可以以任何流状态发送，包括`idle`或`closed`的流。

```
    +-+-------------------------------------------------------------+
    |E|                  Stream Dependency (31)                     |
    +-+-------------+-----------------------------------------------+
    |   Weight (8)  |
    +-+-------------+

                     Figure 8: PRIORITY Frame Payload

```

PRIORITY帧的有效负载包含以下字段：

  - E：一位标志，指示流依赖性是非排他性的（请参阅第5.3节）。
  - Stream Dependency: 此流所依赖的流的31位流标识符（请参阅第5.3节）。
  - Weight: 表示流优先级权重的无符号8位整数（请参阅第5.3节）。将值加1可获得1到256之间的权重。

PRIORITY帧未定义任何标志。 

PRIORITY帧始终标识流。如果收到一个流标识符为0x0的PRIORITY帧，则接收者务必以`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）进行响应。

尽管不能在包含单头块的连续帧之间发送PRIORITY帧，但它可以在任何状态下在流上发送（第4.3节）。请注意，该帧可能在处理后或到达帧发送完成后到达，这将导致它对标识的流没有影响。对于处于`half-closed(remote)`或`closed`状态的流，此帧只能影响所标识的流及其从属流的处理；它不会影响该流上的帧传输。

可以为处于`idle`或`closed`状态的流发送优先级帧。这允许通过更改未使用或关闭的父流的优先级来重新设置一组依赖流的优先级。

长度非5个八位位组的PRIORITY帧必须被视为`FRAME_SIZE_ERROR`类型的流错误（第5.4.2节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.3.  PRIORITY

   The PRIORITY frame (type=0x2) specifies the sender-advised priority
   of a stream (Section 5.3).  It can be sent in any stream state,
   including idle or closed streams.

    +-+-------------------------------------------------------------+
    |E|                  Stream Dependency (31)                     |
    +-+-------------+-----------------------------------------------+
    |   Weight (8)  |
    +-+-------------+

                     Figure 8: PRIORITY Frame Payload

   The payload of a PRIORITY frame contains the following fields:

   E: A single-bit flag indicating that the stream dependency is
      exclusive (see Section 5.3).

   Stream Dependency:  A 31-bit stream identifier for the stream that
      this stream depends on (see Section 5.3).

   Weight:  An unsigned 8-bit integer representing a priority weight for
      the stream (see Section 5.3).  Add one to the value to obtain a
      weight between 1 and 256.

   The PRIORITY frame does not define any flags.

   The PRIORITY frame always identifies a stream.  If a PRIORITY frame
   is received with a stream identifier of 0x0, the recipient MUST
   respond with a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.

   The PRIORITY frame can be sent on a stream in any state, though it
   cannot be sent between consecutive frames that comprise a single
   header block (Section 4.3).  Note that this frame could arrive after
   processing or frame sending has completed, which would cause it to
   have no effect on the identified stream.  For a stream that is in the
   "half-closed (remote)" or "closed" state, this frame can only affect
   processing of the identified stream and its dependent streams; it
   does not affect frame transmission on that stream.

   The PRIORITY frame can be sent for a stream in the "idle" or "closed"
   state.  This allows for the reprioritization of a group of dependent
   streams by altering the priority of an unused or closed parent
   stream.

   A PRIORITY frame with a length other than 5 octets MUST be treated as
   a stream error (Section 5.4.2) of type FRAME_SIZE_ERROR.

</code>
</pre>
</details>

### 6.4 RST_STREAM

RST_STREAM帧（类型=0x3）允许立即终止流。发送RST_STREAM以请求取消流或指示发生了错误情况。

```
    +---------------------------------------------------------------+
    |                        Error Code (32)                        |
    +---------------------------------------------------------------+

                    Figure 9: RST_STREAM Frame Payload
```

RST_STREAM帧包含一个唯一的无符号32位整数，用于标识错误代码（第7节）。错误代码指示为什么终止流。 

RST_STREAM帧未定义任何标志。 RST_STREAM帧完全终止引用的流，并使其进入`closed`状态。流在接收到RST_STREAM之后，接收者必须不发送该流的其他帧，但`PRIORITY`帧除外。但是，在发送了RST_STREAM之后，发送端点必须准备好接收和处理在流上发送的其他帧，这些帧可能是在RST_STREAM到达之前由对等方发送的。

RST_STREAM帧必须与流关联。如果接收到流标识符为0x0的RST_STREAM帧，则接收者必须将其视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。 

RST_STREAM帧不得以`idle`状态发送给流。如果接收到标识空闲流的RST_STREAM帧，则接收方必须将此视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。

长度非4个八位位组的RST_STREAM帧必须被视为`FRAME_SIZE_ERROR`类型的连接错误（第5.4.1节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.4.  RST_STREAM

   The RST_STREAM frame (type=0x3) allows for immediate termination of a
   stream.  RST_STREAM is sent to request cancellation of a stream or to
   indicate that an error condition has occurred.

    +---------------------------------------------------------------+
    |                        Error Code (32)                        |
    +---------------------------------------------------------------+

                    Figure 9: RST_STREAM Frame Payload

   The RST_STREAM frame contains a single unsigned, 32-bit integer
   identifying the error code (Section 7).  The error code indicates why
   the stream is being terminated.

   The RST_STREAM frame does not define any flags.

   The RST_STREAM frame fully terminates the referenced stream and
   causes it to enter the "closed" state.  After receiving a RST_STREAM
   on a stream, the receiver MUST NOT send additional frames for that
   stream, with the exception of PRIORITY.  However, after sending the
   RST_STREAM, the sending endpoint MUST be prepared to receive and
   process additional frames sent on the stream that might have been
   sent by the peer prior to the arrival of the RST_STREAM.

   RST_STREAM frames MUST be associated with a stream.  If a RST_STREAM
   frame is received with a stream identifier of 0x0, the recipient MUST
   treat this as a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.

   RST_STREAM frames MUST NOT be sent for a stream in the "idle" state.
   If a RST_STREAM frame identifying an idle stream is received, the
   recipient MUST treat this as a connection error (Section 5.4.1) of
   type PROTOCOL_ERROR.

   A RST_STREAM frame with a length other than 4 octets MUST be treated
   as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.

</code>
</pre>
</details>

### 6.5 SETTINGS

SETTINGS帧（类型=0x4）传达影响端点通信方式的配置参数，例如，对等方行为的偏好和约束。 SETTINGS帧也用于确认那些参数的接收。单独地，SETTINGS参数也可以称为`setting`。

它们描述了发送方的特征，接收方使用这些特征。每个对等体可以通告相同参数的不同值。例如，客户端可能会设置较高的初始流控制窗口，而服务器可能会设置较低的值以节省资源。

SETTINGS帧必须在连接开始时由两个端点发送，并且可以在任何其他时间由任一端点发送连接的整个生命周期内的端点。实现必须支持该规范定义的所有参数。

SETTINGS帧中的每个参数都将替换该参数的任何现有值。参数按照它们出现的顺序进行处理，并且SETTINGS帧的接收者不需要维护其参数当前值以外的任何状态。因此，SETTINGS参数的值是areceiver看到的最后一个值。

SETTINGS参数被接收对等方确认。要启用此功能，SETTINGS帧定义以下标志：

  - ACK（0x1）：设置后，位0指示此帧确认对等方SETTINGS帧的接收和应用。设置此位后，SETTINGS帧的有效载荷必须为空。接收到设置了ACK标志且长度字段值不为0的SETTINGS帧，必须将其视为FRAME_SIZE_ERROR类型的连接错误（第5.4.1节）。有关更多信息，请参见第6.5.3节（“设置同步”）。
  
SETTINGS帧始终应用于连接，而不是单个流。SETTINGS帧的流标识符必须为零（0x0）。如果端点接收到流标识符字段不是0x0的SETTINGS帧，则端点必须以`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）进行响应。

SETTINGS帧影响连接状态。格式错误或不完整的SETTINGS帧必须视为`PROTOCOL_ERROR`类型的连接错误（第5.4.1节）。

长度除6个八位位组的倍数以外的SETTINGS帧必须视为`FRAME_SIZE_ERROR`类型的连接错误（5.4.1节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.5.  SETTINGS

   The SETTINGS frame (type=0x4) conveys configuration parameters that
   affect how endpoints communicate, such as preferences and constraints
   on peer behavior.  The SETTINGS frame is also used to acknowledge the
   receipt of those parameters.  Individually, a SETTINGS parameter can
   also be referred to as a "setting".

   SETTINGS parameters are not negotiated; they describe characteristics
   of the sending peer, which are used by the receiving peer.  Different
   values for the same parameter can be advertised by each peer.  For
   example, a client might set a high initial flow-control window,
   whereas a server might set a lower value to conserve resources.

   A SETTINGS frame MUST be sent by both endpoints at the start of a
   connection and MAY be sent at any other time by either endpoint over
   the lifetime of the connection.  Implementations MUST support all of
   the parameters defined by this specification.

   Each parameter in a SETTINGS frame replaces any existing value for
   that parameter.  Parameters are processed in the order in which they
   appear, and a receiver of a SETTINGS frame does not need to maintain
   any state other than the current value of its parameters.  Therefore,
   the value of a SETTINGS parameter is the last value that is seen by a
   receiver.

   SETTINGS parameters are acknowledged by the receiving peer.  To
   enable this, the SETTINGS frame defines the following flag:

   ACK (0x1):  When set, bit 0 indicates that this frame acknowledges
      receipt and application of the peer's SETTINGS frame.  When this
      bit is set, the payload of the SETTINGS frame MUST be empty.
      Receipt of a SETTINGS frame with the ACK flag set and a length
      field value other than 0 MUST be treated as a connection error
      (Section 5.4.1) of type FRAME_SIZE_ERROR.  For more information,
      see Section 6.5.3 ("Settings Synchronization").

   SETTINGS frames always apply to a connection, never a single stream.
   The stream identifier for a SETTINGS frame MUST be zero (0x0).  If an
   endpoint receives a SETTINGS frame whose stream identifier field is
   anything other than 0x0, the endpoint MUST respond with a connection
   error (Section 5.4.1) of type PROTOCOL_ERROR.

   The SETTINGS frame affects connection state.  A badly formed or
   incomplete SETTINGS frame MUST be treated as a connection error
   (Section 5.4.1) of type PROTOCOL_ERROR.

   A SETTINGS frame with a length other than a multiple of 6 octets MUST
   be treated as a connection error (Section 5.4.1) of type
   FRAME_SIZE_ERROR.

</code>
</pre>
</details>

#### 6.5.1 SETTINGS格式

SETTINGS帧的有效载荷由零个或多个参数组成，每个参数由一个无符号的16位设置标识符和一个无符号的32位值组成。

```
    +-------------------------------+
    |       Identifier (16)         |
    +-------------------------------+-------------------------------+
    |                        Value (32)                             |
    +---------------------------------------------------------------+

                         Figure 10: Setting Format
```

<details>
<summary>原文</summary>
<pre>
<code>


6.5.1.  SETTINGS Format

   The payload of a SETTINGS frame consists of zero or more parameters,
   each consisting of an unsigned 16-bit setting identifier and an
   unsigned 32-bit value.

    +-------------------------------+
    |       Identifier (16)         |
    +-------------------------------+-------------------------------+
    |                        Value (32)                             |
    +---------------------------------------------------------------+

                         Figure 10: Setting Format

</code>
</pre>
</details>

#### 6.5.2 定义SETTINGS参数

定义了以下参数：
  - SETTINGS_HEADER_TABLE_SIZE（0x1）：允许发送方以字节为单位，通知远程端点用于解码标头块的标头压缩表的最大大小。编码器可以通过使用特定于前端块内标头压缩格式的信号来选择等于或小于此值的任何大小（请参阅[COMPRESSION]）。初始值为4,096个八位位组。
  - SETTINGS_ENABLE_PUSH（0x2）：此设置可用于禁用服务器推送（第8.2节）。如果端点接收到此参数设置为0，则不得发送PUSH_PROMISE帧。既已将此参数都设置为0且已被确认的端点必须将PUSH_PROMISE帧的接收视为PROTOCOL_ERROR类型的连接错误（第5.4.1节）。
  初始值为1，表示允许服务器推送。除0或1以外的任何值都必须被视为类型为PROTOCOL_ERROR。
  - SETTINGS_MAX_CONCURRENT_STREAMS（0x3）的连接错误（第5.4.1节）：指示发送方允许的最大并发流数。此限制是有方向的：它适用于发送方允许接收方创建的流的数量。最初，此值没有限制。建议该值不小于100，以免不必要地限制并行度。端点不应将SETTINGS_MAX_CONCURRENT_STREAMS的0值视为特殊值。零值的确会阻止创建新的流。但是，对于活动流耗尽的任何限制也可能发生这种情况。服务器应仅在短时间内设置零值；如果服务器不希望接受请求，则更合适的方法是关闭连接。
  - SETTINGS_INITIAL_WINDOW_SIZE（0x4）：指示发送方的初始窗口大小（以八位字节为单位），用于流级别的流控制。初始值为2^16-1（65,535）个八位位组。此设置影响所有流的窗口大小（请参见6.9.2节）。大于最大流控制窗口大小2^31-1的值必须视为FLOW_CONTROL_ERROR类型的连接错误（第5.4.1节）。
  - SETTINGS_MAX_FRAME_SIZE（0x5）：指示发送方愿意的最大帧有效负载的大小以八位位组接收。初始值为2^14（16,384）个八位位组。端点通告的值必须在此初始值和允许的最大帧大小（2 ^ 24-1或16,777,215个八位位组）之间（包括此值）。超出此范围的值必须视为类型为PROTOCOL_ERROR的连接错误（第5.4.1节）。
  - SETTINGS_MAX_HEADER_LIST_SIZE（0x6）：此建议设置通知发送方准备接受的报头列表的最大大小（八位字节）。该值基于标题字段的未压缩大小，包括名称的长度和以八位字节为单位的值，以及每个标题字段的32个八位字节的开销。
  对于任何给定的请求，可以强制执行比所公布的更低的限制。此设置的初始值是无限的。
  
接收到带有任何未知或不受支持的标识符的SETTINGS帧的端点必须忽略该设置。

<details>
<summary>原文</summary>
<pre>
<code>

6.5.2.  Defined SETTINGS Parameters

   The following parameters are defined:

   SETTINGS_HEADER_TABLE_SIZE (0x1):  Allows the sender to inform the
      remote endpoint of the maximum size of the header compression
      table used to decode header blocks, in octets.  The encoder can
      select any size equal to or less than this value by using
      signaling specific to the header compression format inside a
      header block (see [COMPRESSION]).  The initial value is 4,096
      octets.

   SETTINGS_ENABLE_PUSH (0x2):  This setting can be used to disable
      server push (Section 8.2).  An endpoint MUST NOT send a
      PUSH_PROMISE frame if it receives this parameter set to a value of
      0.  An endpoint that has both set this parameter to 0 and had it
      acknowledged MUST treat the receipt of a PUSH_PROMISE frame as a
      connection error (Section 5.4.1) of type PROTOCOL_ERROR.

      The initial value is 1, which indicates that server push is
      permitted.  Any value other than 0 or 1 MUST be treated as a
      connection error (Section 5.4.1) of type PROTOCOL_ERROR.

   SETTINGS_MAX_CONCURRENT_STREAMS (0x3):  Indicates the maximum number
      of concurrent streams that the sender will allow.  This limit is
      directional: it applies to the number of streams that the sender
      permits the receiver to create.  Initially, there is no limit to
      this value.  It is recommended that this value be no smaller than
      100, so as to not unnecessarily limit parallelism.

      A value of 0 for SETTINGS_MAX_CONCURRENT_STREAMS SHOULD NOT be
      treated as special by endpoints.  A zero value does prevent the
      creation of new streams; however, this can also happen for any
      limit that is exhausted with active streams.  Servers SHOULD only
      set a zero value for short durations; if a server does not wish to
      accept requests, closing the connection is more appropriate.

   SETTINGS_INITIAL_WINDOW_SIZE (0x4):  Indicates the sender's initial
      window size (in octets) for stream-level flow control.  The
      initial value is 2^16-1 (65,535) octets.

      This setting affects the window size of all streams (see
      Section 6.9.2).

      Values above the maximum flow-control window size of 2^31-1 MUST
      be treated as a connection error (Section 5.4.1) of type
      FLOW_CONTROL_ERROR.

   SETTINGS_MAX_FRAME_SIZE (0x5):  Indicates the size of the largest
      frame payload that the sender is willing to receive, in octets.

      The initial value is 2^14 (16,384) octets.  The value advertised
      by an endpoint MUST be between this initial value and the maximum
      allowed frame size (2^24-1 or 16,777,215 octets), inclusive.
      Values outside this range MUST be treated as a connection error
      (Section 5.4.1) of type PROTOCOL_ERROR.

   SETTINGS_MAX_HEADER_LIST_SIZE (0x6):  This advisory setting informs a
      peer of the maximum size of header list that the sender is
      prepared to accept, in octets.  The value is based on the
      uncompressed size of header fields, including the length of the
      name and value in octets plus an overhead of 32 octets for each
      header field.

      For any given request, a lower limit than what is advertised MAY
      be enforced.  The initial value of this setting is unlimited.

   An endpoint that receives a SETTINGS frame with any unknown or
   unsupported identifier MUST ignore that setting.

</code>
</pre>
</details>

#### 6.5.3 设置同步

SETTINGS中的大多数值受益于或需要了解对等方何时接收并应用更改后的参数值。为了提供此类同步时间点，未设置ACK标志的SETTINGS帧的接收者必须尽快应用更新的参数。

SETTINGS帧中的值必须按照它们出现的顺序进行处理，而各值之间不得进行其他帧处理。不支持的参数必须被忽略。一旦处理完所有值，接收方必须立即发出带有ACK标志集的SETTINGS帧。收到设置了ACK标志的SETTINGS帧后，更改的参数的发送者可以依赖于已应用的设置。

如果SETTINGS帧的发送者在合理的时间内未收到确认，则可能会发出连接错误（本节5.4.1）类型的SETTINGS_TIMEOUT。

<details>
<summary>原文</summary>
<pre>
<code>

6.5.3.  Settings Synchronization

   Most values in SETTINGS benefit from or require an understanding of
   when the peer has received and applied the changed parameter values.
   In order to provide such synchronization timepoints, the recipient of
   a SETTINGS frame in which the ACK flag is not set MUST apply the
   updated parameters as soon as possible upon receipt.

   The values in the SETTINGS frame MUST be processed in the order they
   appear, with no other frame processing between values.  Unsupported
   parameters MUST be ignored.  Once all values have been processed, the
   recipient MUST immediately emit a SETTINGS frame with the ACK flag
   set.  Upon receiving a SETTINGS frame with the ACK flag set, the
   sender of the altered parameters can rely on the setting having been
   applied.

   If the sender of a SETTINGS frame does not receive an acknowledgement
   within a reasonable amount of time, it MAY issue a connection error
   (Section 5.4.1) of type SETTINGS_TIMEOUT.

</code>
</pre>
</details>

### 6.6 PUSH_PROMISE

PUSH_PROMISE帧（类型=0x5）用于在发送方打算初始化的流之前提前通知对等终结点。 PUSH_PROMISE帧包括端点计划创建的流的无符号31位标识符，以及为流提供其他上下文的一组报头。 8.2节详细介绍了PUSH_PROMISE帧的使用。

```
    +---------------+
    |Pad Length? (8)|
    +-+-------------+-----------------------------------------------+
    |R|                  Promised Stream ID (31)                    |
    +-+-----------------------------+-------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+

                  Figure 11: PUSH_PROMISE Payload Format
```

PUSH_PROMISE帧有效载荷具有以下字段：

  - Pad Length：一个8位字段，包含以八位字节为单位的帧填充长度。仅当设置了PADDED标志时，此字段才存在。
  - R：单个保留位。
  - Promised Stream ID: 一个无符号的31位整数，用于标识PUSH_PROMISE保留的流。承诺的流标识符必须是发送方发送的下一个流的有效选择（请参阅第5.1.1节中的“新流标识符”）。
  - Header Block Fragment：包含请求标头字段的标头块片段（第4.3节）。
  - Padding：填充八位字节。
  
PUSH_PROMISE帧定义以下标志：
  - END_HEADERS（0x4）：置位时，位2指示该帧包含整个标题块（第4.3节），并且之后没有任何CONTINUATION帧。没有设置END_HEADERS标志的PUSH_PROMISE帧之后必须是同一流的CONTINUATION帧。接收者必须将接收到的任何其他类型的帧或不同流上的帧视为PROTOCOL_ERROR类型的连接错误（第5.4.1节）
  - PADDED（0x8）：置位时，第3位指示Pad Length字段以及任何存在它描述的填充。 
  
PUSH_PROMISE帧只能在处于`open`或`half-close(remote)`状态的对等方发起的流上发送。 PUSH_PROMISE帧的流标识符指示与其关联的流。如果流标识符字段指定值为0x0，则接收者务必以PROTOCOL_ERROR类型的连接错误（第5.4.1节）进行响应。

不需要按承诺的顺序使用承诺的流。 PUSH_PROMISE仅保留流标识符供以后使用。如果对等端点的SETTINGS_ENABLE_PUSH设置设为0，则不得发送PUSH_PROMISE。已设置此设置并已收到确认的端点必须将PUSH_PROMISE帧的接收视为PROTOCOL_ERROR类型的连接错误（第5.4.1节）。

PUSH_PROMISE帧的接收者可以选择返回RST_STREAM，将RST的流标识符返回给PUSH_PROMISE的发送者，从而拒绝承诺的流。 

PUSH_PROMISE帧以两种方式修改连接状态。首先，包含头块（第4.3节）可能会修改为头压缩而维护的状态。其次，PUSH_PROMISE还保留了一个流供以后使用，从而使承诺的流进入`reserved`状态。发送者不得在流上发送PUSH_PROMISE，除非该流是`open`或`half-closed (remote)`；发送方必须确保承诺流是新流标识符的有效选择（第5.1.1节）（也就是说，承诺流必须处于“空闲”状态）。

由于PUSH_PROMISE保留流，因此忽略PUSH_PROMISE帧会导致流状态变得不确定。接收者必须处理既不是“开放”也不是“半封闭（本地）”的流上的PUSH_PROMISE接收，作为PROTOCOL_ERROR类型的连接错误（第5.4.1节）。但是，在相关流上发送了RST_STREAM的端点必须处理在接收和处理RST_STREAM帧之前可能已经创建的PUSH_PROMISE帧。

接收者必须将收到的PUSH_PROMISE视为允诺将非法流标识符（第5.1.1节）视为PROTOCOL_ERROR类型的连接错误（第5.4.1节）。注意，非法的流标识符是当前不处于“空闲”状态的流的标识符。 

PUSH_PROMISE帧可以包含填充。填充字段和标志与为DATA帧定义的填充字段和标志相同（第6.1节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.6.  PUSH_PROMISE

   The PUSH_PROMISE frame (type=0x5) is used to notify the peer endpoint
   in advance of streams the sender intends to initiate.  The
   PUSH_PROMISE frame includes the unsigned 31-bit identifier of the
   stream the endpoint plans to create along with a set of headers that
   provide additional context for the stream.  Section 8.2 contains a
   thorough description of the use of PUSH_PROMISE frames.

    +---------------+
    |Pad Length? (8)|
    +-+-------------+-----------------------------------------------+
    |R|                  Promised Stream ID (31)                    |
    +-+-----------------------------+-------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+

                  Figure 11: PUSH_PROMISE Payload Format

   The PUSH_PROMISE frame payload has the following fields:

   Pad Length:  An 8-bit field containing the length of the frame
      padding in units of octets.  This field is only present if the
      PADDED flag is set.

   R: A single reserved bit.

   Promised Stream ID:  An unsigned 31-bit integer that identifies the
      stream that is reserved by the PUSH_PROMISE.  The promised stream
      identifier MUST be a valid choice for the next stream sent by the
      sender (see "new stream identifier" in Section 5.1.1).

   Header Block Fragment:  A header block fragment (Section 4.3)
      containing request header fields.

   Padding:  Padding octets.

   The PUSH_PROMISE frame defines the following flags:

   END_HEADERS (0x4):  When set, bit 2 indicates that this frame
      contains an entire header block (Section 4.3) and is not followed
      by any CONTINUATION frames.

      A PUSH_PROMISE frame without the END_HEADERS flag set MUST be
      followed by a CONTINUATION frame for the same stream.  A receiver
      MUST treat the receipt of any other type of frame or a frame on a
      different stream as a connection error (Section 5.4.1) of type
      PROTOCOL_ERROR.

   PADDED (0x8):  When set, bit 3 indicates that the Pad Length field
      and any padding that it describes are present.

   PUSH_PROMISE frames MUST only be sent on a peer-initiated stream that
   is in either the "open" or "half-closed (remote)" state.  The stream
   identifier of a PUSH_PROMISE frame indicates the stream it is
   associated with.  If the stream identifier field specifies the value
   0x0, a recipient MUST respond with a connection error (Section 5.4.1)
   of type PROTOCOL_ERROR.

   Promised streams are not required to be used in the order they are
   promised.  The PUSH_PROMISE only reserves stream identifiers for
   later use.

   PUSH_PROMISE MUST NOT be sent if the SETTINGS_ENABLE_PUSH setting of
   the peer endpoint is set to 0.  An endpoint that has set this setting
   and has received acknowledgement MUST treat the receipt of a
   PUSH_PROMISE frame as a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.

   Recipients of PUSH_PROMISE frames can choose to reject promised
   streams by returning a RST_STREAM referencing the promised stream
   identifier back to the sender of the PUSH_PROMISE.

   A PUSH_PROMISE frame modifies the connection state in two ways.
   First, the inclusion of a header block (Section 4.3) potentially
   modifies the state maintained for header compression.  Second,
   PUSH_PROMISE also reserves a stream for later use, causing the
   promised stream to enter the "reserved" state.  A sender MUST NOT
   send a PUSH_PROMISE on a stream unless that stream is either "open"
   or "half-closed (remote)"; the sender MUST ensure that the promised
   stream is a valid choice for a new stream identifier (Section 5.1.1)
   (that is, the promised stream MUST be in the "idle" state).

   Since PUSH_PROMISE reserves a stream, ignoring a PUSH_PROMISE frame
   causes the stream state to become indeterminate.  A receiver MUST
   treat the receipt of a PUSH_PROMISE on a stream that is neither
   "open" nor "half-closed (local)" as a connection error
   (Section 5.4.1) of type PROTOCOL_ERROR.  However, an endpoint that
   has sent RST_STREAM on the associated stream MUST handle PUSH_PROMISE
   frames that might have been created before the RST_STREAM frame is
   received and processed.

   A receiver MUST treat the receipt of a PUSH_PROMISE that promises an
   illegal stream identifier (Section 5.1.1) as a connection error
   (Section 5.4.1) of type PROTOCOL_ERROR.  Note that an illegal stream
   identifier is an identifier for a stream that is not currently in the
   "idle" state.

   The PUSH_PROMISE frame can include padding.  Padding fields and flags
   are identical to those defined for DATA frames (Section 6.1).

</code>
</pre>
</details>

### 6.7 PING

PING帧（类型=0x6）是一种机制，用于测量来自发送方的最短往返时间，并确定是否仍能正常进行连接。可以从任何端点发送PING帧。

```
    +---------------------------------------------------------------+
    |                                                               |
    |                      Opaque Data (64)                         |
    |                                                               |
    +---------------------------------------------------------------+

                      Figure 12: PING Payload Format
```

除帧头外，PING帧还必须在有效载荷中包含8个八位字节的不透明数据。发送者可以选择任何值，并以任何方式使用这些八位位组。

不包含ACK标志的PING帧的接收者必须发送一个ACK标志作为响应而设置的PING帧，并具有相同的有效载荷。与其他任何帧相比，应该给PING响应更高的优先级。 

PING帧定义以下标志：

  - ACK（0x1）：置1时，位0指示此PING帧是PING响应。端点必须在PING响应中设置该标志。端点不得响应包含此标志的PING帧。 
  
PING帧不与任何单独的流相关联。如果收到的PINGframe的流标识符字段值不是0x0，则接收者务必以PROTOCOL_ERROR类型的连接错误（第5.4.1节）做出响应。

收到长度字段值为8以外的PING帧时，必须将其视为FRAME_SIZE_ERROR类型的连接错误（第5.4.1节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.7.  PING

   The PING frame (type=0x6) is a mechanism for measuring a minimal
   round-trip time from the sender, as well as determining whether an
   idle connection is still functional.  PING frames can be sent from
   any endpoint.

    +---------------------------------------------------------------+
    |                                                               |
    |                      Opaque Data (64)                         |
    |                                                               |
    +---------------------------------------------------------------+

                      Figure 12: PING Payload Format

   In addition to the frame header, PING frames MUST contain 8 octets of
   opaque data in the payload.  A sender can include any value it
   chooses and use those octets in any fashion.

   Receivers of a PING frame that does not include an ACK flag MUST send
   a PING frame with the ACK flag set in response, with an identical
   payload.  PING responses SHOULD be given higher priority than any
   other frame.

   The PING frame defines the following flags:

   ACK (0x1):  When set, bit 0 indicates that this PING frame is a PING
      response.  An endpoint MUST set this flag in PING responses.  An
      endpoint MUST NOT respond to PING frames containing this flag.

   PING frames are not associated with any individual stream.  If a PING
   frame is received with a stream identifier field value other than
   0x0, the recipient MUST respond with a connection error
   (Section 5.4.1) of type PROTOCOL_ERROR.

   Receipt of a PING frame with a length field value other than 8 MUST
   be treated as a connection error (Section 5.4.1) of type
   FRAME_SIZE_ERROR.

</code>
</pre>
</details>

### 6.8 GOAWAY

GOAWAY帧（类型=0x7）用于启动连接的关闭或发出严重的错误情况信号。 GOAWAY允许端点优雅地停止接受新的流，同时仍然完成对先前建立的流的处理。这样就可以执行诸如服务器维护之类的管理操作。

在端点之间，存在一个固有的竞争条件，即启动新数据流的端点与远程发送GOAWAY帧的端点之间。为了处理这种情况，GOAWAY包含该连接的发送端上已经或可能处理的最后一个对等端发起的流的流标识符。例如，如果服务器发送GOAWAY帧，则标识的流是客户端启动的编号最高的流。

发送后，如果流的标识符高于所包含的最后一个流标识符，则发送方将忽略在接收方发起的流上发送的帧。尽管可以为新的流建立新的连接，但GOAWAY帧的接收方一定不能在连接上打开其他流。

如果GOAWAY的接收方已在流标识符高于GOAWAY帧指示的流上发送数据，则这些流不会或将不会被处理。 GOAWAY帧的接收方可以将这些流视为从未创建过的流，从而允许这些流稍后在新的连接上重试。

端点应始终在关闭连接之前发送GOAWAY帧，以便远程对等方可以知道流是否已部分处理。例如，如果HTTP客户端在服务器关闭连接的同时发送POST，则如果服务器未发送GOAWAY帧来指示其可能作用的流，则客户端无法知道服务器是否开始处理该POST请求。

端点可能选择关闭连接，而不发送用于对等端行为不佳的GOAWAY。

GOAWAY帧可能不会立即关闭连接；不再使用该连接的GOAWAY的接收方在终止连接之前仍应发送GOAWAY帧。

···
+-+-------------------------------------------------------------+
|R|                  Last-Stream-ID (31)                        |
+-+-------------------------------------------------------------+
|                      Error Code (32)                          |
+---------------------------------------------------------------+
|                  Additional Debug Data (*)                    |
+---------------------------------------------------------------+

                 Figure 13: GOAWAY Payload Format
···

GOAWAY帧未定义任何标志。

GOAWAY帧适用于连接，而不是特定的流。端点必须将流标识符非0x0的GOAWAY帧视为PROTOCOL_ERROR类型的连接错误（第5.4.1节）。

GOAWAY帧中的最后一个流标识符包含编号最高的流标识符，对于该标识符，GOAWAY帧的发送者可能已对其采取了某些措施或可能尚未采取措施。直至并包括已标识流的所有流都可能已经过某种处理。如果未处理任何流，则最后一个流标识符可以设置为0。

  注意：在这种情况下，“已处理”是指流中的某些数据被传递到了可能会采取某些措施的较高软件层。
  
如果连接终止而没有GOAWAY帧，则最后一个流标识符实际上是最高的可能的流标识符。

在具有较低编号或相等编号的标识符的流（在关闭连接之前未完全关闭）上，无法重新尝试请求，事务或任何协议活动，但幂等操作（例如HTTP GET，PUT或DELETE）除外。可以使用新连接安全地重试使用编号更高的流的任何协议活动。

编号小于或等于最后一个streamidentifier的流上的活动仍可能成功完成。 GOAWAY帧的发送方可以通过发送GOAWAY帧来正常关闭连接，将连接保持在“打开”状态，直到所有进行中的流完成为止。

如果情况发生变化，端点可能会发送多个GOAWAY帧。例如，在正常关机期间发送NO_ERROR的GOAWAY端点可能随后遇到需要立即终止连接的情况。从最后收到的GOAWAY帧中收到的最后一个流标识符表示哪些流可能已经作用了。端点不得增加它们在最后一个流标识符中发送的值，因为对等点可能已经在另一个连接上重试了未处理的请求。

当服务器关闭连接时，无法重试请求的客户端将丢失所有正在处理的请求。对于可能不使用HTTP/2为客户端提供服务的中介而言，尤其如此。试图正常关闭连接的服务器应发送初始GOAWAY帧，最后一个流标识符设置为2^31-1，并提供NO_ERROR代码。这向客户端发出信号，即将关闭，并且禁止发起进一步的请求。在为任何进行中的流式传输留出时间（至少一个往返时间）之后，服务器可以发送具有更新的最后一个流标识符的另一个GOAWAY帧。这确保了可以干净地关闭连接而不会丢失请求。

发送GOAWAY帧后，发送方可以丢弃接收方发起的流的帧，其标识符要比所标识的最后一个流高。但是，任何更改连接状态的框架都不能完全忽略。例如，必须最少处理HEADERS，PUSH_PROMISE和CONTINUATION帧，以确保为报头压缩保持的状态是一致的（请参见第4.3节）；类似地，数据帧必须计入连接流控制窗口。无法处理这些帧会导致流控制或报头压缩状态变得不同步。 

GOAWAY框架还包含一个32位错误代码（第7节），其中包含关闭连接的原因。

端点可以将不透明数据附加到任何GOAWAY帧的有效载荷上。其他调试数据仅用于诊断目的，不带语义值。调试信息可能包含对安全性或隐私敏感的数据。已记录或以其他方式持久存储的调试数据必须具有足够的防护措施，以防止未经授权的访问。

<details>
<summary>原文</summary>
<pre>
<code>

6.8.  GOAWAY

   The GOAWAY frame (type=0x7) is used to initiate shutdown of a
   connection or to signal serious error conditions.  GOAWAY allows an
   endpoint to gracefully stop accepting new streams while still
   finishing processing of previously established streams.  This enables
   administrative actions, like server maintenance.

   There is an inherent race condition between an endpoint starting new
   streams and the remote sending a GOAWAY frame.  To deal with this
   case, the GOAWAY contains the stream identifier of the last peer-
   initiated stream that was or might be processed on the sending
   endpoint in this connection.  For instance, if the server sends a
   GOAWAY frame, the identified stream is the highest-numbered stream
   initiated by the client.

   Once sent, the sender will ignore frames sent on streams initiated by
   the receiver if the stream has an identifier higher than the included
   last stream identifier.  Receivers of a GOAWAY frame MUST NOT open
   additional streams on the connection, although a new connection can
   be established for new streams.

   If the receiver of the GOAWAY has sent data on streams with a higher
   stream identifier than what is indicated in the GOAWAY frame, those
   streams are not or will not be processed.  The receiver of the GOAWAY
   frame can treat the streams as though they had never been created at
   all, thereby allowing those streams to be retried later on a new
   connection.

   Endpoints SHOULD always send a GOAWAY frame before closing a
   connection so that the remote peer can know whether a stream has been
   partially processed or not.  For example, if an HTTP client sends a
   POST at the same time that a server closes a connection, the client
   cannot know if the server started to process that POST request if the
   server does not send a GOAWAY frame to indicate what streams it might
   have acted on.

   An endpoint might choose to close a connection without sending a
   GOAWAY for misbehaving peers.

   A GOAWAY frame might not immediately precede closing of the
   connection; a receiver of a GOAWAY that has no more use for the
   connection SHOULD still send a GOAWAY frame before terminating the
   connection.

    +-+-------------------------------------------------------------+
    |R|                  Last-Stream-ID (31)                        |
    +-+-------------------------------------------------------------+
    |                      Error Code (32)                          |
    +---------------------------------------------------------------+
    |                  Additional Debug Data (*)                    |
    +---------------------------------------------------------------+

                     Figure 13: GOAWAY Payload Format

   The GOAWAY frame does not define any flags.

   The GOAWAY frame applies to the connection, not a specific stream.
   An endpoint MUST treat a GOAWAY frame with a stream identifier other
   than 0x0 as a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.

   The last stream identifier in the GOAWAY frame contains the highest-
   numbered stream identifier for which the sender of the GOAWAY frame
   might have taken some action on or might yet take action on.  All
   streams up to and including the identified stream might have been
   processed in some way.  The last stream identifier can be set to 0 if
   no streams were processed.

      Note: In this context, "processed" means that some data from the
      stream was passed to some higher layer of software that might have
      taken some action as a result.

   If a connection terminates without a GOAWAY frame, the last stream
   identifier is effectively the highest possible stream identifier.

   On streams with lower- or equal-numbered identifiers that were not
   closed completely prior to the connection being closed, reattempting
   requests, transactions, or any protocol activity is not possible,
   with the exception of idempotent actions like HTTP GET, PUT, or
   DELETE.  Any protocol activity that uses higher-numbered streams can
   be safely retried using a new connection.

   Activity on streams numbered lower or equal to the last stream
   identifier might still complete successfully.  The sender of a GOAWAY
   frame might gracefully shut down a connection by sending a GOAWAY
   frame, maintaining the connection in an "open" state until all in-
   progress streams complete.

   An endpoint MAY send multiple GOAWAY frames if circumstances change.
   For instance, an endpoint that sends GOAWAY with NO_ERROR during
   graceful shutdown could subsequently encounter a condition that
   requires immediate termination of the connection.  The last stream
   identifier from the last GOAWAY frame received indicates which
   streams could have been acted upon.  Endpoints MUST NOT increase the
   value they send in the last stream identifier, since the peers might
   already have retried unprocessed requests on another connection.

   A client that is unable to retry requests loses all requests that are
   in flight when the server closes the connection.  This is especially
   true for intermediaries that might not be serving clients using
   HTTP/2.  A server that is attempting to gracefully shut down a
   connection SHOULD send an initial GOAWAY frame with the last stream
   identifier set to 2^31-1 and a NO_ERROR code.  This signals to the
   client that a shutdown is imminent and that initiating further
   requests is prohibited.  After allowing time for any in-flight stream
   creation (at least one round-trip time), the server can send another
   GOAWAY frame with an updated last stream identifier.  This ensures
   that a connection can be cleanly shut down without losing requests.

   After sending a GOAWAY frame, the sender can discard frames for
   streams initiated by the receiver with identifiers higher than the
   identified last stream.  However, any frames that alter connection
   state cannot be completely ignored.  For instance, HEADERS,
   PUSH_PROMISE, and CONTINUATION frames MUST be minimally processed to
   ensure the state maintained for header compression is consistent (see
   Section 4.3); similarly, DATA frames MUST be counted toward the
   connection flow-control window.  Failure to process these frames can
   cause flow control or header compression state to become
   unsynchronized.

   The GOAWAY frame also contains a 32-bit error code (Section 7) that
   contains the reason for closing the connection.

   Endpoints MAY append opaque data to the payload of any GOAWAY frame.
   Additional debug data is intended for diagnostic purposes only and
   carries no semantic value.  Debug information could contain security-
   or privacy-sensitive data.  Logged or otherwise persistently stored
   debug data MUST have adequate safeguards to prevent unauthorized
   access.

</code>
</pre>
</details>

### 6.9 WINDOW_UPDATE

WINDOW_UPDATE帧（类型= 0x8）用于实现流控制;有关概述，请参见5.2节。

流控制在两个级别上运行：在每个单独的流和整个连接上。

两种流控制类型都是逐跳的，即，仅在两个端点之间。中介程序不会在依赖的连接之间转发WINDOW_UPDATE帧。但是，任何接收者进行的数据传输节制都会间接导致流控制信息向原始发送者传播。

流控制仅适用于被标识为受流控制的帧。在本文档中定义的帧类型中，这仅包括DATA帧。除非接收者无法分配资源来处理帧，否则必须接受和处理免于流控制的帧。如果接收器无法接受帧，则可能会以FLOW_CONTROL_ERROR类型的流错误（第5.4.2节）或连接错误（第5.4.1节）进行响应。

```
    +-+-------------------------------------------------------------+
    |R|              Window Size Increment (31)                     |
    +-+-------------------------------------------------------------+

                  Figure 14: WINDOW_UPDATE Payload Format
```

WINDOW_UPDATE帧的有效载荷是一个保留位加上一个无符号的31位整数，指示发送者的八位字节数除了现有的流控制窗口外，还可以传输。流控制窗口增量的合法范围是1到2^31-1（2,147,483,647）个八位位组。

WINDOW_UPDATE框架未定义任何标志。

WINDOW_UPDATE帧可以特定于流或整个连接。在前一种情况下，帧的流标识符指示受影响的流；在后者中，值“ 0”指示整个连接是框架的主题。接收方必须将收到的WINDOW_UPDATE帧（其流控制窗口的增量为0）视为PROTOCOL_ERROR类型的流错误（见第5.4.2节）；连接流控制窗口上的错误必须视为连接错误（第5.4.1节）。

对等方可以发送WINDOW_UPDATE，该对等方已发送带有END_STREAM标志的帧。这意味着接收方可以在“半闭路（远程）”或“闭路”流上接收WINDOW_UPDATE帧。接收方不得将此视为错误（请参阅第5.1节）。

接收到流控制帧的接收者必须始终对连接流控制窗口做出贡献，除非接收者将其视为连接错误（第5.4.1节）。即使帧出错，这也是必要的。发送方将帧计数到流控制窗口，但是如果接收方没有，则发送方和接收方的流控制窗口可能会不同。

必须将长度不是4个八位位组的WINDOW_UPDATE帧视为类型为FRAME_SIZE_ERROR的连接错误（第5.4.1节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.9.  WINDOW_UPDATE

   The WINDOW_UPDATE frame (type=0x8) is used to implement flow control;
   see Section 5.2 for an overview.

   Flow control operates at two levels: on each individual stream and on
   the entire connection.

   Both types of flow control are hop by hop, that is, only between the
   two endpoints.  Intermediaries do not forward WINDOW_UPDATE frames
   between dependent connections.  However, throttling of data transfer
   by any receiver can indirectly cause the propagation of flow-control
   information toward the original sender.

   Flow control only applies to frames that are identified as being
   subject to flow control.  Of the frame types defined in this
   document, this includes only DATA frames.  Frames that are exempt
   from flow control MUST be accepted and processed, unless the receiver
   is unable to assign resources to handling the frame.  A receiver MAY
   respond with a stream error (Section 5.4.2) or connection error
   (Section 5.4.1) of type FLOW_CONTROL_ERROR if it is unable to accept
   a frame.

    +-+-------------------------------------------------------------+
    |R|              Window Size Increment (31)                     |
    +-+-------------------------------------------------------------+

                  Figure 14: WINDOW_UPDATE Payload Format

   The payload of a WINDOW_UPDATE frame is one reserved bit plus an
   unsigned 31-bit integer indicating the number of octets that the
   sender can transmit in addition to the existing flow-control window.
   The legal range for the increment to the flow-control window is 1 to
   2^31-1 (2,147,483,647) octets.

   The WINDOW_UPDATE frame does not define any flags.

   The WINDOW_UPDATE frame can be specific to a stream or to the entire
   connection.  In the former case, the frame's stream identifier
   indicates the affected stream; in the latter, the value "0" indicates
   that the entire connection is the subject of the frame.

   A receiver MUST treat the receipt of a WINDOW_UPDATE frame with an
   flow-control window increment of 0 as a stream error (Section 5.4.2)
   of type PROTOCOL_ERROR; errors on the connection flow-control window
   MUST be treated as a connection error (Section 5.4.1).

   WINDOW_UPDATE can be sent by a peer that has sent a frame bearing the
   END_STREAM flag.  This means that a receiver could receive a
   WINDOW_UPDATE frame on a "half-closed (remote)" or "closed" stream.
   A receiver MUST NOT treat this as an error (see Section 5.1).

   A receiver that receives a flow-controlled frame MUST always account
   for its contribution against the connection flow-control window,
   unless the receiver treats this as a connection error
   (Section 5.4.1).  This is necessary even if the frame is in error.
   The sender counts the frame toward the flow-control window, but if
   the receiver does not, the flow-control window at the sender and
   receiver can become different.

   A WINDOW_UPDATE frame with a length other than 4 octets MUST be
   treated as a connection error (Section 5.4.1) of type
   FRAME_SIZE_ERROR.

</code>
</pre>
</details>

#### 6.9.1 Flow-Control Window

HTTP/2中的流控制是使用每个发送者在每个流上保留的窗口来实现的。流量控制窗口是一个简单的整数值，指示允许发送方传输多少个八位位组的数据；因此，它的大小可以衡量接收器的缓冲能力。

两个流控制窗口都适用：流流控制窗口和连接流控制窗口。发送方不得发送长度超过接收方通告的任何一个流控制窗口中可用空间的流控制帧。如果两个流控制窗口中都没有可用空间，则可以发送设置了END_STREAM标志的长度为零的帧（即空的DATA帧）。

对于流控制计算，不计9个字节的帧头。

流控制的帧，发送方通过传输的帧的长度减少两个窗口中的可用空间。

帧的接收方发送WINDOW_UPDATE帧，因为它消耗数据并释放流控制窗口中的空间。为流和连接级别的流控制窗口发送单独的WINDOW_UPDATE帧。

接收WINDOW_UPDATE帧的发送者以帧中指定的数量更新相应的窗口。

发送者务必不允许流控制窗口超过2^31-1个八位位组。如果发送方收到WINDOW_UPDATE导致流量控制窗口超过此最大值，则发送方必须视情况终止流或连接。对于流，发送方以错误代码FLOW_CONTROL_ERROR发送RST_STREAM；对于连接，将发送一个错误代码为FLOW_CONTROL_ERROR的GOAWAY帧。

来自发送方的流控制帧和来自接收方的WINDOW_UPDATE帧彼此完全异步。此属性允许接收方积极地将发送方保留的窗口大小更新为防止溪流停滞。

<details>
<summary>原文</summary>
<pre>
<code>

6.9.1.  The Flow-Control Window

   Flow control in HTTP/2 is implemented using a window kept by each
   sender on every stream.  The flow-control window is a simple integer
   value that indicates how many octets of data the sender is permitted
   to transmit; as such, its size is a measure of the buffering capacity
   of the receiver.

   Two flow-control windows are applicable: the stream flow-control
   window and the connection flow-control window.  The sender MUST NOT
   send a flow-controlled frame with a length that exceeds the space
   available in either of the flow-control windows advertised by the
   receiver.  Frames with zero length with the END_STREAM flag set (that
   is, an empty DATA frame) MAY be sent if there is no available space
   in either flow-control window.

   For flow-control calculations, the 9-octet frame header is not
   counted.

   After sending a flow-controlled frame, the sender reduces the space
   available in both windows by the length of the transmitted frame.

   The receiver of a frame sends a WINDOW_UPDATE frame as it consumes
   data and frees up space in flow-control windows.  Separate
   WINDOW_UPDATE frames are sent for the stream- and connection-level
   flow-control windows.

   A sender that receives a WINDOW_UPDATE frame updates the
   corresponding window by the amount specified in the frame.

   A sender MUST NOT allow a flow-control window to exceed 2^31-1
   octets.  If a sender receives a WINDOW_UPDATE that causes a flow-
   control window to exceed this maximum, it MUST terminate either the
   stream or the connection, as appropriate.  For streams, the sender
   sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the
   connection, a GOAWAY frame with an error code of FLOW_CONTROL_ERROR
   is sent.

   Flow-controlled frames from the sender and WINDOW_UPDATE frames from
   the receiver are completely asynchronous with respect to each other.
   This property allows a receiver to aggressively update the window
   size kept by the sender to prevent streams from stalling.

</code>
</pre>
</details>

#### 6.9.2 初始流控制窗口大小

首次建立HTTP/2连接时，将创建初始流控制窗口大小为65,535个八位位组的新流。连接流控制窗口也为65,535个八位位组。两个端点都可以通过在构成连接前言一部分的SETTINGS帧中包含SETTINGS_INITIAL_WINDOW_SIZE的值来调整新流的初始窗口大小。只能使用WINDOW_UPDATE帧来更改连接流控制窗口。

在接收设置为SETTINGS_INITIAL_WINDOW_SIZE设置值的SETTINGS帧之前，端点在发送流控制的框架时只能使用默认的初始窗口大小。同样，将连接流控制窗口设置为默认的初始窗口大小，直到接收到WINDOW_UPDATE帧为止。

除了更改尚未激活的流的流控制窗口外，SETTINGS帧还可以更改以下各项的初始流控制窗口大小：具有活动流控制窗口的流（即处于“打开”或“半关闭（远程）”状态的流）。当SETTINGS_INITIAL_WINDOW_SIZE的值更改时，接收方必须通过新值和旧值之间的差异来调整其所维护的所有流流控制窗口的大小。

对SETTINGS_INITIAL_WINDOW_SIZE的更改可能导致流控制窗口中的可用空间变为负数。发送方必须跟踪否定的流控制窗口，并且在接收到导致流控制窗口变为正数的WINDOW_UPDATE帧之前，不得发送新的流控制帧。

例如，如果客户端在连接建立后立即发送60 KB，并且服务器设置了初始窗口大小为16KB，客户端将在收到SETTINGS帧后将可用的流控制窗口重新计算为-44 KB。在WINDOW_UPDATE帧将窗口恢复为正值之前，客户端将保留负的流控制窗口，此后客户端可以继续发送。

SETTINGS帧不能更改连接流控制窗口。

端点必须处理对SETTINGS_INITIAL_WINDOW_SIZE的更改，这会导致任何流控制窗口超过最大大小，这是类型为FLOW_CONTROL_ERROR的连接错误（第5.4.1节）。

<details>
<summary>原文</summary>
<pre>
<code>

6.9.2.  Initial Flow-Control Window Size

   When an HTTP/2 connection is first established, new streams are
   created with an initial flow-control window size of 65,535 octets.
   The connection flow-control window is also 65,535 octets.  Both
   endpoints can adjust the initial window size for new streams by
   including a value for SETTINGS_INITIAL_WINDOW_SIZE in the SETTINGS
   frame that forms part of the connection preface.  The connection
   flow-control window can only be changed using WINDOW_UPDATE frames.

   Prior to receiving a SETTINGS frame that sets a value for
   SETTINGS_INITIAL_WINDOW_SIZE, an endpoint can only use the default
   initial window size when sending flow-controlled frames.  Similarly,
   the connection flow-control window is set to the default initial
   window size until a WINDOW_UPDATE frame is received.

   In addition to changing the flow-control window for streams that are
   not yet active, a SETTINGS frame can alter the initial flow-control
   window size for streams with active flow-control windows (that is,
   streams in the "open" or "half-closed (remote)" state).  When the
   value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust
   the size of all stream flow-control windows that it maintains by the
   difference between the new value and the old value.

   A change to SETTINGS_INITIAL_WINDOW_SIZE can cause the available
   space in a flow-control window to become negative.  A sender MUST
   track the negative flow-control window and MUST NOT send new flow-
   controlled frames until it receives WINDOW_UPDATE frames that cause
   the flow-control window to become positive.

   For example, if the client sends 60 KB immediately on connection
   establishment and the server sets the initial window size to be 16
   KB, the client will recalculate the available flow-control window to
   be -44 KB on receipt of the SETTINGS frame.  The client retains a
   negative flow-control window until WINDOW_UPDATE frames restore the
   window to being positive, after which the client can resume sending.

   A SETTINGS frame cannot alter the connection flow-control window.

   An endpoint MUST treat a change to SETTINGS_INITIAL_WINDOW_SIZE that
   causes any flow-control window to exceed the maximum size as a
   connection error (Section 5.4.1) of type FLOW_CONTROL_ERROR.

</code>
</pre>
</details>

#### 6.9.3 减小流窗口大小

希望使用比当前大小小的流控制窗口的接收器可以发送新的SETTINGS帧。但是，接收者必须准备好接收超过该窗口大小的数据，因为发送者可能在处理SETTINGS帧之前发送了超出下限的数据。

发送设置帧以减小初始流控制窗口大小之后，接收者可以继续超过流量控制限制的处理流。允许流继续运行不会使接收方立即减少其为流控制窗口保留的空间。这些流上的进度也可能会停止，因为需要WINDOW_UPDATE帧来允许发送方继续发送。接收者可以向受影响的流发送RST_STREAM，错误代码为FLOW_CONTROL_ERROR。

<details>
<summary>原文</summary>
<pre>
<code>

6.9.3.  Reducing the Stream Window Size

   A receiver that wishes to use a smaller flow-control window than the
   current size can send a new SETTINGS frame.  However, the receiver
   MUST be prepared to receive data that exceeds this window size, since
   the sender might send data that exceeds the lower limit prior to
   processing the SETTINGS frame.

   After sending a SETTINGS frame that reduces the initial flow-control
   window size, a receiver MAY continue to process streams that exceed
   flow-control limits.  Allowing streams to continue does not allow the
   receiver to immediately reduce the space it reserves for flow-control
   windows.  Progress on these streams can also stall, since
   WINDOW_UPDATE frames are needed to allow the sender to resume
   sending.  The receiver MAY instead send a RST_STREAM with an error
   code of FLOW_CONTROL_ERROR for the affected streams.

</code>
</pre>
</details>

### 6.10 CONTINUATION

CONTINUATION帧（类型=0x9）用于继续一系列标题块片段（第4.3节）。只要前一帧在同一流上并且是没有设置END_HEADERS标志的HEADERS，PUSH_PROMISE或CONTINUATION帧，就可以发送任意数量的CONTINUATION帧。

```
    +---------------------------------------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+

                   Figure 15: CONTINUATION Frame Payload
```

CONTINUATION帧有效载荷包含一个头块片段（第4.3节）。

CONTINUATION帧定义了以下标志：

  - END_HEADERS（0x4）：置位时，位2指示该帧结束在前面的块（第4.3节）。
  如果未设置END_HEADERS位，则此帧后必须跟另一个CONTINUATION帧。接收方必须将接收到的任何其他类型的帧或不同流上的帧视为PROTOCOL_ERROR类型的连接错误（第5.4.1节）。

CONTINUATION帧会按照第4.3节中的定义更改连接状态。

CONTINUATION帧必须与流关联。如果接收到流标识符字段为0x0的CONTINUATION帧，则接收者务必以PROTOCOL_ERROR类型的连接错误（第5.4.1节）

没有设置END_HEADERS标志的HEADERS，PUSH_PROMISE或CONTINUATION帧必须在CONTINUATION帧之前。观察到违反此规则的收件人必须以PROTOCOL_ERROR类型的连接错误（第5.4.1节）进行响应。

<details>
<summary>原文</summary>
<pre>
<code>

6.10.  CONTINUATION

   The CONTINUATION frame (type=0x9) is used to continue a sequence of
   header block fragments (Section 4.3).  Any number of CONTINUATION
   frames can be sent, as long as the preceding frame is on the same
   stream and is a HEADERS, PUSH_PROMISE, or CONTINUATION frame without
   the END_HEADERS flag set.

    +---------------------------------------------------------------+
    |                   Header Block Fragment (*)                 ...
    +---------------------------------------------------------------+

                   Figure 15: CONTINUATION Frame Payload

   The CONTINUATION frame payload contains a header block fragment
   (Section 4.3).

   The CONTINUATION frame defines the following flag:

   END_HEADERS (0x4):  When set, bit 2 indicates that this frame ends a
      header block (Section 4.3).

      If the END_HEADERS bit is not set, this frame MUST be followed by
      another CONTINUATION frame.  A receiver MUST treat the receipt of
      any other type of frame or a frame on a different stream as a
      connection error (Section 5.4.1) of type PROTOCOL_ERROR.

   The CONTINUATION frame changes the connection state as defined in
   Section 4.3.

   CONTINUATION frames MUST be associated with a stream.  If a
   CONTINUATION frame is received whose stream identifier field is 0x0,
   the recipient MUST respond with a connection error (Section 5.4.1) of
   type PROTOCOL_ERROR.

   A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or
   CONTINUATION frame without the END_HEADERS flag set.  A recipient
   that observes violation of this rule MUST respond with a connection
   error (Section 5.4.1) of type PROTOCOL_ERROR.

</code>
</pre>
</details>

<details>
<summary>原文</summary>
<pre>
<code>

7.  Error Codes

   Error codes are 32-bit fields that are used in RST_STREAM and GOAWAY
   frames to convey the reasons for the stream or connection error.

   Error codes share a common code space.  Some error codes apply only
   to either streams or the entire connection and have no defined
   semantics in the other context.

   The following error codes are defined:

   NO_ERROR (0x0):  The associated condition is not a result of an
      error.  For example, a GOAWAY might include this code to indicate
      graceful shutdown of a connection.

   PROTOCOL_ERROR (0x1):  The endpoint detected an unspecific protocol
      error.  This error is for use when a more specific error code is
      not available.

   INTERNAL_ERROR (0x2):  The endpoint encountered an unexpected
      internal error.

   FLOW_CONTROL_ERROR (0x3):  The endpoint detected that its peer
      violated the flow-control protocol.

   SETTINGS_TIMEOUT (0x4):  The endpoint sent a SETTINGS frame but did
      not receive a response in a timely manner.  See Section 6.5.3
      ("Settings Synchronization").

   STREAM_CLOSED (0x5):  The endpoint received a frame after a stream
      was half-closed.

   FRAME_SIZE_ERROR (0x6):  The endpoint received a frame with an
      invalid size.

   REFUSED_STREAM (0x7):  The endpoint refused the stream prior to
      performing any application processing (see Section 8.1.4 for
      details).

   CANCEL (0x8):  Used by the endpoint to indicate that the stream is no
      longer needed.

   COMPRESSION_ERROR (0x9):  The endpoint is unable to maintain the
      header compression context for the connection.

   CONNECT_ERROR (0xa):  The connection established in response to a
      CONNECT request (Section 8.3) was reset or abnormally closed.

   ENHANCE_YOUR_CALM (0xb):  The endpoint detected that its peer is
      exhibiting a behavior that might be generating excessive load.

   INADEQUATE_SECURITY (0xc):  The underlying transport has properties
      that do not meet minimum security requirements (see Section 9.2).

   HTTP_1_1_REQUIRED (0xd):  The endpoint requires that HTTP/1.1 be used
      instead of HTTP/2.

   Unknown or unsupported error codes MUST NOT trigger any special
   behavior.  These MAY be treated by an implementation as being
   equivalent to INTERNAL_ERROR.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.  HTTP Message Exchanges

   HTTP/2 is intended to be as compatible as possible with current uses
   of HTTP.  This means that, from the application perspective, the
   features of the protocol are largely unchanged.  To achieve this, all
   request and response semantics are preserved, although the syntax of
   conveying those semantics has changed.

   Thus, the specification and requirements of HTTP/1.1 Semantics and
   Content [RFC7231], Conditional Requests [RFC7232], Range Requests
   [RFC7233], Caching [RFC7234], and Authentication [RFC7235] are
   applicable to HTTP/2.  Selected portions of HTTP/1.1 Message Syntax
   and Routing [RFC7230], such as the HTTP and HTTPS URI schemes, are
   also applicable in HTTP/2, but the expression of those semantics for
   this protocol are defined in the sections below.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.  HTTP Request/Response Exchange

   A client sends an HTTP request on a new stream, using a previously
   unused stream identifier (Section 5.1.1).  A server sends an HTTP
   response on the same stream as the request.

   An HTTP message (request or response) consists of:

   1.  for a response only, zero or more HEADERS frames (each followed
       by zero or more CONTINUATION frames) containing the message
       headers of informational (1xx) HTTP responses (see [RFC7230],
       Section 3.2 and [RFC7231], Section 6.2),

   2.  one HEADERS frame (followed by zero or more CONTINUATION frames)
       containing the message headers (see [RFC7230], Section 3.2),

   3.  zero or more DATA frames containing the payload body (see
       [RFC7230], Section 3.3), and

   4.  optionally, one HEADERS frame, followed by zero or more
       CONTINUATION frames containing the trailer-part, if present (see
       [RFC7230], Section 4.1.2).

   The last frame in the sequence bears an END_STREAM flag, noting that
   a HEADERS frame bearing the END_STREAM flag can be followed by
   CONTINUATION frames that carry any remaining portions of the header
   block.

   Other frames (from any stream) MUST NOT occur between the HEADERS
   frame and any CONTINUATION frames that might follow.

   HTTP/2 uses DATA frames to carry message payloads.  The "chunked"
   transfer encoding defined in Section 4.1 of [RFC7230] MUST NOT be
   used in HTTP/2.

   Trailing header fields are carried in a header block that also
   terminates the stream.  Such a header block is a sequence starting
   with a HEADERS frame, followed by zero or more CONTINUATION frames,
   where the HEADERS frame bears an END_STREAM flag.  Header blocks
   after the first that do not terminate the stream are not part of an
   HTTP request or response.

   A HEADERS frame (and associated CONTINUATION frames) can only appear
   at the start or end of a stream.  An endpoint that receives a HEADERS
   frame without the END_STREAM flag set after receiving a final (non-
   informational) status code MUST treat the corresponding request or
   response as malformed (Section 8.1.2.6).

   An HTTP request/response exchange fully consumes a single stream.  A
   request starts with the HEADERS frame that puts the stream into an
   "open" state.  The request ends with a frame bearing END_STREAM,
   which causes the stream to become "half-closed (local)" for the
   client and "half-closed (remote)" for the server.  A response starts
   with a HEADERS frame and ends with a frame bearing END_STREAM, which
   places the stream in the "closed" state.

   An HTTP response is complete after the server sends -- or the client
   receives -- a frame with the END_STREAM flag set (including any
   CONTINUATION frames needed to complete a header block).  A server can
   send a complete response prior to the client sending an entire
   request if the response does not depend on any portion of the request
   that has not been sent and received.  When this is true, a server MAY
   request that the client abort transmission of a request without error
   by sending a RST_STREAM with an error code of NO_ERROR after sending
   a complete response (i.e., a frame with the END_STREAM flag).
   Clients MUST NOT discard responses as a result of receiving such a
   RST_STREAM, though clients can always discard responses at their
   discretion for other reasons.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.1.  Upgrading from HTTP/2

   HTTP/2 removes support for the 101 (Switching Protocols)
   informational status code ([RFC7231], Section 6.2.2).

   The semantics of 101 (Switching Protocols) aren't applicable to a
   multiplexed protocol.  Alternative protocols are able to use the same
   mechanisms that HTTP/2 uses to negotiate their use (see Section 3).

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.2.  HTTP Header Fields

   HTTP header fields carry information as a series of key-value pairs.
   For a listing of registered HTTP headers, see the "Message Header
   Field" registry maintained at <https://www.iana.org/assignments/
   message-headers>.

   Just as in HTTP/1.x, header field names are strings of ASCII
   characters that are compared in a case-insensitive fashion.  However,
   header field names MUST be converted to lowercase prior to their
   encoding in HTTP/2.  A request or response containing uppercase
   header field names MUST be treated as malformed (Section 8.1.2.6).

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.2.1.  Pseudo-Header Fields

   While HTTP/1.x used the message start-line (see [RFC7230],
   Section 3.1) to convey the target URI, the method of the request, and
   the status code for the response, HTTP/2 uses special pseudo-header
   fields beginning with ':' character (ASCII 0x3a) for this purpose.

   Pseudo-header fields are not HTTP header fields.  Endpoints MUST NOT
   generate pseudo-header fields other than those defined in this
   document.

   Pseudo-header fields are only valid in the context in which they are
   defined.  Pseudo-header fields defined for requests MUST NOT appear
   in responses; pseudo-header fields defined for responses MUST NOT
   appear in requests.  Pseudo-header fields MUST NOT appear in
   trailers.  Endpoints MUST treat a request or response that contains
   undefined or invalid pseudo-header fields as malformed
   (Section 8.1.2.6).

   All pseudo-header fields MUST appear in the header block before
   regular header fields.  Any request or response that contains a
   pseudo-header field that appears in a header block after a regular
   header field MUST be treated as malformed (Section 8.1.2.6).

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.2.2.  Connection-Specific Header Fields

   HTTP/2 does not use the Connection header field to indicate
   connection-specific header fields; in this protocol, connection-
   specific metadata is conveyed by other means.  An endpoint MUST NOT
   generate an HTTP/2 message containing connection-specific header
   fields; any message containing connection-specific header fields MUST
   be treated as malformed (Section 8.1.2.6).

   The only exception to this is the TE header field, which MAY be
   present in an HTTP/2 request; when it is, it MUST NOT contain any
   value other than "trailers".

   This means that an intermediary transforming an HTTP/1.x message to
   HTTP/2 will need to remove any header fields nominated by the
   Connection header field, along with the Connection header field
   itself.  Such intermediaries SHOULD also remove other connection-
   specific header fields, such as Keep-Alive, Proxy-Connection,
   Transfer-Encoding, and Upgrade, even if they are not nominated by the
   Connection header field.

      Note: HTTP/2 purposefully does not support upgrade to another
      protocol.  The handshake methods described in Section 3 are
      believed sufficient to negotiate the use of alternative protocols.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.2.3.  Request Pseudo-Header Fields

   The following pseudo-header fields are defined for HTTP/2 requests:

   o  The ":method" pseudo-header field includes the HTTP method
      ([RFC7231], Section 4).

   o  The ":scheme" pseudo-header field includes the scheme portion of
      the target URI ([RFC3986], Section 3.1).

      ":scheme" is not restricted to "http" and "https" schemed URIs.  A
      proxy or gateway can translate requests for non-HTTP schemes,
      enabling the use of HTTP to interact with non-HTTP services.

   o  The ":authority" pseudo-header field includes the authority
      portion of the target URI ([RFC3986], Section 3.2).  The authority
      MUST NOT include the deprecated "userinfo" subcomponent for "http"
      or "https" schemed URIs.

      To ensure that the HTTP/1.1 request line can be reproduced
      accurately, this pseudo-header field MUST be omitted when
      translating from an HTTP/1.1 request that has a request target in
      origin or asterisk form (see [RFC7230], Section 5.3).  Clients
      that generate HTTP/2 requests directly SHOULD use the ":authority"
      pseudo-header field instead of the Host header field.  An
      intermediary that converts an HTTP/2 request to HTTP/1.1 MUST
      create a Host header field if one is not present in a request by
      copying the value of the ":authority" pseudo-header field.

   o  The ":path" pseudo-header field includes the path and query parts
      of the target URI (the "path-absolute" production and optionally a
      '?' character followed by the "query" production (see Sections 3.3
      and 3.4 of [RFC3986]).  A request in asterisk form includes the
      value '*' for the ":path" pseudo-header field.

      This pseudo-header field MUST NOT be empty for "http" or "https"
      URIs; "http" or "https" URIs that do not contain a path component
      MUST include a value of '/'.  The exception to this rule is an
      OPTIONS request for an "http" or "https" URI that does not include
      a path component; these MUST include a ":path" pseudo-header field
      with a value of '*' (see [RFC7230], Section 5.3.4).

   All HTTP/2 requests MUST include exactly one valid value for the
   ":method", ":scheme", and ":path" pseudo-header fields, unless it is
   a CONNECT request (Section 8.3).  An HTTP request that omits
   mandatory pseudo-header fields is malformed (Section 8.1.2.6).

   HTTP/2 does not define a way to carry the version identifier that is
   included in the HTTP/1.1 request line.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.2.4.  Response Pseudo-Header Fields

   For HTTP/2 responses, a single ":status" pseudo-header field is
   defined that carries the HTTP status code field (see [RFC7231],
   Section 6).  This pseudo-header field MUST be included in all
   responses; otherwise, the response is malformed (Section 8.1.2.6).

   HTTP/2 does not define a way to carry the version or reason phrase
   that is included in an HTTP/1.1 status line.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.2.5.  Compressing the Cookie Header Field

   The Cookie header field [COOKIE] uses a semi-colon (";") to delimit
   cookie-pairs (or "crumbs").  This header field doesn't follow the
   list construction rules in HTTP (see [RFC7230], Section 3.2.2), which
   prevents cookie-pairs from being separated into different name-value
   pairs.  This can significantly reduce compression efficiency as
   individual cookie-pairs are updated.

   To allow for better compression efficiency, the Cookie header field
   MAY be split into separate header fields, each with one or more
   cookie-pairs.  If there are multiple Cookie header fields after
   decompression, these MUST be concatenated into a single octet string
   using the two-octet delimiter of 0x3B, 0x20 (the ASCII string "; ")
   before being passed into a non-HTTP/2 context, such as an HTTP/1.1
   connection, or a generic HTTP server application.

   Therefore, the following two lists of Cookie header fields are
   semantically equivalent.

     cookie: a=b; c=d; e=f

     cookie: a=b
     cookie: c=d
     cookie: e=f

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.2.6.  Malformed Requests and Responses

   A malformed request or response is one that is an otherwise valid
   sequence of HTTP/2 frames but is invalid due to the presence of
   extraneous frames, prohibited header fields, the absence of mandatory
   header fields, or the inclusion of uppercase header field names.

   A request or response that includes a payload body can include a
   content-length header field.  A request or response is also malformed
   if the value of a content-length header field does not equal the sum
   of the DATA frame payload lengths that form the body.  A response
   that is defined to have no payload, as described in [RFC7230],
   Section 3.3.2, can have a non-zero content-length header field, even
   though no content is included in DATA frames.

   Intermediaries that process HTTP requests or responses (i.e., any
   intermediary not acting as a tunnel) MUST NOT forward a malformed
   request or response.  Malformed requests or responses that are
   detected MUST be treated as a stream error (Section 5.4.2) of type
   PROTOCOL_ERROR.

   For malformed requests, a server MAY send an HTTP response prior to
   closing or resetting the stream.  Clients MUST NOT accept a malformed
   response.  Note that these requirements are intended to protect
   against several types of common attacks against HTTP; they are
   deliberately strict because being permissive can expose
   implementations to these vulnerabilities.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.3.  Examples

   This section shows HTTP/1.1 requests and responses, with
   illustrations of equivalent HTTP/2 requests and responses.

   An HTTP GET request includes request header fields and no payload
   body and is therefore transmitted as a single HEADERS frame, followed
   by zero or more CONTINUATION frames containing the serialized block
   of request header fields.  The HEADERS frame in the following has
   both the END_HEADERS and END_STREAM flags set; no CONTINUATION frames
   are sent.

     GET /resource HTTP/1.1           HEADERS
     Host: example.org          ==>     + END_STREAM
     Accept: image/jpeg                 + END_HEADERS
                                          :method = GET
                                          :scheme = https
                                          :path = /resource
                                          host = example.org
                                          accept = image/jpeg

   Similarly, a response that includes only response header fields is
   transmitted as a HEADERS frame (again, followed by zero or more
   CONTINUATION frames) containing the serialized block of response
   header fields.

     HTTP/1.1 304 Not Modified        HEADERS
     ETag: "xyzzy"              ==>     + END_STREAM
     Expires: Thu, 23 Jan ...           + END_HEADERS
                                          :status = 304
                                          etag = "xyzzy"
                                          expires = Thu, 23 Jan ...

   An HTTP POST request that includes request header fields and payload
   data is transmitted as one HEADERS frame, followed by zero or more
   CONTINUATION frames containing the request header fields, followed by
   one or more DATA frames, with the last CONTINUATION (or HEADERS)
   frame having the END_HEADERS flag set and the final DATA frame having
   the END_STREAM flag set:

     POST /resource HTTP/1.1          HEADERS
     Host: example.org          ==>     - END_STREAM
     Content-Type: image/jpeg           - END_HEADERS
     Content-Length: 123                  :method = POST
                                          :path = /resource
     {binary data}                        :scheme = https

                                      CONTINUATION
                                        + END_HEADERS
                                          content-type = image/jpeg
                                          host = example.org
                                          content-length = 123

                                      DATA
                                        + END_STREAM
                                      {binary data}

   Note that data contributing to any given header field could be spread
   between header block fragments.  The allocation of header fields to
   frames in this example is illustrative only.

   A response that includes header fields and payload data is
   transmitted as a HEADERS frame, followed by zero or more CONTINUATION
   frames, followed by one or more DATA frames, with the last DATA frame
   in the sequence having the END_STREAM flag set:

     HTTP/1.1 200 OK                  HEADERS
     Content-Type: image/jpeg   ==>     - END_STREAM
     Content-Length: 123                + END_HEADERS
                                          :status = 200
     {binary data}                        content-type = image/jpeg
                                          content-length = 123

                                      DATA
                                        + END_STREAM
                                      {binary data}

   An informational response using a 1xx status code other than 101 is
   transmitted as a HEADERS frame, followed by zero or more CONTINUATION
   frames.

   Trailing header fields are sent as a header block after both the
   request or response header block and all the DATA frames have been
   sent.  The HEADERS frame starting the trailers header block has the
   END_STREAM flag set.

   The following example includes both a 100 (Continue) status code,
   which is sent in response to a request containing a "100-continue"
   token in the Expect header field, and trailing header fields:

     HTTP/1.1 100 Continue            HEADERS
     Extension-Field: bar       ==>     - END_STREAM
                                        + END_HEADERS
                                          :status = 100
                                          extension-field = bar

     HTTP/1.1 200 OK                  HEADERS
     Content-Type: image/jpeg   ==>     - END_STREAM
     Transfer-Encoding: chunked         + END_HEADERS
     Trailer: Foo                         :status = 200
                                          content-length = 123
     123                                  content-type = image/jpeg
     {binary data}                        trailer = Foo
     0
     Foo: bar                         DATA
                                        - END_STREAM
                                      {binary data}

                                      HEADERS
                                        + END_STREAM
                                        + END_HEADERS
                                          foo = bar

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.1.4.  Request Reliability Mechanisms in HTTP/2

   In HTTP/1.1, an HTTP client is unable to retry a non-idempotent
   request when an error occurs because there is no means to determine
   the nature of the error.  It is possible that some server processing
   occurred prior to the error, which could result in undesirable
   effects if the request were reattempted.

   HTTP/2 provides two mechanisms for providing a guarantee to a client
   that a request has not been processed:

   o  The GOAWAY frame indicates the highest stream number that might
      have been processed.  Requests on streams with higher numbers are
      therefore guaranteed to be safe to retry.

   o  The REFUSED_STREAM error code can be included in a RST_STREAM
      frame to indicate that the stream is being closed prior to any
      processing having occurred.  Any request that was sent on the
      reset stream can be safely retried.

   Requests that have not been processed have not failed; clients MAY
   automatically retry them, even those with non-idempotent methods.

   A server MUST NOT indicate that a stream has not been processed
   unless it can guarantee that fact.  If frames that are on a stream
   are passed to the application layer for any stream, then
   REFUSED_STREAM MUST NOT be used for that stream, and a GOAWAY frame
   MUST include a stream identifier that is greater than or equal to the
   given stream identifier.

   In addition to these mechanisms, the PING frame provides a way for a
   client to easily test a connection.  Connections that remain idle can
   become broken as some middleboxes (for instance, network address
   translators or load balancers) silently discard connection bindings.
   The PING frame allows a client to safely test whether a connection is
   still active without sending a request.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.2.  Server Push

   HTTP/2 allows a server to pre-emptively send (or "push") responses
   (along with corresponding "promised" requests) to a client in
   association with a previous client-initiated request.  This can be
   useful when the server knows the client will need to have those
   responses available in order to fully process the response to the
   original request.

   A client can request that server push be disabled, though this is
   negotiated for each hop independently.  The SETTINGS_ENABLE_PUSH
   setting can be set to 0 to indicate that server push is disabled.

   Promised requests MUST be cacheable (see [RFC7231], Section 4.2.3),
   MUST be safe (see [RFC7231], Section 4.2.1), and MUST NOT include a
   request body.  Clients that receive a promised request that is not
   cacheable, that is not known to be safe, or that indicates the
   presence of a request body MUST reset the promised stream with a
   stream error (Section 5.4.2) of type PROTOCOL_ERROR.  Note this could
   result in the promised stream being reset if the client does not
   recognize a newly defined method as being safe.

   Pushed responses that are cacheable (see [RFC7234], Section 3) can be
   stored by the client, if it implements an HTTP cache.  Pushed
   responses are considered successfully validated on the origin server
   (e.g., if the "no-cache" cache response directive is present
   ([RFC7234], Section 5.2.2)) while the stream identified by the
   promised stream ID is still open.

   Pushed responses that are not cacheable MUST NOT be stored by any
   HTTP cache.  They MAY be made available to the application
   separately.

   The server MUST include a value in the ":authority" pseudo-header
   field for which the server is authoritative (see Section 10.1).  A
   client MUST treat a PUSH_PROMISE for which the server is not
   authoritative as a stream error (Section 5.4.2) of type
   PROTOCOL_ERROR.

   An intermediary can receive pushes from the server and choose not to
   forward them on to the client.  In other words, how to make use of
   the pushed information is up to that intermediary.  Equally, the
   intermediary might choose to make additional pushes to the client,
   without any action taken by the server.

   A client cannot push.  Thus, servers MUST treat the receipt of a
   PUSH_PROMISE frame as a connection error (Section 5.4.1) of type
   PROTOCOL_ERROR.  Clients MUST reject any attempt to change the
   SETTINGS_ENABLE_PUSH setting to a value other than 0 by treating the
   message as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.2.1.  Push Requests

   Server push is semantically equivalent to a server responding to a
   request; however, in this case, that request is also sent by the
   server, as a PUSH_PROMISE frame.

   The PUSH_PROMISE frame includes a header block that contains a
   complete set of request header fields that the server attributes to
   the request.  It is not possible to push a response to a request that
   includes a request body.

   Pushed responses are always associated with an explicit request from
   the client.  The PUSH_PROMISE frames sent by the server are sent on
   that explicit request's stream.  The PUSH_PROMISE frame also includes
   a promised stream identifier, chosen from the stream identifiers
   available to the server (see Section 5.1.1).

   The header fields in PUSH_PROMISE and any subsequent CONTINUATION
   frames MUST be a valid and complete set of request header fields
   (Section 8.1.2.3).  The server MUST include a method in the ":method"
   pseudo-header field that is safe and cacheable.  If a client receives
   a PUSH_PROMISE that does not include a complete and valid set of
   header fields or the ":method" pseudo-header field identifies a
   method that is not safe, it MUST respond with a stream error
   (Section 5.4.2) of type PROTOCOL_ERROR.

   The server SHOULD send PUSH_PROMISE (Section 6.6) frames prior to
   sending any frames that reference the promised responses.  This
   avoids a race where clients issue requests prior to receiving any
   PUSH_PROMISE frames.

   For example, if the server receives a request for a document
   containing embedded links to multiple image files and the server
   chooses to push those additional images to the client, sending
   PUSH_PROMISE frames before the DATA frames that contain the image
   links ensures that the client is able to see that a resource will be
   pushed before discovering embedded links.  Similarly, if the server
   pushes responses referenced by the header block (for instance, in
   Link header fields), sending a PUSH_PROMISE before sending the header
   block ensures that clients do not request those resources.

   PUSH_PROMISE frames MUST NOT be sent by the client.

   PUSH_PROMISE frames can be sent by the server in response to any
   client-initiated stream, but the stream MUST be in either the "open"
   or "half-closed (remote)" state with respect to the server.
   PUSH_PROMISE frames are interspersed with the frames that comprise a
   response, though they cannot be interspersed with HEADERS and
   CONTINUATION frames that comprise a single header block.

   Sending a PUSH_PROMISE frame creates a new stream and puts the stream
   into the "reserved (local)" state for the server and the "reserved
   (remote)" state for the client.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.2.2.  Push Responses

   After sending the PUSH_PROMISE frame, the server can begin delivering
   the pushed response as a response (Section 8.1.2.4) on a server-
   initiated stream that uses the promised stream identifier.  The
   server uses this stream to transmit an HTTP response, using the same
   sequence of frames as defined in Section 8.1.  This stream becomes
   "half-closed" to the client (Section 5.1) after the initial HEADERS
   frame is sent.

   Once a client receives a PUSH_PROMISE frame and chooses to accept the
   pushed response, the client SHOULD NOT issue any requests for the
   promised response until after the promised stream has closed.

   If the client determines, for any reason, that it does not wish to
   receive the pushed response from the server or if the server takes
   too long to begin sending the promised response, the client can send
   a RST_STREAM frame, using either the CANCEL or REFUSED_STREAM code
   and referencing the pushed stream's identifier.

   A client can use the SETTINGS_MAX_CONCURRENT_STREAMS setting to limit
   the number of responses that can be concurrently pushed by a server.
   Advertising a SETTINGS_MAX_CONCURRENT_STREAMS value of zero disables
   server push by preventing the server from creating the necessary
   streams.  This does not prohibit a server from sending PUSH_PROMISE
   frames; clients need to reset any promised streams that are not
   wanted.

   Clients receiving a pushed response MUST validate that either the
   server is authoritative (see Section 10.1) or the proxy that provided
   the pushed response is configured for the corresponding request.  For
   example, a server that offers a certificate for only the
   "example.com" DNS-ID or Common Name is not permitted to push a
   response for "https://www.example.org/doc".

   The response for a PUSH_PROMISE stream begins with a HEADERS frame,
   which immediately puts the stream into the "half-closed (remote)"
   state for the server and "half-closed (local)" state for the client,
   and ends with a frame bearing END_STREAM, which places the stream in
   the "closed" state.

      Note: The client never sends a frame with the END_STREAM flag for
      a server push.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

8.3.  The CONNECT Method

   In HTTP/1.x, the pseudo-method CONNECT ([RFC7231], Section 4.3.6) is
   used to convert an HTTP connection into a tunnel to a remote host.
   CONNECT is primarily used with HTTP proxies to establish a TLS
   session with an origin server for the purposes of interacting with
   "https" resources.

   In HTTP/2, the CONNECT method is used to establish a tunnel over a
   single HTTP/2 stream to a remote host for similar purposes.  The HTTP
   header field mapping works as defined in Section 8.1.2.3 ("Request
   Pseudo-Header Fields"), with a few differences.  Specifically:

   o  The ":method" pseudo-header field is set to "CONNECT".

   o  The ":scheme" and ":path" pseudo-header fields MUST be omitted.

   o  The ":authority" pseudo-header field contains the host and port to
      connect to (equivalent to the authority-form of the request-target
      of CONNECT requests (see [RFC7230], Section 5.3)).

   A CONNECT request that does not conform to these restrictions is
   malformed (Section 8.1.2.6).

   A proxy that supports CONNECT establishes a TCP connection [TCP] to
   the server identified in the ":authority" pseudo-header field.  Once
   this connection is successfully established, the proxy sends a
   HEADERS frame containing a 2xx series status code to the client, as
   defined in [RFC7231], Section 4.3.6.

   After the initial HEADERS frame sent by each peer, all subsequent
   DATA frames correspond to data sent on the TCP connection.  The
   payload of any DATA frames sent by the client is transmitted by the
   proxy to the TCP server; data received from the TCP server is
   assembled into DATA frames by the proxy.  Frame types other than DATA
   or stream management frames (RST_STREAM, WINDOW_UPDATE, and PRIORITY)
   MUST NOT be sent on a connected stream and MUST be treated as a
   stream error (Section 5.4.2) if received.

   The TCP connection can be closed by either peer.  The END_STREAM flag
   on a DATA frame is treated as being equivalent to the TCP FIN bit.  A
   client is expected to send a DATA frame with the END_STREAM flag set
   after receiving a frame bearing the END_STREAM flag.  A proxy that
   receives a DATA frame with the END_STREAM flag set sends the attached
   data with the FIN bit set on the last TCP segment.  A proxy that
   receives a TCP segment with the FIN bit set sends a DATA frame with
   the END_STREAM flag set.  Note that the final TCP segment or DATA
   frame could be empty.

   A TCP connection error is signaled with RST_STREAM.  A proxy treats
   any error in the TCP connection, which includes receiving a TCP
   segment with the RST bit set, as a stream error (Section 5.4.2) of
   type CONNECT_ERROR.  Correspondingly, a proxy MUST send a TCP segment
   with the RST bit set if it detects an error with the stream or the
   HTTP/2 connection.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

9.  Additional HTTP Requirements/Considerations

   This section outlines attributes of the HTTP protocol that improve
   interoperability, reduce exposure to known security vulnerabilities,
   or reduce the potential for implementation variation.


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

9.1.  Connection Management

   HTTP/2 connections are persistent.  For best performance, it is
   expected that clients will not close connections until it is
   determined that no further communication with a server is necessary
   (for example, when a user navigates away from a particular web page)
   or until the server closes the connection.

   Clients SHOULD NOT open more than one HTTP/2 connection to a given
   host and port pair, where the host is derived from a URI, a selected
   alternative service [ALT-SVC], or a configured proxy.

   A client can create additional connections as replacements, either to
   replace connections that are near to exhausting the available stream
   identifier space (Section 5.1.1), to refresh the keying material for
   a TLS connection, or to replace connections that have encountered
   errors (Section 5.4.1).

   A client MAY open multiple connections to the same IP address and TCP
   port using different Server Name Indication [TLS-EXT] values or to
   provide different TLS client certificates but SHOULD avoid creating
   multiple connections with the same configuration.

   Servers are encouraged to maintain open connections for as long as
   possible but are permitted to terminate idle connections if
   necessary.  When either endpoint chooses to close the transport-layer
   TCP connection, the terminating endpoint SHOULD first send a GOAWAY
   (Section 6.8) frame so that both endpoints can reliably determine
   whether previously sent frames have been processed and gracefully
   complete or terminate any necessary remaining tasks.


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

9.1.1.  Connection Reuse

   Connections that are made to an origin server, either directly or
   through a tunnel created using the CONNECT method (Section 8.3), MAY
   be reused for requests with multiple different URI authority
   components.  A connection can be reused as long as the origin server
   is authoritative (Section 10.1).  For TCP connections without TLS,
   this depends on the host having resolved to the same IP address.

   For "https" resources, connection reuse additionally depends on
   having a certificate that is valid for the host in the URI.  The
   certificate presented by the server MUST satisfy any checks that the
   client would perform when forming a new TLS connection for the host
   in the URI.

   An origin server might offer a certificate with multiple
   "subjectAltName" attributes or names with wildcards, one of which is
   valid for the authority in the URI.  For example, a certificate with
   a "subjectAltName" of "*.example.com" might permit the use of the
   same connection for requests to URIs starting with
   "https://a.example.com/" and "https://b.example.com/".

   In some deployments, reusing a connection for multiple origins can
   result in requests being directed to the wrong origin server.  For
   example, TLS termination might be performed by a middlebox that uses
   the TLS Server Name Indication (SNI) [TLS-EXT] extension to select an
   origin server.  This means that it is possible for clients to send
   confidential information to servers that might not be the intended
   target for the request, even though the server is otherwise
   authoritative.

   A server that does not wish clients to reuse connections can indicate
   that it is not authoritative for a request by sending a 421
   (Misdirected Request) status code in response to the request (see
   Section 9.1.2).

   A client that is configured to use a proxy over HTTP/2 directs
   requests to that proxy through a single connection.  That is, all
   requests sent via a proxy reuse the connection to the proxy.


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

9.1.2.  The 421 (Misdirected Request) Status Code

   The 421 (Misdirected Request) status code indicates that the request
   was directed at a server that is not able to produce a response.
   This can be sent by a server that is not configured to produce
   responses for the combination of scheme and authority that are
   included in the request URI.

   Clients receiving a 421 (Misdirected Request) response from a server
   MAY retry the request -- whether the request method is idempotent or
   not -- over a different connection.  This is possible if a connection
   is reused (Section 9.1.1) or if an alternative service is selected
   [ALT-SVC].

   This status code MUST NOT be generated by proxies.

   A 421 response is cacheable by default, i.e., unless otherwise
   indicated by the method definition or explicit cache controls (see
   Section 4.2.2 of [RFC7234]).


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

9.2.  Use of TLS Features

   Implementations of HTTP/2 MUST use TLS version 1.2 [TLS12] or higher
   for HTTP/2 over TLS.  The general TLS usage guidance in [TLSBCP]
   SHOULD be followed, with some additional restrictions that are
   specific to HTTP/2.

   The TLS implementation MUST support the Server Name Indication (SNI)
   [TLS-EXT] extension to TLS.  HTTP/2 clients MUST indicate the target
   domain name when negotiating TLS.

   Deployments of HTTP/2 that negotiate TLS 1.3 or higher need only
   support and use the SNI extension; deployments of TLS 1.2 are subject
   to the requirements in the following sections.  Implementations are
   encouraged to provide defaults that comply, but it is recognized that
   deployments are ultimately responsible for compliance.


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

9.2.1.  TLS 1.2 Features

   This section describes restrictions on the TLS 1.2 feature set that
   can be used with HTTP/2.  Due to deployment limitations, it might not
   be possible to fail TLS negotiation when these restrictions are not
   met.  An endpoint MAY immediately terminate an HTTP/2 connection that
   does not meet these TLS requirements with a connection error
   (Section 5.4.1) of type INADEQUATE_SECURITY.

   A deployment of HTTP/2 over TLS 1.2 MUST disable compression.  TLS
   compression can lead to the exposure of information that would not
   otherwise be revealed [RFC3749].  Generic compression is unnecessary
   since HTTP/2 provides compression features that are more aware of
   context and therefore likely to be more appropriate for use for
   performance, security, or other reasons.

   A deployment of HTTP/2 over TLS 1.2 MUST disable renegotiation.  An
   endpoint MUST treat a TLS renegotiation as a connection error
   (Section 5.4.1) of type PROTOCOL_ERROR.  Note that disabling

   renegotiation can result in long-lived connections becoming unusable
   due to limits on the number of messages the underlying cipher suite
   can encipher.

   An endpoint MAY use renegotiation to provide confidentiality
   protection for client credentials offered in the handshake, but any
   renegotiation MUST occur prior to sending the connection preface.  A
   server SHOULD request a client certificate if it sees a renegotiation
   request immediately after establishing a connection.

   This effectively prevents the use of renegotiation in response to a
   request for a specific protected resource.  A future specification
   might provide a way to support this use case.  Alternatively, a
   server might use an error (Section 5.4) of type HTTP_1_1_REQUIRED to
   request the client use a protocol that supports renegotiation.

   Implementations MUST support ephemeral key exchange sizes of at least
   2048 bits for cipher suites that use ephemeral finite field Diffie-
   Hellman (DHE) [TLS12] and 224 bits for cipher suites that use
   ephemeral elliptic curve Diffie-Hellman (ECDHE) [RFC4492].  Clients
   MUST accept DHE sizes of up to 4096 bits.  Endpoints MAY treat
   negotiation of key sizes smaller than the lower limits as a
   connection error (Section 5.4.1) of type INADEQUATE_SECURITY.


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

9.2.2.  TLS 1.2 Cipher Suites

   A deployment of HTTP/2 over TLS 1.2 SHOULD NOT use any of the cipher
   suites that are listed in the cipher suite black list (Appendix A).

   Endpoints MAY choose to generate a connection error (Section 5.4.1)
   of type INADEQUATE_SECURITY if one of the cipher suites from the
   black list is negotiated.  A deployment that chooses to use a black-
   listed cipher suite risks triggering a connection error unless the
   set of potential peers is known to accept that cipher suite.

   Implementations MUST NOT generate this error in reaction to the
   negotiation of a cipher suite that is not on the black list.
   Consequently, when clients offer a cipher suite that is not on the
   black list, they have to be prepared to use that cipher suite with
   HTTP/2.

   The black list includes the cipher suite that TLS 1.2 makes
   mandatory, which means that TLS 1.2 deployments could have non-
   intersecting sets of permitted cipher suites.  To avoid this problem
   causing TLS handshake failures, deployments of HTTP/2 that use TLS
   1.2 MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 [TLS-ECDHE]
   with the P-256 elliptic curve [FIPS186].

   Note that clients might advertise support of cipher suites that are
   on the black list in order to allow for connection to servers that do
   not support HTTP/2.  This allows servers to select HTTP/1.1 with a
   cipher suite that is on the HTTP/2 black list.  However, this can
   result in HTTP/2 being negotiated with a black-listed cipher suite if
   the application protocol and cipher suite are independently selected.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.  Security Considerations

10.1.  Server Authority

   HTTP/2 relies on the HTTP/1.1 definition of authority for determining
   whether a server is authoritative in providing a given response (see
   [RFC7230], Section 9.1).  This relies on local name resolution for
   the "http" URI scheme and the authenticated server identity for the
   "https" scheme (see [RFC2818], Section 3).

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.2.  Cross-Protocol Attacks

   In a cross-protocol attack, an attacker causes a client to initiate a
   transaction in one protocol toward a server that understands a
   different protocol.  An attacker might be able to cause the
   transaction to appear as a valid transaction in the second protocol.
   In combination with the capabilities of the web context, this can be
   used to interact with poorly protected servers in private networks.

   Completing a TLS handshake with an ALPN identifier for HTTP/2 can be
   considered sufficient protection against cross-protocol attacks.
   ALPN provides a positive indication that a server is willing to
   proceed with HTTP/2, which prevents attacks on other TLS-based
   protocols.

   The encryption in TLS makes it difficult for attackers to control the
   data that could be used in a cross-protocol attack on a cleartext
   protocol.

   The cleartext version of HTTP/2 has minimal protection against cross-
   protocol attacks.  The connection preface (Section 3.5) contains a
   string that is designed to confuse HTTP/1.1 servers, but no special
   protection is offered for other protocols.  A server that is willing
   to ignore parts of an HTTP/1.1 request containing an Upgrade header
   field in addition to the client connection preface could be exposed
   to a cross-protocol attack.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.3.  Intermediary Encapsulation Attacks

   The HTTP/2 header field encoding allows the expression of names that
   are not valid field names in the Internet Message Syntax used by
   HTTP/1.1.  Requests or responses containing invalid header field
   names MUST be treated as malformed (Section 8.1.2.6).  An
   intermediary therefore cannot translate an HTTP/2 request or response
   containing an invalid field name into an HTTP/1.1 message.

   Similarly, HTTP/2 allows header field values that are not valid.
   While most of the values that can be encoded will not alter header
   field parsing, carriage return (CR, ASCII 0xd), line feed (LF, ASCII
   0xa), and the zero character (NUL, ASCII 0x0) might be exploited by
   an attacker if they are translated verbatim.  Any request or response
   that contains a character not permitted in a header field value MUST
   be treated as malformed (Section 8.1.2.6).  Valid characters are
   defined by the "field-content" ABNF rule in Section 3.2 of [RFC7230].

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.4.  Cacheability of Pushed Responses

   Pushed responses do not have an explicit request from the client; the
   request is provided by the server in the PUSH_PROMISE frame.

   Caching responses that are pushed is possible based on the guidance
   provided by the origin server in the Cache-Control header field.
   However, this can cause issues if a single server hosts more than one
   tenant.  For example, a server might offer multiple users each a
   small portion of its URI space.

   Where multiple tenants share space on the same server, that server
   MUST ensure that tenants are not able to push representations of
   resources that they do not have authority over.  Failure to enforce
   this would allow a tenant to provide a representation that would be
   served out of cache, overriding the actual representation that the
   authoritative tenant provides.

   Pushed responses for which an origin server is not authoritative (see
   Section 10.1) MUST NOT be used or cached.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.5.  Denial-of-Service Considerations

   An HTTP/2 connection can demand a greater commitment of resources to
   operate than an HTTP/1.1 connection.  The use of header compression
   and flow control depend on a commitment of resources for storing a
   greater amount of state.  Settings for these features ensure that
   memory commitments for these features are strictly bounded.

   The number of PUSH_PROMISE frames is not constrained in the same
   fashion.  A client that accepts server push SHOULD limit the number
   of streams it allows to be in the "reserved (remote)" state.  An
   excessive number of server push streams can be treated as a stream
   error (Section 5.4.2) of type ENHANCE_YOUR_CALM.

   Processing capacity cannot be guarded as effectively as state
   capacity.

   The SETTINGS frame can be abused to cause a peer to expend additional
   processing time.  This might be done by pointlessly changing SETTINGS
   parameters, setting multiple undefined parameters, or changing the
   same setting multiple times in the same frame.  WINDOW_UPDATE or
   PRIORITY frames can be abused to cause an unnecessary waste of
   resources.

   Large numbers of small or empty frames can be abused to cause a peer
   to expend time processing frame headers.  Note, however, that some
   uses are entirely legitimate, such as the sending of an empty DATA or
   CONTINUATION frame at the end of a stream.

   Header compression also offers some opportunities to waste processing
   resources; see Section 7 of [COMPRESSION] for more details on
   potential abuses.

   Limits in SETTINGS parameters cannot be reduced instantaneously,
   which leaves an endpoint exposed to behavior from a peer that could
   exceed the new limits.  In particular, immediately after establishing
   a connection, limits set by a server are not known to clients and
   could be exceeded without being an obvious protocol violation.

   All these features -- i.e., SETTINGS changes, small frames, header
   compression -- have legitimate uses.  These features become a burden
   only when they are used unnecessarily or to excess.

   An endpoint that doesn't monitor this behavior exposes itself to a
   risk of denial-of-service attack.  Implementations SHOULD track the
   use of these features and set limits on their use.  An endpoint MAY
   treat activity that is suspicious as a connection error
   (Section 5.4.1) of type ENHANCE_YOUR_CALM.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.5.1.  Limits on Header Block Size

   A large header block (Section 4.3) can cause an implementation to
   commit a large amount of state.  Header fields that are critical for
   routing can appear toward the end of a header block, which prevents
   streaming of header fields to their ultimate destination.  This
   ordering and other reasons, such as ensuring cache correctness, mean

   that an endpoint might need to buffer the entire header block.  Since
   there is no hard limit to the size of a header block, some endpoints
   could be forced to commit a large amount of available memory for
   header fields.

   An endpoint can use the SETTINGS_MAX_HEADER_LIST_SIZE to advise peers
   of limits that might apply on the size of header blocks.  This
   setting is only advisory, so endpoints MAY choose to send header
   blocks that exceed this limit and risk having the request or response
   being treated as malformed.  This setting is specific to a
   connection, so any request or response could encounter a hop with a
   lower, unknown limit.  An intermediary can attempt to avoid this
   problem by passing on values presented by different peers, but they
   are not obligated to do so.

   A server that receives a larger header block than it is willing to
   handle can send an HTTP 431 (Request Header Fields Too Large) status
   code [RFC6585].  A client can discard responses that it cannot
   process.  The header block MUST be processed to ensure a consistent
   connection state, unless the connection is closed.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.5.2.  CONNECT Issues

   The CONNECT method can be used to create disproportionate load on an
   proxy, since stream creation is relatively inexpensive when compared
   to the creation and maintenance of a TCP connection.  A proxy might
   also maintain some resources for a TCP connection beyond the closing
   of the stream that carries the CONNECT request, since the outgoing
   TCP connection remains in the TIME_WAIT state.  Therefore, a proxy
   cannot rely on SETTINGS_MAX_CONCURRENT_STREAMS alone to limit the
   resources consumed by CONNECT requests.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.6.  Use of Compression

   Compression can allow an attacker to recover secret data when it is
   compressed in the same context as data under attacker control.
   HTTP/2 enables compression of header fields (Section 4.3); the
   following concerns also apply to the use of HTTP compressed content-
   codings ([RFC7231], Section 3.1.2.1).

   There are demonstrable attacks on compression that exploit the
   characteristics of the web (e.g., [BREACH]).  The attacker induces
   multiple requests containing varying plaintext, observing the length
   of the resulting ciphertext in each, which reveals a shorter length
   when a guess about the secret is correct.

   Implementations communicating on a secure channel MUST NOT compress
   content that includes both confidential and attacker-controlled data
   unless separate compression dictionaries are used for each source of
   data.  Compression MUST NOT be used if the source of data cannot be
   reliably determined.  Generic stream compression, such as that
   provided by TLS, MUST NOT be used with HTTP/2 (see Section 9.2).

   Further considerations regarding the compression of header fields are
   described in [COMPRESSION].

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.7.  Use of Padding

   Padding within HTTP/2 is not intended as a replacement for general
   purpose padding, such as might be provided by TLS [TLS12].  Redundant
   padding could even be counterproductive.  Correct application can
   depend on having specific knowledge of the data that is being padded.

   To mitigate attacks that rely on compression, disabling or limiting
   compression might be preferable to padding as a countermeasure.

   Padding can be used to obscure the exact size of frame content and is
   provided to mitigate specific attacks within HTTP, for example,
   attacks where compressed content includes both attacker-controlled
   plaintext and secret data (e.g., [BREACH]).

   Use of padding can result in less protection than might seem
   immediately obvious.  At best, padding only makes it more difficult
   for an attacker to infer length information by increasing the number
   of frames an attacker has to observe.  Incorrectly implemented
   padding schemes can be easily defeated.  In particular, randomized
   padding with a predictable distribution provides very little
   protection; similarly, padding payloads to a fixed size exposes
   information as payload sizes cross the fixed-sized boundary, which
   could be possible if an attacker can control plaintext.

   Intermediaries SHOULD retain padding for DATA frames but MAY drop
   padding for HEADERS and PUSH_PROMISE frames.  A valid reason for an
   intermediary to change the amount of padding of frames is to improve
   the protections that padding provides.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

10.8.  Privacy Considerations

   Several characteristics of HTTP/2 provide an observer an opportunity
   to correlate actions of a single client or server over time.  These
   include the value of settings, the manner in which flow-control
   windows are managed, the way priorities are allocated to streams, the
   timing of reactions to stimulus, and the handling of any features
   that are controlled by settings.

   As far as these create observable differences in behavior, they could
   be used as a basis for fingerprinting a specific client, as defined
   in Section 1.8 of [HTML5].

   HTTP/2's preference for using a single TCP connection allows
   correlation of a user's activity on a site.  Reusing connections for
   different origins allows tracking across those origins.

   Because the PING and SETTINGS frames solicit immediate responses,
   they can be used by an endpoint to measure latency to their peer.
   This might have privacy implications in certain scenarios.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.  IANA Considerations

   A string for identifying HTTP/2 is entered into the "Application-
   Layer Protocol Negotiation (ALPN) Protocol IDs" registry established
   in [TLS-ALPN].

   This document establishes a registry for frame types, settings, and
   error codes.  These new registries appear in the new "Hypertext
   Transfer Protocol version 2 (HTTP/2) Parameters" section.

   This document registers the HTTP2-Settings header field for use in
   HTTP; it also registers the 421 (Misdirected Request) status code.

   This document registers the "PRI" method for use in HTTP to avoid
   collisions with the connection preface (Section 3.5).

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.1.  Registration of HTTP/2 Identification Strings

   This document creates two registrations for the identification of
   HTTP/2 (see Section 3.3) in the "Application-Layer Protocol
   Negotiation (ALPN) Protocol IDs" registry established in [TLS-ALPN].

   The "h2" string identifies HTTP/2 when used over TLS:

   Protocol:  HTTP/2 over TLS

   Identification Sequence:  0x68 0x32 ("h2")

   Specification:  This document

   The "h2c" string identifies HTTP/2 when used over cleartext TCP:

   Protocol:  HTTP/2 over TCP

   Identification Sequence:  0x68 0x32 0x63 ("h2c")

   Specification:  This document

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.2.  Frame Type Registry

   This document establishes a registry for HTTP/2 frame type codes.
   The "HTTP/2 Frame Type" registry manages an 8-bit space.  The "HTTP/2
   Frame Type" registry operates under either of the "IETF Review" or
   "IESG Approval" policies [RFC5226] for values between 0x00 and 0xef,
   with values between 0xf0 and 0xff being reserved for Experimental
   Use.

   New entries in this registry require the following information:

   Frame Type:  A name or label for the frame type.

   Code:  The 8-bit code assigned to the frame type.

   Specification:  A reference to a specification that includes a
      description of the frame layout, its semantics, and flags that the
      frame type uses, including any parts of the frame that are
      conditionally present based on the value of flags.

   The entries in the following table are registered by this document.

   +---------------+------+--------------+
   | Frame Type    | Code | Section      |
   +---------------+------+--------------+
   | DATA          | 0x0  | Section 6.1  |
   | HEADERS       | 0x1  | Section 6.2  |
   | PRIORITY      | 0x2  | Section 6.3  |
   | RST_STREAM    | 0x3  | Section 6.4  |
   | SETTINGS      | 0x4  | Section 6.5  |
   | PUSH_PROMISE  | 0x5  | Section 6.6  |
   | PING          | 0x6  | Section 6.7  |
   | GOAWAY        | 0x7  | Section 6.8  |
   | WINDOW_UPDATE | 0x8  | Section 6.9  |
   | CONTINUATION  | 0x9  | Section 6.10 |
   +---------------+------+--------------+

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.3.  Settings Registry

   This document establishes a registry for HTTP/2 settings.  The
   "HTTP/2 Settings" registry manages a 16-bit space.  The "HTTP/2
   Settings" registry operates under the "Expert Review" policy
   [RFC5226] for values in the range from 0x0000 to 0xefff, with values
   between and 0xf000 and 0xffff being reserved for Experimental Use.

   New registrations are advised to provide the following information:

   Name:  A symbolic name for the setting.  Specifying a setting name is
      optional.

   Code:  The 16-bit code assigned to the setting.

   Initial Value:  An initial value for the setting.

   Specification:  An optional reference to a specification that
      describes the use of the setting.

   The entries in the following table are registered by this document.

   +------------------------+------+---------------+---------------+
   | Name                   | Code | Initial Value | Specification |
   +------------------------+------+---------------+---------------+
   | HEADER_TABLE_SIZE      | 0x1  | 4096          | Section 6.5.2 |
   | ENABLE_PUSH            | 0x2  | 1             | Section 6.5.2 |
   | MAX_CONCURRENT_STREAMS | 0x3  | (infinite)    | Section 6.5.2 |
   | INITIAL_WINDOW_SIZE    | 0x4  | 65535         | Section 6.5.2 |
   | MAX_FRAME_SIZE         | 0x5  | 16384         | Section 6.5.2 |
   | MAX_HEADER_LIST_SIZE   | 0x6  | (infinite)    | Section 6.5.2 |
   +------------------------+------+---------------+---------------+

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.4.  Error Code Registry

   This document establishes a registry for HTTP/2 error codes.  The
   "HTTP/2 Error Code" registry manages a 32-bit space.  The "HTTP/2
   Error Code" registry operates under the "Expert Review" policy
   [RFC5226].

   Registrations for error codes are required to include a description
   of the error code.  An expert reviewer is advised to examine new
   registrations for possible duplication with existing error codes.
   Use of existing registrations is to be encouraged, but not mandated.

   New registrations are advised to provide the following information:

   Name:  A name for the error code.  Specifying an error code name is
      optional.

   Code:  The 32-bit error code value.

   Description:  A brief description of the error code semantics, longer
      if no detailed specification is provided.

   Specification:  An optional reference for a specification that
      defines the error code.

   The entries in the following table are registered by this document.

   +---------------------+------+----------------------+---------------+
   | Name                | Code | Description          | Specification |
   +---------------------+------+----------------------+---------------+
   | NO_ERROR            | 0x0  | Graceful shutdown    | Section 7     |
   | PROTOCOL_ERROR      | 0x1  | Protocol error       | Section 7     |
   |                     |      | detected             |               |
   | INTERNAL_ERROR      | 0x2  | Implementation fault | Section 7     |
   | FLOW_CONTROL_ERROR  | 0x3  | Flow-control limits  | Section 7     |
   |                     |      | exceeded             |               |
   | SETTINGS_TIMEOUT    | 0x4  | Settings not         | Section 7     |
   |                     |      | acknowledged         |               |
   | STREAM_CLOSED       | 0x5  | Frame received for   | Section 7     |
   |                     |      | closed stream        |               |
   | FRAME_SIZE_ERROR    | 0x6  | Frame size incorrect | Section 7     |
   | REFUSED_STREAM      | 0x7  | Stream not processed | Section 7     |
   | CANCEL              | 0x8  | Stream cancelled     | Section 7     |
   | COMPRESSION_ERROR   | 0x9  | Compression state    | Section 7     |
   |                     |      | not updated          |               |
   | CONNECT_ERROR       | 0xa  | TCP connection error | Section 7     |
   |                     |      | for CONNECT method   |               |
   | ENHANCE_YOUR_CALM   | 0xb  | Processing capacity  | Section 7     |
   |                     |      | exceeded             |               |
   | INADEQUATE_SECURITY | 0xc  | Negotiated TLS       | Section 7     |
   |                     |      | parameters not       |               |
   |                     |      | acceptable           |               |
   | HTTP_1_1_REQUIRED   | 0xd  | Use HTTP/1.1 for the | Section 7     |
   |                     |      | request              |               |
   +---------------------+------+----------------------+---------------+

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.5.  HTTP2-Settings Header Field Registration

   This section registers the HTTP2-Settings header field in the
   "Permanent Message Header Field Names" registry [BCP90].

   Header field name:  HTTP2-Settings

   Applicable protocol:  http

   Status:  standard

   Author/Change controller:  IETF

   Specification document(s):  Section 3.2.1 of this document

   Related information:  This header field is only used by an HTTP/2
      client for Upgrade-based negotiation.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.6.  PRI Method Registration

   This section registers the "PRI" method in the "HTTP Method Registry"
   ([RFC7231], Section 8.1).

   Method Name:  PRI

   Safe:  Yes

   Idempotent:  Yes

   Specification document(s):  Section 3.5 of this document

   Related information:  This method is never used by an actual client.
      This method will appear to be used when an HTTP/1.1 server or
      intermediary attempts to parse an HTTP/2 connection preface.

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.7.  The 421 (Misdirected Request) HTTP Status Code

   This document registers the 421 (Misdirected Request) HTTP status
   code in the "HTTP Status Codes" registry ([RFC7231], Section 8.2).

   Status Code:  421

   Short Description:  Misdirected Request

   Specification:  Section 9.1.2 of this document

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>

11.8.  The h2c Upgrade Token

   This document registers the "h2c" upgrade token in the "HTTP Upgrade
   Tokens" registry ([RFC7230], Section 8.6).

   Value:  h2c

   Description:  Hypertext Transfer Protocol version 2 (HTTP/2)

   Expected Version Tokens:  None

   Reference:  Section 3.2 of this document

</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>


<details>
<summary>原文</summary>
<pre>
<code>


</code>
</pre>
</details>
