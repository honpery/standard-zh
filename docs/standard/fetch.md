---
sidebarDepth: 4
---

# Fetch

> Fetch [原文链接](https://fetch.spec.whatwg.org/)

### 摘要

Fetch标准定义了请求、响应以及绑定它们的过程：获取。

<details>
<summary>原文</summary>
<pre>
<code>

Abstract

The Fetch standard defines requests, responses, and the process that binds them: fetching.

</code>
</pre>
</details>

### 目标

目标是统一跨Web平台的获取并提供涉及所有内容的一致处理，包括：

  - URL方案
  - 重定向
  - 跨源语义
  - CSP [CSP]
  - Service workers[SW]
  - 混合内容[MIX]
  - `Referer` [REFERRER]

取代最初在Web Origin概念中定义的HTTP`Origin`标头语义。 [起源]

<details>
<summary>原文</summary>
<pre>
<code>

Goals
The goal is to unify fetching across the web platform and provide consistent handling of everything that involves, including:

URL schemes
Redirects
Cross-origin semantics
CSP [CSP]
Service workers [SW]
Mixed Content [MIX]
`Referer` [REFERRER]
To do so it also supersedes the HTTP `Origin` header semantics originally defined in The Web Origin Concept. [ORIGIN]

</code>
</pre>
</details>

