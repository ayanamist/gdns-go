Google DoH客户端

1. 服务端是[Google HTTPS DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https)

2. 必须配置socks5代理或http代理才能使用。

3. 支持配置edns0 subnet参数来解决CDN解析出美国IP而不是中国IP的问题。

4. 支持HTTP 2.0

----

已知问题：

1. 连接了AnyConnect VPN后，AnyConnect Windows Client会阻断访问本地53端口的DNS，导致无法使用。