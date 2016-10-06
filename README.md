Local DNS服务器。[![Build Status](https://travis-ci.org/ayanamist/gdns-go.png?branch=master)](https://travis-ci.org/shadowsocks/shadowsocks-go)

1. 服务端是[Google HTTPS DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https)

2. 通过ShadowSocks解决访问问题。

3. 通过传递探测到的公网IP作为edns0 subnet的参数来解决CDN解析出美国IP而不是中国IP的问题。

4. 公网IP探测使用了[淘宝的API](http://ip.taobao.com/instructions.php)。

5. 自带域名分流功能，但设计目标仅针对公司内网域名服务，不需要把常用国内网站加入，由于第3点，不会受到SS服务器IP的影响（SS服务器在美国依然能解析出中国IP）

6. 通过HTTP 2.0解决传统DNS over TCP缓慢的问题。

----

已知问题：

1. 连接了AnyConnect VPN后，AnyConnect Windows Client会阻断访问本地53端口的DNS，导致无法使用。