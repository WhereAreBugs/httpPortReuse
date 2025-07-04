### HTTP Port Reuse
#### 这是什么？
一个很早期的项目。原始需求是需要在openwrt中同一个端口同时运行一个http服务和一个其他的二进制协议的服务，且都不允许我修改默认端口。<br>
原理很简单，本程序作为反代，根据协议类型提取出http流量，转发到一个反代的端口。否则转发到另一个端口。将服务区分开。适用于极致的端口复用。
> 早期开发阶段，功能还十分简单。后续会添加更多协议的支持。

> 由于功能逐渐增加，现正在计划修改项目名
#### TODO
- [x] 实现基础的反代功能
- [x] 提取http/TLS流量，进行分流
- [x] 反向代理http/https时支持proxy_protocol_v2
- [ ] 支持TLS SNI提取，根据SNI进一步分流
- [ ] 添加CI/CD自动化构建和发布release
- [ ] 支持ssh用户名分流
- [ ] 支持更多的协议 (rtsp etc...)
- [ ] 支持使用uci配置文件统一配置
- [ ] 开发luci界面，便于配置
- [ ] 支持多个混合端口
#### 编译教程
在你的openwrt仓库根，运行以下代码:
```shell
git clone {本仓库地址} package/httpPortReuse
```
之后在Network -> Routing and Redirection下即可配置加入编译
#### 后记
> 欢迎Pr和Issue。