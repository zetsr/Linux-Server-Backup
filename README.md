# Linux-Server-Backup
从Linux服务器传输文件到Windows，自动生成格式化日期名称的文件夹用于分类。

### servers.cfg
```
[s1]
ip = "192.168.1.1"
port = "22"
user = "root"
password = "pw"
server_dir = "/home/game/myserver/saved"
pc_dir = "D:\backup\myserver"

[s2]
ip = "192.168.2.1"
port = "1222"
user = "backup"
password = "pw"
server_dir = "/root/csgo_ds/csgo/addons/sourcemod/data/sqlite"
pc_dir = "D:\backup\csgo_ds"
```
