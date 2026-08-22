# 查找客户端的 add.list 文件有内容的,列出来
find . -path "*/Clash/custom/add.list" -type f ! -empty
find . -path "*/Loon/custom/add.list" -type f ! -empty
find . -path "*/QuantumultX/custom/add.list" -type f ! -empty
find . -path "*/Shadowrocket/custom/add.list" -type f ! -empty
find . -path "*/Surge/custom/add.list" -type f ! -empty

# 查找 全局 add.list 文件有内容的,列出来
find . -path "*/z-custom/add.list" -type f ! -empty
