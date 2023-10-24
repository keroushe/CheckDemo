#/bin/sh

set -o errexit

# cd到sh脚本路径下
cd "$(dirname "$0")";

## 这里放所有需要查找的符号
symbols=("CCMD5", "CCCrypt")
for i in ${symbols[@]}; do
	# 工程路径改为工程目录
	sh ./find_symbol.sh "工程路径" "$i"
done

