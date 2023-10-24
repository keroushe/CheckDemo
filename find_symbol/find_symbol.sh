
# usage : ./find_symbol.sh <工程目录> <要查找的函数名>
# ‼️‼️ 不要直接在这里改工程目录，终端执行时传递参数就行了 ‼️‼️

if [ $# != 2 ] ; then
echo "usage : $0 <工程目录> <要查找的函数名>"
echo " e.g.: $0 ~/Desktop/workspace/demo _CC_MD5"
exit 1
fi

path=$1
symbol=$2
echo "查找工程目录: $path"
echo "查找符号名: $symbol"

for file in $(find $path -name "*.a")
do
	echo "\n开始查找库文件: $file"
	nm -pa $file | grep $symbol
	echo "==========================结束\n"
done

for framework in $(find $path -name "*.framework")
do
	echo "\n开始查找库文件: $framework"
	framework_name=$(basename $framework .framework)
	nm -pa "$framework/$framework_name" | grep $symbol
	echo "==========================结束\n"
done