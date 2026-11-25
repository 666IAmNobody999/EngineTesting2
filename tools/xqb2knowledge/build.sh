#!/bin/sh
# 编译 xqb2knowledge（需要 SQLite amalgamation，会自动下载）
#   Linux：  sh build.sh
#   Windows：sh build.sh win   （用 MinGW-w64 交叉编译，生成 xqb2knowledge.exe）
set -e
cd "$(dirname "$0")"
S=sqlite-amalgamation-3500400
[ -d $S ] || { curl -sSLo sq.zip https://www.sqlite.org/2025/$S.zip && unzip -q sq.zip && rm sq.zip; }
F="-O2 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0"
if [ "$1" = win ]; then
    x86_64-w64-mingw32-gcc $F -c $S/sqlite3.c -o sqlite3_w.o
    x86_64-w64-mingw32-g++ -O2 -std=c++17 -municode -I$S xqb2knowledge.cpp sqlite3_w.o -static -s -o xqb2knowledge.exe
else
    gcc $F -c $S/sqlite3.c -o sqlite3.o
    g++ -O2 -std=c++17 -I$S xqb2knowledge.cpp sqlite3.o -o xqb2knowledge
fi
