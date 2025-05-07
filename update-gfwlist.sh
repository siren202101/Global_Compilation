#!/bin/bash

# 设置下载 URL
GFWLIST_URL="https://raw.githubusercontent.com/siren202101/Global_Compilation/refs/heads/main/output/processed.txt"
GFWLIST_FILE="gfwlist"

# 备份旧的 gfwlist 文件
if [ -f "$GFWLIST_FILE" ]; then
    cp "$GFWLIST_FILE" "$GFWLIST_FILE.bak"
fi

# 下载最新的 gfwlist
curl -L "$GFWLIST_URL" -o "$GFWLIST_FILE"

# 检查下载是否成功
if [ $? -eq 0 ]; then
    echo "gfwlist 更新成功！"
else
    echo "gfwlist 更新失败，恢复旧版本。"
    mv "$GFWLIST_FILE.bak" "$GFWLIST_FILE"
fi
