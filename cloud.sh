#!/usr/bin/env bash
# ---------- 从 JSON 读取 ----------
CONFIG_FILE="alipan_config.json"


get_json_raw() {
    awk -F'"' -v k="$1" '
        $2 == k {
            
            val=$0; sub(/^[^:]*:[[:space:]]*"/,"",val); sub(/"[[:space:]]*,?[[:space:]]*$/,"",val);
         
            gsub(/\\"/,"\"",val);
            print val;
            exit;
        }
    ' "$CONFIG_FILE"
}



set_json_val() {
    key=$1
    val=$2
    file=$3
    tmp=$(mktemp)
    awk -v k="$key" -v v="$val" '
        BEGIN{FS=":"; OFS=":"}
        $0 ~ "\"" k "\"" {
           
            sub(/:[[:space:]]*".*"/, ": \"" v "\"");
        }
        {print}
    ' "$file" > "$tmp" && mv "$tmp" "$file"
}

CLIENT_ID=$(get_json_raw "CLIENT_ID")
code=$(get_json_raw "code")
client_secret=$(get_json_raw "client_secret")
ACCESS_TOKEN=$(get_json_raw "ACCESS_TOKEN")
REFRESH_TOKEN=$(get_json_raw "REFRESH_TOKEN")
drive_id=$(get_json_raw "drive_id")
parent_file_id=$(get_json_raw "parent_file_id")



# ---------- 原有逻辑 ----------
if [[ -z "$code" ]]; then
    echo "访问获取 code："
    echo "https://www.alipan.com/o/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=oob&scope=user:base,file:all:read,file:all:write&style=folder"
    exit 0
fi

JSON_PAYLOAD=$(cat <<EOF
{
  "client_id":     "$CLIENT_ID",
  "client_secret": "$client_secret",
  "grant_type":    "authorization_code",
  "code":          "$code"
}
EOF
)

# ---------- 首次拿到 ACCESS_TOKEN 时记录“发放时间” ----------
if [[ -z "$REFRESH_TOKEN" && -z "$ACCESS_TOKEN" ]]; then
    RESPONSE=$(curl -sS -X POST "https://openapi.alipan.com/oauth/access_token" \
                    -H "Content-Type: application/json" \
                    -d "$JSON_PAYLOAD")

    ACCESS_TOKEN=$(echo "$RESPONSE"  | grep -o '"access_token":"[^"]*'  | sed 's/"access_token":"//')
    REFRESH_TOKEN=$(echo "$RESPONSE" | grep -o '"refresh_token":"[^"]*' | sed 's/"refresh_token":"//')

    # 记录当前时间戳（秒）
    expire_time=$(date +%s)

    set_json_val "ACCESS_TOKEN"  "$ACCESS_TOKEN"  "$CONFIG_FILE"
    set_json_val "REFRESH_TOKEN" "$REFRESH_TOKEN" "$CONFIG_FILE"
    set_json_val "expire_time"      "$expire_time"      "$CONFIG_FILE"

    echo "首次 ACCESS_TOKEN 已写入，记录发放时间 $expire_time"
fi

# ---------- 后续运行：判断是否 ≥ 2700 秒 ----------
# 读取上次记录的发放时间
expire_time=$(get_json_raw "expire_time")
expire_time=${expire_time:-0}          # 若为空则置 0

now=$(date +%s)
elapsed=$(( now - expire_time ))

if [[ $elapsed -ge 6500 ]]; then
    REFRESH_PAYLOAD=$(cat <<EOF
{
  "client_id":     "$CLIENT_ID",
  "client_secret": "$client_secret",
  "grant_type":    "refresh_token",
  "refresh_token": "$REFRESH_TOKEN"
}
EOF
)

    REFRESH_RESP=$(
      curl -sS -X POST "https://openapi.alipan.com/oauth/access_token" \
           -H "Content-Type: application/json" \
           -d "$REFRESH_PAYLOAD"
    )

    NEW_ACCESS=$(echo "$REFRESH_RESP"  | grep -o '"access_token":"[^"]*'  | sed 's/"access_token":"//')
    NEW_REFRESH=$(echo "$REFRESH_RESP" | grep -o '"refresh_token":"[^"]*' | sed 's/"refresh_token":"//')

    if [[ -n "$NEW_ACCESS" ]]; then
        ACCESS_TOKEN=$NEW_ACCESS
        set_json_val "ACCESS_TOKEN" "$ACCESS_TOKEN" "$CONFIG_FILE"
    fi
    if [[ -n "$NEW_REFRESH" ]]; then
        REFRESH_TOKEN=$NEW_REFRESH
        set_json_val "REFRESH_TOKEN" "$REFRESH_TOKEN" "$CONFIG_FILE"
    fi

    # 重新记录新的发放时间
    expire_time=$(date +%s)
    set_json_val "expire_time" "$expire_time" "$CONFIG_FILE"

    echo "已刷新 ACCESS_TOKEN，重新计时"
fi


if [[ -z "$drive_id" && -z "$parent_file_id" ]]; then
    INFO=$(
      curl -sS -X POST "https://openapi.alipan.com/adrive/v1.0/user/getDriveInfo" \
           -H "Authorization: Bearer ${ACCESS_TOKEN}"
    )
    drive_id=$(echo "$INFO" | grep -o '"default_drive_id":"[^"]*' | sed 's/"default_drive_id":"//')
    parent_file_id=$(echo "$INFO" | grep -o '"folder_id":"[^"]*' | sed 's/"folder_id":"//')       # 默认根目录，可自行修改

    # 写回配置文件
    set_json_val "drive_id"        "$drive_id"        "$CONFIG_FILE"
    set_json_val "parent_file_id"  "$parent_file_id"  "$CONFIG_FILE"
    
fi



CREATE_RESP=$(
  curl -sS -X POST "https://open.aliyundrive.com/adrive/v1.0/openFile/create" \
       -H "Authorization: Bearer ${ACCESS_TOKEN}" \
       -H "Content-Type: application/json" \
       -d '{
             "drive_id": "'"$drive_id"'",
             "parent_file_id": "'"$parent_file_id"'",
             "name": "'$(basename "$1")'",
             "type": "file",
             "check_name_mode": "auto_rename"
           }'
)

UPLOAD_URL=$(grep -o '"upload_url":"[^"]*' <<<"$CREATE_RESP" | cut -d'"' -f4)
file_id=$(grep -o '"file_id":"[^"]*' <<<"$CREATE_RESP" | cut -d'"' -f4)
upload_id=$(grep -o '"upload_id":"[^"]*' <<<"$CREATE_RESP" | cut -d'"' -f4)

UPLOAD_RESULT=$(
  curl -sS -X PUT "$UPLOAD_URL" \
       -H "Content-Type:" \
       --data-binary @"$1" \
       -w "\n%{http_code}"
)



COMPLETE_URL="https://open.aliyundrive.com/adrive/v1.0/openFile/complete"

COMPLETE_RESP=$(
  curl -sS -X POST "$COMPLETE_URL" \
       -H "Authorization: Bearer ${ACCESS_TOKEN}" \
       -H "Content-Type: application/json" \
       -d "{
             \"drive_id\": \"$drive_id\",
             \"file_id\": \"$file_id\",
             \"upload_id\": \"$upload_id\"
           }"
)



if echo "$COMPLETE_RESP" | grep -q '"file_id"'; then
    echo "文件上传成功，删除本地文件: $1"
    rm -- "$1"
else
    echo "文件上传失败，保留本地文件"
    echo "响应: $COMPLETE_RESP"
fi