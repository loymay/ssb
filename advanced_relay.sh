#!/bin/bash

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 全局变量 ---
# 主脚本配置路径（落地机和中转机共用）
MAIN_CONFIG_FILE="/usr/local/etc/sing-box/config.json"
MAIN_METADATA_FILE="/usr/local/etc/sing-box/metadata.json"

# 辅助文件目录（用于存储中转机的证书和链接信息）
RELAY_AUX_DIR="/usr/local/etc/sing-box"
# 中转机专用 YAML 配置文件
RELAY_CLASH_YAML="${RELAY_AUX_DIR}/clash.yaml"
# 中转/适配层专用 JSON 配置文件 (隔离配置)
RELAY_CONFIG_FILE="${RELAY_AUX_DIR}/relay.json"

SINGBOX_BIN="/usr/local/bin/sing-box"

# --- 辅助函数 ---
_info() { echo -e "${CYAN}[信息] $1${NC}"; }
_success() { echo -e "${GREEN}[成功] $1${NC}"; }
_warn() { echo -e "${YELLOW}[注意] $1${NC}"; }
_error() { echo -e "${RED}[错误] $1${NC}"; }
_pause() { 
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

# 检测初始化系统
_detect_init_system() {
    if [ -d "/run/systemd/system" ] || command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
    elif [ -f "/sbin/openrc-run" ] || command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="unknown"
    fi
}

# 服务管理函数
_manage_service() {
    local action="$1"
    local service_name="sing-box"
    
    [ -z "$INIT_SYSTEM" ] && _detect_init_system
    
    case "$INIT_SYSTEM" in
        systemd)
            systemctl "$action" "$service_name"
            ;;
        openrc)
            rc-service "$service_name" "$action"
            ;;
        *)
            return 1
            ;;
    esac
}

# 日志记录函数
_log_operation() {
    local operation="$1"
    local details="$2"
    local LOG_FILE="${RELAY_AUX_DIR}/relay_operations.log"
    [ -d "$RELAY_AUX_DIR" ] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] $operation: $details" >> "$LOG_FILE"
}

# 获取公网IP
_get_public_ip() {
    local ip=""
    # 尝试多个源获取IP
    ip=$(curl -s4 --max-time 3 icanhazip.com 2>/dev/null)
    if [ -z "$ip" ]; then
        ip=$(curl -s4 --max-time 3 ipinfo.io/ip 2>/dev/null)
    fi
    if [ -z "$ip" ]; then
        ip=$(curl -s6 --max-time 3 icanhazip.com 2>/dev/null)
    fi
    
    if [ -z "$ip" ]; then
        # 最后的手段：提示用户输入
        _warn "无法自动获取公网IP"
        read -p "请手动输入本服务器公网IP: " ip
    fi
    
    # 简单的IP格式验证
    if [[ -z "$ip" ]]; then
        ip="YOUR_IP_ADDRESS"
    fi
    echo "$ip"
}

# 获取地区旗帜 (Emoji)
_get_country_flag() {
    # 优先使用 ipapi.co
    local country_code=$(curl -s --max-time 2 https://ipapi.co/country/ 2>/dev/null)
    
    # 备用 ip-api.com
    if [ -z "$country_code" ] || [ ${#country_code} -ne 2 ]; then
        local raw=$(curl -s --max-time 2 http://ip-api.com/line/?fields=countryCode 2>/dev/null)
        if [[ "$raw" =~ ^[A-Z]{2}$ ]]; then
            country_code="$raw"
        fi
    fi

    # 验证是否为2位字母
    if [[ ! "$country_code" =~ ^[a-zA-Z]{2}$ ]]; then
        echo ""
        return
    fi

    # 转换为大写
    country_code=$(echo "$country_code" | tr '[:lower:]' '[:upper:]')

    # 计算 Emoji
    local flag=""
    for (( i=0; i<${#country_code}; i++ )); do
        local char="${country_code:$i:1}"
        local ascii_val=$(printf "%d" "'$char")
        local emoji_val=$((ascii_val + 127397))
        # 使用更稳健的方式渲染 Emoji: 直接构造 UTF-8 字节序列或使用标准的 bash 4.2+ \U
        # 对大多数现代 bash 环境，\U 是最稳健的
        local hex=$(printf "%08x" $emoji_val)
        local f=$(printf "\\U$hex" 2>/dev/null || echo -e "\\U$hex")
        flag+="$f"
    done
    echo "$flag"
}

# YAML 操作辅助函数 (保留原逻辑)
_add_node_to_relay_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    local YQ_BINARY="/usr/local/bin/yq"

    if [ ! -f "$YQ_BINARY" ] || [ ! -f "$RELAY_CLASH_YAML" ]; then
        return
    fi

    local temp_json="/tmp/relay_node_$$.json"
    echo "$proxy_json" > "$temp_json"
    ${YQ_BINARY} eval ".proxies += [$(cat $temp_json)]" -i "$RELAY_CLASH_YAML" 2>/dev/null
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "中转节点") | .proxies += [env(PROXY_NAME)] | .proxies |= unique)' -i "$RELAY_CLASH_YAML" 2>/dev/null
    rm -f "$temp_json"
    _info "已更新 Clash 订阅配置"
}

_remove_node_from_relay_yaml() {
    local proxy_name="$1"
    local YQ_BINARY="/usr/local/bin/yq"
    if [ ! -f "$YQ_BINARY" ] || [ ! -f "$RELAY_CLASH_YAML" ]; then return; fi

    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval 'del(.proxies[] | select(.name == env(PROXY_NAME)))' -i "$RELAY_CLASH_YAML" 2>/dev/null
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "中转节点") | .proxies |= del(.[] | select(. == env(PROXY_NAME))))' -i "$RELAY_CLASH_YAML" 2>/dev/null
}

# 初始化目录和文件
_init_relay_dirs() {
    mkdir -p "$RELAY_AUX_DIR"

    # 初始化 relay_links.json
    if [ ! -f "${RELAY_AUX_DIR}/relay_links.json" ]; then
        echo '{}' > "${RELAY_AUX_DIR}/relay_links.json"
    fi

    # 初始化 relay.json
    if [ ! -f "$RELAY_CONFIG_FILE" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE"
    fi

    # 初始化 clash.yaml (简化版，仅用于订阅)
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        cat > "$RELAY_CLASH_YAML" << 'EOF'
proxies: []
proxy-groups:
  - name: 中转节点
    type: select
    proxies: []
rules:
  - MATCH,中转节点
EOF
    fi
}

_check_deps() {
    if ! command -v jq &>/dev/null; then
        _error "缺少 'jq' 工具，请先安装: apt install jq 或 yum install jq"
        exit 1
    fi
    _init_relay_dirs
}

# ==============================================
#  解析函数集
# ==============================================

_parse_vless_share_link() {
    local link="$1"
    
    local uuid=$(echo "$link" | sed -n 's/vless:\/\/\([^@]*\)@.*/\1/p')
    local server_port=$(echo "$link" | sed -n 's/.*@\([^?#]*\).*/\1/p')
    local server=""
    local port=""
    
    if [[ "$server_port" == "["* ]]; then
        server=$(echo "$server_port" | sed -n 's/\[\(.*\)\]:.*/\1/p')
        port=$(echo "$server_port" | sed -n 's/.*\]:\(.*\)/\1/p')
    else
        server=$(echo "$server_port" | cut -d: -f1)
        port=$(echo "$server_port" | cut -d: -f2)
    fi
    
    local query=$(echo "$link" | grep -oP '\?\K[^#]*' 2>/dev/null || echo "")
    
    local flow=""
    local security="none"
    local sni=""
    local pbk=""
    local sid=""
    local fp="chrome"
    local network="tcp"
    local path="/"
    local serviceName=""

    IFS='&' read -ra PARAM_ARRAY <<< "$query"
    for param in "${PARAM_ARRAY[@]}"; do
        local key=$(echo "$param" | cut -d= -f1)
        local value=$(echo "$param" | cut -d= -f2-)
        case "$key" in
            "flow") flow="$value" ;;
            "security") security="$value" ;;
            "sni"|"servername") sni="$value" ;;
            "pbk") pbk="$value" ;;
            "sid") sid="$value" ;;
            "fp") fp="$value" ;;
            "type"|"network") network="$value" ;;
            "path") path=$(echo "$value" | sed 's/%2F/\//g') ;;
            "serviceName") serviceName="$value" ;;
        esac
    done

    # 构造 outbound
    jq -n \
        --arg s "$server" --arg p "$port" --arg u "$uuid" \
        --arg sec "$security" --arg net "$network" --arg sni "$sni" \
        --arg flow "$flow" --arg pbk "$pbk" --arg sid "$sid" --arg fp "$fp" \
        --arg path "$path" --arg snm "$serviceName" \
        '{
            type: "vless",
            server: $s,
            server_port: ($p|tonumber),
            uuid: $u,
            flow: $flow,
            network: $net,
            packet_encoding: "xudp",
            tls: (if ($sec == "tls" or $sec == "reality") then {
                enabled: true,
                server_name: $sni,
                utls: { enabled: true, fingerprint: $fp }
            } else { enabled: false } end)
        } | 
        if ($sec == "reality") then 
            .tls.reality = { enabled: true, public_key: $pbk, short_id: $sid }
        else . end |
        if ($net == "ws") then 
            .transport = {type: "ws", path: $path, headers: {Host: $sni}} 
        elif ($net == "grpc") then 
            .transport = {type: "grpc", service_name: $snm}
        else . end'
}

_parse_vmess_share_link() {
    local link="$1"
    local json=$(echo "$link" | sed 's/vmess:\/\///' | base64 -d 2>/dev/null)
    if [ -z "$json" ]; then return 1; fi
    
    jq -n --argjson data "$json" \
        '{
            type: "vmess",
            server: ($data.add),
            server_port: ($data.port|tonumber),
            uuid: ($data.id),
            alter_id: ($data.aid // 0 | tonumber),
            network: ($data.net // "tcp"),
            tls: (if ($data.tls == "tls") then {
                enabled: true,
                server_name: ($data.sni // $data.host // "")
            } else {
                enabled: false
            } end)
        } |
        if (.network == "ws") then
            .transport = {type: "ws", path: ($data.path // "/"), headers: {Host: ($data.host // "")}}
        elif (.network == "grpc") then
            .transport = {type: "grpc", service_name: ($data.path // "")}
        else . end |
        .packet_encoding = "xudp"'
}

_parse_shadowsocks_share_link() {
    local link="$1"
    # ss://base64(method:password)@server:port#name
    # 或 ss://method:password@server:port#name
    local main=$(echo "$link" | sed 's/ss:\/\///; s/#.*//')
    
    local userinfo=""
    local server_port=""
    
    if [[ "$main" == *.* ]]; then
        # 可能是未base64的格式 user:pass@ip:port
        # 但标准 URL encoding 中 @ 之前是 userinfo
        if echo "$main" | grep -q "@"; then
            userinfo=$(echo "$main" | cut -d@ -f1)
            server_port=$(echo "$main" | cut -d@ -f2)
        else
            # 可能是旧版 base64(method:password@server:port)
            local decoded=$(echo "$main" | base64 -d 2>/dev/null)
            if [ -n "$decoded" ]; then
                userinfo=$(echo "$decoded" | cut -d@ -f1)
                server_port=$(echo "$decoded" | cut -d@ -f2)
            fi
        fi
    fi

    # 如果 userinfo 还是空的，可能是 pure base64 userinfo
    if [ -z "$userinfo" ]; then
        # 尝试标准解析: userinfo@server:port
        userinfo=$(echo "$main" | cut -d@ -f1)
        server_port=$(echo "$main" | cut -d@ -f2)
    fi

    local method=""
    local password=""
    
    # 检查 userinfo 是否 base64 编码 (含冒号一般没编码，不含冒号可能编码了)
    if [[ "$userinfo" != *:* ]]; then
        local decoded=$(echo "$userinfo" | base64 -d 2>/dev/null)
        if [[ "$decoded" == *:* ]]; then
             method=$(echo "$decoded" | cut -d: -f1)
             password=$(echo "$decoded" | cut -d: -f2-)
        fi
    else
        method=$(echo "$userinfo" | cut -d: -f1)
        password=$(echo "$userinfo" | cut -d: -f2-)
    fi
    
    local server=$(echo "$server_port" | cut -d: -f1)
    local port=$(echo "$server_port" | cut -d: -f2)
    
    jq -n \
        --arg s "$server" --arg p "$port" \
        --arg m "$method" --arg pw "$password" \
        '{
            type: "shadowsocks",
            server: $s,
            server_port: ($p|tonumber),
            method: $m,
            password: $pw
        }'
}

_parse_trojan_share_link() {
    local link="$1"
    # trojan://password@server:port?sni=xxx#name
    local password=$(echo "$link" | sed -n 's/trojan:\/\/\([^@]*\)@.*/\1/p')
    local server_port=$(echo "$link" | sed -n 's/.*@\([^?#]*\).*/\1/p')
    local server=$(echo "$server_port" | cut -d: -f1)
    local port=$(echo "$server_port" | cut -d: -f2)
    local sni=$(echo "$link" | grep -oP 'sni=\K[^&#]*' 2>/dev/null || echo "$server")
    
    jq -n \
        --arg s "$server" --arg p "$port" --arg pw "$password" --arg sni "$sni" \
        '{
            type: "trojan",
            server: $s,
            server_port: ($p|tonumber),
            password: $pw,
            packet_encoding: "xudp",
            tls: {
                enabled: true,
                server_name: $sni,
                utls: { enabled: true, fingerprint: "chrome" }
            }
        }'
}

_parse_hysteria2_share_link() {
    local link="$1"
    local password=$(echo "$link" | sed -n 's/hysteria2:\/\/\([^@]*\)@.*/\1/p')
    if [ -z "$password" ]; then
        password=$(echo "$link" | sed -n 's/hy2:\/\/\([^@]*\)@.*/\1/p')
    fi
    
    local server_port=$(echo "$link" | sed -n 's/.*@\([^?#]*\).*/\1/p')
    local server=$(echo "$server_port" | cut -d: -f1)
    local port=$(echo "$server_port" | cut -d: -f2)
    local query=$(echo "$link" | grep -oP '\?\K[^#]*' 2>/dev/null || echo "")
    
    local sni="$server"
    local insecure="0"
    local obfs=""
    local obfs_password=""

    IFS='&' read -ra PARAM_ARRAY <<< "$query"
    for param in "${PARAM_ARRAY[@]}"; do
        local key=$(echo "$param" | cut -d= -f1)
        local value=$(echo "$param" | cut -d= -f2-)
        case "$key" in
            "sni") sni="$value" ;;
            "insecure"|"allow_insecure") insecure="1" ;;
            "obfs") obfs="$value" ;;
            "obfs-password") obfs_password="$value" ;;
        esac
    done

    jq -n \
        --arg s "$server" --arg p "$port" --arg pw "$password" \
        --arg sni "$sni" --arg insecure "$insecure" \
        --arg obfs "$obfs" --arg obfs_pw "$obfs_password" \
        '{
            type: "hysteria2",
            server: $s,
            server_port: ($p|tonumber),
            password: $pw,
            tls: {
                enabled: true,
                server_name: $sni,
                insecure: (if $insecure == "1" then true else false end)
            }
        } |
        if $obfs != "" then 
            .obfs = { type: $obfs, password: $obfs_pw }
        else . end |
        .packet_encoding = "xudp"'
}

_parse_tuic_link() {
    local link="$1"
    # tuic://uuid:password@server:port?sni=...&insecure=1#name
    local uuid=$(echo "$link" | sed -n 's/tuic:\/\/\([^:]*\):.*/\1/p')
    local password=$(echo "$link" | sed -n 's/tuic:\/\/[^:]*:\([^@]*\)@.*/\1/p')
    local server_port=$(echo "$link" | sed -n 's/.*@\([^?#]*\).*/\1/p')
    local server=$(echo "$server_port" | cut -d: -f1)
    local port=$(echo "$server_port" | cut -d: -f2)
    local query=$(echo "$link" | grep -oP '\?\K[^#]*' 2>/dev/null || echo "")

    local sni="$server"
    local insecure="1"
    local alpn="h3"

    IFS='&' read -ra PARAM_ARRAY <<< "$query"
    for param in "${PARAM_ARRAY[@]}"; do
        local key=$(echo "$param" | cut -d= -f1)
        local value=$(echo "$param" | cut -d= -f2-)
        case "$key" in
            "sni") sni="$value" ;;
            "insecure"|"allow_insecure") insecure="1" ;;
            "alpn") alpn="$value" ;;
        esac
    done

    jq -n \
        --arg s "$server" --arg p "$port" --arg u "$uuid" \
        --arg pw "$password" --arg sni "$sni" --arg insecure "$insecure" --arg alpn "$alpn" \
        '{
            type: "tuic",
            server: $s,
            server_port: ($p|tonumber),
            uuid: $u,
            password: $pw,
            congestion_control: "bbr",
            tls: {
                enabled: true,
                server_name: $sni,
                alpn: [$alpn],
                insecure: (if $insecure == "1" then true else false end)
            }
        }'
}

_parse_input_smart() {
    # 移除首尾空格和可能的换行符
    local input=$(echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\r\n')
    local outbound_json=""
    local dest_type=""
    
    # 1. 尝试 Base64 解码 (处理可能缺少的填充)
    if [[ "$input" =~ ^[A-Za-z0-9+/_-]+=*$ ]] && [[ ${#input} -gt 20 ]]; then
        local b64_input="$input"
        local len=$(( ${#b64_input} % 4 ))
        [[ $len -eq 2 ]] && b64_input="${b64_input}=="
        [[ $len -eq 3 ]] && b64_input="${b64_input}="
        
        local decoded=$(echo "$b64_input" | tr '_-' '/+' | base64 -d 2>/dev/null)
        if [ -n "$decoded" ]; then
             # 如果解码后包含 type 字段，假设是 JSON Token
             if echo "$decoded" | grep -q "\"type\":"; then
                 local j_type=$(echo "$decoded" | jq -r .type 2>/dev/null)
                 # 兼容旧版 Token 生成格式
                 if [[ "$j_type" == "vless" ]]; then
                     local addr=$(echo "$decoded" | jq -r .addr)
                     local port=$(echo "$decoded" | jq -r .port)
                     local uuid=$(echo "$decoded" | jq -r .uuid)
                     outbound_json=$(jq -n --arg s "$addr" --arg p "$port" --arg u "$uuid" \
                        '{"type":"vless","server":$s,"server_port":($p|tonumber),"uuid":$u,"packet_encoding":"xudp","tls":{"enabled":false}}')
                     dest_type="vless"
                 elif [[ "$j_type" == "shadowsocks" ]]; then
                     local addr=$(echo "$decoded" | jq -r .addr)
                     local port=$(echo "$decoded" | jq -r .port)
                     local method=$(echo "$decoded" | jq -r .method)
                     local pw=$(echo "$decoded" | jq -r .password)
                     outbound_json=$(jq -n --arg s "$addr" --arg p "$port" --arg m "$method" --arg pw "$pw" \
                        '{"type":"shadowsocks","server":$s,"server_port":($p|tonumber),"method":$m,"password":$pw}')
                     dest_type="shadowsocks"
                 fi
                 
                 if [ -n "$outbound_json" ]; then
                     echo "$outbound_json|$dest_type"
                     return 0
                 fi
             fi
             
             # 如果解码后是链接
             if [[ "$decoded" =~ ^(vless|vmess|ss|trojan|hysteria2|hy2):// ]]; then
                 input="$decoded"
                 _info "Base64 解码成功: 下一步解析 $input"
             fi
        fi
    fi
    
    # 2. 链接解析
    if [[ "$input" == vless://* ]]; then
        outbound_json=$(_parse_vless_share_link "$input")
        dest_type="vless"
    elif [[ "$input" == vmess://* ]]; then
        outbound_json=$(_parse_vmess_share_link "$input")
        dest_type="vmess"
    elif [[ "$input" == ss://* ]]; then
        outbound_json=$(_parse_shadowsocks_share_link "$input")
        dest_type="shadowsocks"
    elif [[ "$input" == trojan://* ]]; then
        outbound_json=$(_parse_trojan_share_link "$input")
        dest_type="trojan"
    elif [[ "$input" == hysteria2://* ]] || [[ "$input" == hy2://* ]]; then
        outbound_json=$(_parse_hysteria2_share_link "$input")
        dest_type="hysteria2"
    elif [[ "$input" == tuic://* ]]; then
        outbound_json=$(_parse_tuic_link "$input")
        dest_type="tuic"
    fi

    if [ -n "$outbound_json" ] && [ "$outbound_json" != "null" ]; then
        echo "$outbound_json|$dest_type"
        return 0
    else
        return 1
    fi
}

# ==============================================
#  核心功能
# ==============================================

# 1. 落地机配置 (生成 Token)
_landing_config() {
    echo -e "================================================"
    echo -e "         生成落地机 Token (用于中转机连接)"
    echo -e "================================================"
    
    if [ ! -f "$MAIN_CONFIG_FILE" ]; then
        _error "未找到主配置文件: $MAIN_CONFIG_FILE"
        return
    fi
    
    # 筛选合适的节点
    local nodes=$(jq -c '.inbounds[] | select(.type=="vless" or .type=="shadowsocks")' "$MAIN_CONFIG_FILE")
    if [ -z "$nodes" ]; then
        _error "未找到 VLESS 或 Shadowsocks 节点。"
        _pause
        return
    fi
    
    local i=1
    local node_list=()
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag')
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port')
        echo -e "${GREEN}$i)${NC} $tag ($type : $port)"
        node_list+=("$node")
        ((i++))
    done <<EOF
$(echo "$nodes")
EOF
    
    echo "0) 返回"
    read -p "请选择落地节点: " choice
    if [[ ! "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then 
        _warn "已取消或输入无效"
        _pause
        return 
    fi
    
    local selected=${node_list[$((choice-1))]}
    local port=$(echo "$selected" | jq -r '.listen_port')
    local type=$(echo "$selected" | jq -r '.type')
    local ip=$(_get_public_ip)
    
    local token_json=""
    if [[ "$type" == "vless" ]]; then
        local uuid=$(echo "$selected" | jq -r '.users[0].uuid')
        token_json=$(jq -n --arg ip "$ip" --arg p "$port" --arg u "$uuid" \
            '{type:"vless", addr:$ip, port:$p, uuid:$u}')
    elif [[ "$type" == "shadowsocks" ]]; then
        local method=$(echo "$selected" | jq -r '.method')
        local pw=$(echo "$selected" | jq -r '.password')
        token_json=$(jq -n --arg ip "$ip" --arg p "$port" --arg m "$method" --arg pw "$pw" \
            '{type:"shadowsocks", addr:$ip, port:$p, method:$m, password:$pw}')
    fi
    
    local b64=$(echo "$token_json" | base64 -w 0)
    
    _success "Token 生成成功！"
    echo -e "${YELLOW}请复制下方 Token 到中转机使用：${NC}"
    echo "----------------------------------------"
    echo "$b64"
    echo "----------------------------------------"
    read -p "按回车继续..."
}

# 2. 中转机配置 (智能导入)
_relay_config() {
    echo -e "================================================"
    echo -e "          配置中转规则 (智能导入)"
    echo -e "================================================"
    echo -e "支持格式: "
    echo -e " 1. Base64 Token (来自 落地机配置)"
    echo -e " 2. 分享链接 (vless://, vmess://, ss://, trojan://, hysteria2://)"
    echo -e " 3. Base64 编码的分享链接"
    echo "----------------------------------------"
    echo -e "${YELLOW}请粘贴内容 (完成后按回车):${NC}"
    read -r input
    
    if [ -z "$input" ]; then 
        _error "输入为空"
        _pause
        return 
    fi
    
    _info "正在解析..."
    local result=$(_parse_input_smart "$input")
    
    if [ $? -ne 0 ]; then
        _error "无法解析输入内容！请检查格式。"
        _pause
        return
    fi
    
    # 解析结果格式: outbound_json|type
    local outbound_json=$(echo "$result" | cut -d'|' -f1)
    local dest_type=$(echo "$result" | cut -d'|' -f2)
    local dest_addr=$(echo "$outbound_json" | jq -r .server)
    local dest_port=$(echo "$outbound_json" | jq -r .server_port)
    
    _success "解析成功: ${dest_type} -> ${dest_addr}:${dest_port}"
    
    _finalize_relay_setup "$dest_type" "$dest_addr" "$dest_port" "$outbound_json"
}

# 3. 完成中转设置
_finalize_relay_setup() {
    local dest_type="$1"
    local dest_addr="$2"
    local dest_port="$3"
    local outbound_json="$4"
    
    echo ""
    echo -e "请选择本机 [中转入口] 协议:"
    echo -e " 1) VLESS-Reality (推荐, 稳定)"
    echo -e " 2) Hysteria2 (UDP, 速度快)"
    echo -e " 3) TUIC (UDP)"
    echo -e " 4) AnyTLS (TCP)"
    read -p "选择 [1-4]: " choice
    
    local relay_type=""
    case "$choice" in
        1) relay_type="vless-reality" ;;
        2) relay_type="hysteria2" ;;
        3) relay_type="tuic" ;;
        4) relay_type="anytls" ;;
        *) _error "无效选择"; _pause; return ;;
    esac
    
    read -p "请输入本机监听端口 (留空随机): " listen_port
    [[ -z "$listen_port" ]] && listen_port=$(shuf -i 20000-50000 -n 1)
    
    read -p "请输入伪装域名 SNI (留空 www.microsoft.com): " sni
    [[ -z "$sni" ]] && sni="www.microsoft.com"
    
    local flag=$(_get_country_flag)
    local default_name="${flag}${relay_type}-Relay-${listen_port}"
    read -p "节点名称 (默认: $default_name): " node_name
    [[ -z "$node_name" ]] && node_name="$default_name"
    
    # 构造 Inbound JSON
    local inbound_tag="${relay_type}-in-${listen_port}"
    local outbound_tag="relay-out-${listen_port}"
    local inbound_json=""
    local link=""
    local cert_path="${RELAY_AUX_DIR}/${inbound_tag}.pem"
    local key_path="${RELAY_AUX_DIR}/${inbound_tag}.key"
    local server_ip=$(_get_public_ip)
    
    if [[ "$relay_type" =~ ^(hysteria2|tuic|anytls)$ ]]; then
        _info "生成自签名证书..."
        openssl ecparam -genkey -name prime256v1 -out "$key_path" 2>/dev/null
        openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${sni}" 2>/dev/null
    fi
    
    if [[ "$relay_type" == "vless-reality" ]]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        local keypair=$($SINGBOX_BIN generate reality-keypair)
        local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
        local pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
        local sid=$($SINGBOX_BIN generate rand --hex 8)
        
        inbound_json=$(jq -n \
            --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" \
            --arg sn "$sni" --arg pk "$pk" --arg sid "$sid" \
            '{
                type: "vless", tag: $t, listen: "::", listen_port: ($p|tonumber),
                users: [{uuid: $u, flow: "xtls-rprx-vision"}],
                tls: {
                    enabled: true, server_name: $sn,
                    reality: { enabled: true, handshake: {server: $sn, server_port: 443}, private_key: $pk, short_id: [$sid] }
                }
            }')
         link="vless://${uuid}@${server_ip}:${listen_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#${node_name}"
         
    elif [[ "$relay_type" == "hysteria2" ]]; then
        local pw=$($SINGBOX_BIN generate rand --hex 16)
        inbound_json=$(jq -n \
            --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$pw" \
            --arg sn "$sni" --arg c "$cert_path" --arg k "$key_path" \
            '{
                type: "hysteria2", tag: $t, listen: "::", listen_port: ($p|tonumber),
                users: [{password: $pw}],
                tls: { enabled: true, server_name: $sn, alpn: ["h3"], certificate_path: $c, key_path: $k }
            }')
        link="hysteria2://${pw}@${server_ip}:${listen_port}?sni=${sni}&insecure=1#${node_name}"
    
    elif [[ "$relay_type" == "tuic" ]]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        local pw=$($SINGBOX_BIN generate rand --hex 16)
        inbound_json=$(jq -n \
            --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg pw "$pw" \
            --arg sn "$sni" --arg c "$cert_path" --arg k "$key_path" \
            '{
                type: "tuic", tag: $t, listen: "::", listen_port: ($p|tonumber),
                users: [{uuid: $u, password: $pw}], congestion_control: "bbr",
                tls: { enabled: true, server_name: $sn, alpn: ["h3"], certificate_path: $c, key_path: $k }
            }')
         link="tuic://${uuid}:${pw}@${server_ip}:${listen_port}?sni=${sni}&alpn=h3&congestion_control=bbr&allow_insecure=1#${node_name}"
    
    elif [[ "$relay_type" == "anytls" ]]; then
         local pw=$($SINGBOX_BIN generate uuid)
         inbound_json=$(jq -n \
            --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$pw" \
            --arg sn "$sni" --arg c "$cert_path" --arg k "$key_path" \
            '{
                type: "anytls", tag: $t, listen: "::", listen_port: ($p|tonumber),
                users: [{name: "default", password: $pw}],
                tls: { enabled: true, server_name: $sn, certificate_path: $c, key_path: $k }
            }')
         link="anytls://${pw}@${server_ip}:${listen_port}?security=tls&sni=${sni}&insecure=1&type=tcp#${node_name}"
    fi

    # 写入配置文件
    _info "正在写入配置..."
    # 修正 outbound tag
    outbound_json=$(echo "$outbound_json" | jq --arg t "$outbound_tag" '.tag=$t')
    
    local tmp_file="${RELAY_CONFIG_FILE}.tmp"
    cp "$RELAY_CONFIG_FILE" "${RELAY_CONFIG_FILE}.bak"
    
    # 1. Add Inbound
    jq ".inbounds += [$inbound_json]" "$RELAY_CONFIG_FILE" > "$tmp_file" && mv "$tmp_file" "$RELAY_CONFIG_FILE"
    # 2. Add Outbound
    jq ".outbounds = [$outbound_json] + .outbounds" "$RELAY_CONFIG_FILE" > "$tmp_file" && mv "$tmp_file" "$RELAY_CONFIG_FILE"
    # 3. Add Route Rule
    jq ".route.rules += [{\"inbound\":\"$inbound_tag\",\"outbound\":\"$outbound_tag\"}]" "$RELAY_CONFIG_FILE" > "$tmp_file" && mv "$tmp_file" "$RELAY_CONFIG_FILE"

    # 重启服务
    if _manage_service restart; then
        _success "服务重启成功！中转已生效。"
    else
        _error "服务重启失败，即将回滚..."
        mv "${RELAY_CONFIG_FILE}.bak" "$RELAY_CONFIG_FILE"
        _manage_service restart
        _pause
        return
    fi
    
    # 保存链接信息
    local meta_json=$(jq -n --arg l "$link" --arg n "$node_name" --arg t "$dest_type" \
        '{link: $l, node_name: $n, target_type: $t, created: "now"}')
    local link_file="${RELAY_AUX_DIR}/relay_links.json"
    local tmp_link="${link_file}.tmp"
    jq --arg k "$inbound_tag" --argjson v "$meta_json" '.[$k] = $v' "$link_file" > "$tmp_link" && mv "$tmp_link" "$link_file"

    echo -e "----------------------------------------"
    echo -e "中转节点名称: ${GREEN}${node_name}${NC}"
    echo -e "分享链接: ${YELLOW}${link}${NC}"
    echo -e "----------------------------------------"
    
    # 尝试添加到 Clash YAML
    local proxy_json=""
    if [[ "$relay_type" == "vless-reality" ]]; then
         # 简化生成 clash proxy json (仅供参考)
         proxy_json=$(jq -n --arg n "$node_name" --arg s "$server_ip" --arg p "$listen_port" --arg u "$uuid" --arg sn "$sni" --arg pk "$pbk" --arg sid "$sid" \
            '{name:$n, type:"vless", server:$s, port:($p|tonumber), uuid:$u, tls:true, flow:"xtls-rprx-vision", servername:$sn, "reality-opts":{"public-key":$pk, "short-id":$sid}, "client-fingerprint":"chrome"}')
    fi
    # (其他协议 Clah Meta 支持较复杂，这里简化处理，如有需求可继续扩充)
    
    if [ -n "$proxy_json" ]; then
        _add_node_to_relay_yaml "$proxy_json"
    fi
    
    _pause
}

# 4. 查看/删除 中转
_manage_relays() {
    local link_file="${RELAY_AUX_DIR}/relay_links.json"
    if [ ! -f "$link_file" ]; then echo "{}">"$link_file"; fi
    
    echo -e "================ 中转管理 ================"
    local keys=$(jq -r 'keys[]' "$link_file")
    if [ -z "$keys" ]; then echo "无中转节点"; read -p "按回车返回..."; return; fi
    
    local i=1
    local key_arr=()
    for k in $keys; do
        local name=$(jq -r ".[\"$k\"].node_name" "$link_file")
        local tgt=$(jq -r ".[\"$k\"].target_type" "$link_file")
        echo -e "${GREEN}$i)${NC} $name (落地: $tgt) [Tag: $k]"
        key_arr+=("$k")
        ((i++))
    done
    
    echo "----------------------------------------"
    echo "d + 序号) 删除节点 (如 d1)"
    echo "v + 序号) 查看链接 (如 v1)"
    echo "0) 返回"
    read -p "请选择: " choice
    
    if [[ "$choice" == "0" ]]; then return; fi
    
    local action=${choice:0:1}
    local idx=${choice:1}
    
    if [[ ! "$idx" =~ ^[0-9]+$ ]] || [ "$idx" -ge "$i" ] || [ "$idx" -lt 1 ]; then
        return
    fi
    
    local selected_key=${key_arr[$((idx-1))]}
    
    if [[ "$action" == "v" ]]; then
        local link=$(jq -r ".[\"$selected_key\"].link" "$link_file")
        echo ""
        echo -e "${YELLOW}$link${NC}"
        echo ""
        read -p "按回车继续..."
    elif [[ "$action" == "d" ]]; then
        read -p "确认删除? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then
            _info "正在删除..."
            # 1. Delete from config
            # 查找对应的 outbound tag
            local out_tag=$(jq -r ".route.rules[] | select(.inbound==\"$selected_key\") | .outbound" "$RELAY_CONFIG_FILE")
            
            local tmp="${RELAY_CONFIG_FILE}.tmp"
            jq "del(.inbounds[] | select(.tag==\"$selected_key\"))" "$RELAY_CONFIG_FILE" > "$tmp" && mv "$tmp" "$RELAY_CONFIG_FILE"
            if [ -n "$out_tag" ]; then
                jq "del(.outbounds[] | select(.tag==\"$out_tag\"))" "$RELAY_CONFIG_FILE" > "$tmp" && mv "$tmp" "$RELAY_CONFIG_FILE"
                jq "del(.route.rules[] | select(.inbound==\"$selected_key\"))" "$RELAY_CONFIG_FILE" > "$tmp" && mv "$tmp" "$RELAY_CONFIG_FILE"
            fi
            
            # 2. Remove certs
            rm -f "${RELAY_AUX_DIR}/${selected_key}.key" "${RELAY_AUX_DIR}/${selected_key}.pem"
            
            # 3. Remove from links
            local tmp_l="${link_file}.tmp"
            jq "del(.[\"$selected_key\"])" "$link_file" > "$tmp_l" && mv "$tmp_l" "$link_file"
            
            _manage_service restart
            _success "删除成功"
            _pause
        fi
    fi
}

# --- 菜单 ---
_advanced_menu() {
    _check_deps
    while true; do
        clear
        echo -e "${CYAN}========== Sing-box 进阶中转系统 ==========${NC}"
        echo -e " ${GREEN}1)${NC} 落地机: 生成对接 Token"
        echo -e " ${GREEN}2)${NC} 中转机: 新增中转 (支持 Token/链接)"
        echo -e " ${GREEN}3)${NC} 中转机: 管理中转 (查看/删除)"
        echo -e " ${GREEN}0)${NC} 退出"
        echo ""
        read -p "请选择: " opt
        case $opt in
            1) _landing_config ;;
            2) _relay_config ;;
            3) _manage_relays ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

_advanced_menu
