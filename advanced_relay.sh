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

# 日志记录函数
_log_operation() {
    local operation="$1"
    local details="$2"
    local LOG_FILE="${RELAY_AUX_DIR}/relay_operations.log"
    [ -d "$RELAY_AUX_DIR" ] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] $operation: $details" >> "$LOG_FILE"
}


# 获取公网IP
_get_public_ip() {
    # 优先使用 curl，timeout 命令可能缺失
    local ip=""
    if command -v timeout &>/dev/null; then
        ip=$(timeout 3 curl -s4 --max-time 3 icanhazip.com 2>/dev/null || timeout 3 curl -s4 --max-time 3 ipinfo.io/ip 2>/dev/null)
        if [ -z "$ip" ]; then
            ip=$(timeout 3 curl -s6 --max-time 3 icanhazip.com 2>/dev/null || timeout 3 curl -s6 --max-time 3 ipinfo.io/ip 2>/dev/null)
        fi
    else
        # 不带 timeout 命令的 fallback
        ip=$(curl -s4 --max-time 3 icanhazip.com 2>/dev/null || curl -s4 --max-time 3 ipinfo.io/ip 2>/dev/null)
        if [ -z "$ip" ]; then
            ip=$(curl -s6 --max-time 3 icanhazip.com 2>/dev/null || curl -s6 --max-time 3 ipinfo.io/ip 2>/dev/null)
        fi
    fi
    if [ -z "$ip" ]; then
        _warn "无法自动获取公网IP"
        read -p "请手动输入服务器IP地址: " ip
        if [ -z "$ip" ]; then
            ip="YOUR_IP"
        fi
    fi
    echo "$ip"
}

# 智能保存 iptables 规则（支持 Debian 和 Alpine）
_save_iptables_rules() {
    _info "正在保存 iptables 规则..."
    
    # 检测系统类型
    if [ -f "/sbin/openrc-run" ] || command -v rc-service &>/dev/null; then
        # Alpine Linux
        local rules_file="/etc/iptables/rules-save"
        mkdir -p /etc/iptables 2>/dev/null
        iptables-save > "$rules_file" 2>/dev/null
        rc-update add iptables default 2>/dev/null
        _success "iptables 规则已保存，重启后自动恢复"
    else
        # Debian/Ubuntu
        local rules_file="/etc/iptables/rules.v4"
        mkdir -p /etc/iptables 2>/dev/null
        iptables-save > "$rules_file" 2>/dev/null
        
        if ! dpkg -l | grep -q iptables-persistent 2>/dev/null; then
            if command -v apt-get &>/dev/null; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1
            fi
        fi
        _success "iptables 规则已保存，重启后自动恢复"
    fi
}

# YAML 操作辅助函数
_add_node_to_relay_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    
    # 使用 yq 添加节点（需要主脚本的 yq）
    local YQ_BINARY="/usr/local/bin/yq"
    if [ ! -f "$YQ_BINARY" ]; then
        _warn "未找到 yq 工具，跳过 YAML 配置生成"
        return
    fi
    
    # 检查 YAML 文件是否存在
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        _warn "YAML 配置文件不存在，跳过添加"
        return
    fi
    
    # 将 JSON 写入临时文件
    local temp_json="/tmp/relay_node_$$.json"
    echo "$proxy_json" > "$temp_json"
    
    # 使用 yq 从文件读取并添加
    ${YQ_BINARY} eval ".proxies += [$(cat $temp_json)]" -i "$RELAY_CLASH_YAML" 2>/dev/null
    # 使用环境变量避免特殊字符问题
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "中转节点") | .proxies += [env(PROXY_NAME)] | .proxies |= unique)' -i "$RELAY_CLASH_YAML" 2>/dev/null
    
    # 清理临时文件
    rm -f "$temp_json"
    
    _info "已添加节点到 YAML 配置: ${proxy_name}"
}

_remove_node_from_relay_yaml() {
    local proxy_name="$1"
    local YQ_BINARY="/usr/local/bin/yq"
    
    if [ ! -f "$YQ_BINARY" ]; then
        return
    fi
    
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        return
    fi
    
    # 删除节点 - 使用环境变量避免特殊字符问题
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval 'del(.proxies[] | select(.name == env(PROXY_NAME)))' -i "$RELAY_CLASH_YAML" 2>/dev/null
    PROXY_NAME="$proxy_name" ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "中转节点") | .proxies |= del(.[] | select(. == env(PROXY_NAME))))' -i "$RELAY_CLASH_YAML" 2>/dev/null
    
    _info "已从 YAML 配置中删除节点: ${proxy_name}"
}


# 初始化辅助目录
_init_relay_dirs() {
    # 确保辅助目录存在
    if [ ! -d "$RELAY_AUX_DIR" ]; then
        mkdir -p "$RELAY_AUX_DIR"
        _info "已创建辅助目录: $RELAY_AUX_DIR"
    fi
    
    # 确保 relay_links.json 存在
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    if [ ! -f "$LINKS_FILE" ]; then
        echo '{}' > "$LINKS_FILE"
        _info "已初始化链接存储文件: $LINKS_FILE"
    fi
    
    # 确保 clash.yaml 存在
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        cat > "$RELAY_CLASH_YAML" << 'EOF'
proxies: []
proxy-groups:
  - name: 节点选择
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
EOF
        _info "已初始化 YAML 配置文件: $RELAY_CLASH_YAML"
    fi

    # 确保 relay.json 存在
    if [ ! -f "$RELAY_CONFIG_FILE" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE"
        _info "已初始化中转配置文件: $RELAY_CONFIG_FILE"
    fi
}

# 检查依赖
_check_deps() {
    if ! command -v jq &>/dev/null; then
        _error "缺少 'jq' 工具，请先安装。"
        read -p "按任意键退出..."
        exit 1
    fi
    
    # 确保辅助目录存在
    if [ ! -d "$RELAY_AUX_DIR" ]; then
        _info "创建辅助目录: $RELAY_AUX_DIR"
        mkdir -p "$RELAY_AUX_DIR"
    fi
    
    # 初始化中转机专用 YAML 配置文件
    if [ ! -f "$RELAY_CLASH_YAML" ]; then
        _info "正在创建中转机专用 clash.yaml 配置文件..."
        cat > "$RELAY_CLASH_YAML" << 'EOF'
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
bind-address: '*'
mode: rule
log-level: info
ipv6: false
find-process-mode: strict
external-controller: '127.0.0.1:9090'
profile:
  store-selected: true
  store-fake-ip: true
unified-delay: true
tcp-concurrent: true
ntp:
  enable: true
  write-to-system: false
  server: ntp.aliyun.com
  port: 123
  interval: 30
dns:
  enable: true
  respect-rules: true
  use-system-hosts: true
  prefer-h3: false
  listen: '0.0.0.0:1053'
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  fake-ip-filter:
    - +.lan
    - +.local
    - localhost.ptlogin2.qq.com
    - +.msftconnecttest.com
    - +.msftncsi.com
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 'https://1.1.1.1/dns-query'
    - 'https://dns.quad9.net/dns-query'
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 'https://1.0.0.1/dns-query'
    - 'https://9.9.9.10/dns-query'
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
  strict-route: false
  dns-hijack:
    - 'any:53'
  device: RelayTunnel
  endpoint-independent-nat: true
proxies: []
proxy-groups:
  - name: 中转节点
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,中转节点
EOF
    fi
}

# ==============================================
#  智能解析函数 - 支持多种导入格式
# ==============================================

# 获取地区旗帜 (Emoji) - 用于节点命名
_get_country_flag() {
    # 优先使用 ipapi.co (更准确)
    local country_code=$(curl -s --max-time 2 https://ipapi.co/country/ 2>/dev/null)
    
    # 备用 ip-api.com
    if [ -z "$country_code" ] || [ ${#country_code} -ne 2 ]; then
        country_code=$(curl -s --max-time 2 http://ip-api.com/line/?fields=countryCode 2>/dev/null)
    fi

    # 验证是否为2位字母
    if [[ ! "$country_code" =~ ^[a-zA-Z]{2}$ ]]; then
        echo ""
        return
    fi

    # 转换为大写
    country_code=$(echo "$country_code" | tr '[:lower:]' '[:upper:]')

    # 计算 Emoji (Regional Indicator Symbols)
    local flag=""
    for (( i=0; i<${#country_code}; i++ )); do
        local char="${country_code:$i:1}"
        local ascii_val=$(printf "%d" "'$char")
        local emoji_val=$((ascii_val + 127397))
        flag+=$(printf "\\U$(printf "%x" $emoji_val)")
    done
    echo "$flag"
}

# 解析 VLESS 分享链接为 outbound JSON
_parse_vless_share_link() {
    local link="$1"
    
    # vless://UUID@SERVER:PORT?参数#名称
    local uuid=$(echo "$link" | sed -n 's/vless:\/\/\([^@]*\)@.*/\1/p')
    local server_port=$(echo "$link" | sed -n 's/.*@\([^?#]*\).*/\1/p')
    
    # 支持 IPv6 地址 (带括号 [2001:...]:port)
    local server=$(echo "$server_port" | rev | cut -d: -f2- | rev | tr -d '[]')
    local port=$(echo "$server_port" | rev | cut -d: -f1 | rev)
    
    # 解析查询参数
    local query=$(echo "$link" | grep -oP '\?\K[^#]*' 2>/dev/null || echo "")
    
    local security=$(echo "$query" | grep -oP 'security=\K[^&]*' 2>/dev/null || echo "none")
    local network=$(echo "$query" | grep -oP '(type|network)=\K[^&]*' 2>/dev/null || echo "tcp")
    local sni=$(echo "$query" | grep -oP 'sni=\K[^&]*' 2>/dev/null || echo "")
    
    # 构造 outbound
    local outbound_json=$(jq -n \
        --arg s "$server" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg sec "$security" \
        --arg net "$network" \
        --arg sni "$sni" \
        '{
            type: "vless",
            server: $s,
            server_port: ($p|tonumber),
            uuid: $u,
            network: $net,
            packet_encoding: "xudp",
            tls: (if ($sec == "tls" or $sec == "reality") then {
                enabled: true,
                server_name: $sni
            } else {
                enabled: false
            } end)
        }' 2>/dev/null)
    
    echo "$outbound_json"
}

# 解析 Shadowsocks 分享链接
_parse_shadowsocks_share_link() {
    local link="$1"
    
    # ss://base64(method:password)@server:port#name
    local main_part=$(echo "$link" | sed 's/ss:\/\/\([^#]*\)#.*/\1/')
    
    # 提取 userinfo 和 server:port
    local userinfo=$(echo "$main_part" | sed 's/@.*//')
    local server_port=$(echo "$main_part" | sed 's/.*@//')
    
    local server=$(echo "$server_port" | cut -d':' -f1)
    local port=$(echo "$server_port" | cut -d':' -f2)
    
    # 解码 userinfo
    local decoded=$(echo "$userinfo" | base64 -d 2>/dev/null || echo "$userinfo")
    local method=$(echo "$decoded" | cut -d':' -f1)
    local password=$(echo "$decoded" | cut -d':' -f2-)
    
    local outbound_json=$(jq -n \
        --arg s "$server" \
        --arg p "$port" \
        --arg m "$method" \
        --arg pw "$password" \
        '{
            type: "shadowsocks",
            server: $s,
            server_port: ($p|tonumber),
            method: $m,
            password: $pw
        }')
    
    echo "$outbound_json"
}

# 解析 VMess 分享链接
_parse_vmess_share_link() {
    local link="$1"
    # vmess://base64(JSON)
    local json=$(echo "$link" | sed 's/vmess:\/\///' | base64 -d 2>/dev/null)
    
    if [ -z "$json" ]; then
        _error "VMess链接解码失败"
        return 1
    fi
    
    local server=$(echo "$json" | jq -r '.add')
    local port=$(echo "$json" | jq -r '.port')
    local uuid=$(echo "$json" | jq -r '.id')
    local alterId=$(echo "$json" | jq -r '.aid // 0')
    local network=$(echo "$json" | jq -r '.net // "tcp"')
    local security=$(echo "$json" | jq -r '.tls // "none"')
    local sni=$(echo "$json" | jq -r '.sni // .host // ""')
    
    local outbound_json=$(jq -n \
        --arg s "$server" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg aid "$alterId" \
        --arg net "$network" \
        --arg sec "$security" \
        --arg sni "$sni" \
        '{
            type: "vmess",
            server: $s,
            server_port: ($p|tonumber),
            uuid: $u,
            alter_id: ($aid|tonumber),
            network: $net,
            tls: (if $sec == "tls" then {
                enabled: true,
                server_name: $sni
            } else {
                enabled: false
            } end)
        }')
    
    echo "$outbound_json"
}

# 解析 Trojan 分享链接
_parse_trojan_share_link() {
    local link="$1"
    # trojan://password@server:port?参数#名称
    
    local password=$(echo "$link" | sed 's/trojan:\/\/\([^@]*\)@.*/\1/')
    local server=$(echo "$link" | sed 's/.*@\([^:]*\):.*/\1/')
    local port=$(echo "$link" | sed 's/.*:\([0-9]*\)?.*/\1/' | cut -d'?' -f1)
    
    local query=$(echo "$link" | grep -oP '\?.*?(?=#|$)' 2>/dev/null || echo "")
    query=$(echo "$query" | sed 's/^?//')
    
    local sni=$(echo "$query" | grep -oP 'sni=\K[^&]*' 2>/dev/null || echo "$server")
    local network=$(echo "$query" | grep -oP '(type|network)=\K[^&]*' 2>/dev/null || echo "tcp")
    
    local outbound_json=$(jq -n \
        --arg s "$server" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sni "$sni" \
        --arg net "$network" \
        '{
            type: "trojan",
            server: $s,
            server_port: ($p|tonumber),
            password: $pw,
            network: $net,
            tls: {
                enabled: true,
                server_name: $sni
            }
        }')
    
    echo "$outbound_json"
}

# 解析 Hysteria2 分享链接
_parse_hysteria2_share_link() {
    local link="$1"
    # hysteria2://password@server:port?参数#名称
    
    local password=$(echo "$link" | sed 's/hysteria2:\/\/\([^@]*\)@.*/\1/')
    local server=$(echo "$link" | sed 's/.*@\([^:]*\):.*/\1/')
    local port=$(echo "$link" | sed 's/.*:\([0-9]*\)?.*/\1/' | cut -d'?' -f1)
    
    local query=$(echo "$link" | grep -oP '\?.*?(?=#|$)' 2>/dev/null || echo "")
    query=$(echo "$query" | sed 's/^?//')
    
    local sni=$(echo "$query" | grep -oP 'sni=\K[^&]*' 2>/dev/null || echo "$server")
    
    local outbound_json=$(jq -n \
        --arg s "$server" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sni "$sni" \
        '{
            type: "hysteria2",
            server: $s,
            server_port: ($p|tonumber),
            password: $pw,
            tls: {
                enabled: true,
                server_name: $sni
            }
        }')
    
    echo "$outbound_json"
}

# 智能识别并解析落地节点
_parse_landing_input() {
    local input="$1"
    local outbound_json=""
    local dest_type=""
    local dest_addr=""
    local dest_port=""
    
    # 1. 尝试识别是否为 base64 编码
    if [[ "$input" =~ ^[A-Za-z0-9+/]+=*$ ]] && [[ ${#input} -gt 40 ]]; then
        _info "检测到可能是 Base64 编码，尝试解码..."
        local decoded=$(echo "$input" | base64 -d 2>/dev/null)
        
        if [ $? -eq 0 ] && [ -n "$decoded" ]; then
            # 检查解码后是否为分享链接
            if [[ "$decoded" == vless://* ]] || [[ "$decoded" == vmess://* ]] || \
               [[ "$decoded" == ss://* ]] || [[ "$decoded" == trojan://* ]] || \
               [[ "$decoded" == hysteria2://* ]] || [[ "$decoded" == hy2://* ]]; then
                _success "识别为 Base64 编码的分享链接"
                input="$decoded"
            # 检查解码后是否为 JSON Token
            elif echo "$decoded" | jq -e '.type' >/dev/null 2>&1; then
                _success "识别为 Base64 编码的 JSON Token (兼容原格式)"
                dest_type=$(echo "$decoded" | jq -r '.type')
                dest_addr=$(echo "$decoded" | jq -r '.addr')
                dest_port=$(echo "$decoded" | jq -r '.port')
                
                if [ "$dest_type" == "vless" ]; then
                    local uuid=$(echo "$decoded" | jq -r '.uuid')
                    outbound_json=$(jq -n --arg s "$dest_addr" --arg p "$dest_port" --arg u "$uuid" \
                        '{"type":"vless","server":$s,"server_port":($p|tonumber),"uuid":$u,"packet_encoding":"xudp","tls":{"enabled":false}}')
                elif [ "$dest_type" == "shadowsocks" ]; then
                    local method=$(echo "$decoded" | jq -r '.method')
                    local password=$(echo "$decoded" | jq -r '.password')
                    outbound_json=$(jq -n --arg s "$dest_addr" --arg p "$dest_port" --arg m "$method" --arg pw "$password" \
                        '{"type":"shadowsocks","server":$s,"server_port":($p|tonumber),"method":$m,"password":$pw}')
                else
                    _error "不支持的 Token 协议类型: $dest_type"
                    return 1
                fi
                
                # Token 模式已经构造好，直接返回
                echo "$outbound_json|$dest_type|$dest_addr|$dest_port"
                return 0
            fi
        fi
    fi
    
    # 2. 解析分享链接
    if [[ "$input" == vless://* ]]; then
        _info "识别为 VLESS 分享链接"
        outbound_json=$(_parse_vless_share_link "$input")
        dest_type="vless"
    elif [[ "$input" == vmess://* ]]; then
        _info "识别为 VMess 分享链接"
        outbound_json=$(_parse_vmess_share_link "$input")
        dest_type="vmess"
    elif [[ "$input" == ss://* ]]; then
        _info "识别为 Shadowsocks 分享链接"
        outbound_json=$(_parse_shadowsocks_share_link "$input")
        dest_type="shadowsocks"
    elif [[ "$input" == trojan://* ]]; then
        _info "识别为 Trojan 分享链接"
        outbound_json=$(_parse_trojan_share_link "$input")
        dest_type="trojan"
    elif [[ "$input" == hysteria2://* ]] || [[ "$input" == hy2://* ]]; then
        _info "识别为 Hysteria2 分享链接"
        outbound_json=$(_parse_hysteria2_share_link "$input")
        dest_type="hysteria2"
    else
        _error "无法识别的格式！"
        _warn "支持的格式："
        echo "  1) vless://... (VLESS 分享链接)"
        echo "  2) vmess://... (VMess 分享链接)"
        echo "  3) ss://... (Shadowsocks 分享链接)"
        echo "  4) trojan://... (Trojan 分享链接)"
        echo "  5) hysteria2://... (Hysteria2 分享链接)"
        echo "  6) Base64 编码的上述链接"
        echo "  7) Base64 编码的 JSON Token (兼容原格式)"
        return 1
    fi
    
    # 从 outbound_json 提取地址和端口
    if [ -n "$outbound_json" ]; then
        dest_addr=$(echo "$outbound_json" | jq -r '.server')
        dest_port=$(echo "$outbound_json" | jq -r '.server_port')
    fi
    
    # 返回格式: outbound_json|dest_type|dest_addr|dest_port
    echo "$outbound_json|$dest_type|$dest_addr|$dest_port"
}

# --- 1. 落地机配置 (生成 Token) ---
_landing_config() {
    _info "正在读取本机节点配置..."
    
    if [ ! -f "$MAIN_CONFIG_FILE" ]; then
        _error "配置文件不存在: $MAIN_CONFIG_FILE"
        _warn "请先在主菜单中添加节点。"
        return
    fi
    
    # 获取本机IP，用于生成Token中的地址
    local server_ip=$(_get_public_ip)

    # 筛选支持的协议: VLESS-TCP (不含 Reality), Shadowsocks (aes-256-gcm, 2022-blake3-aes-128-gcm)
    local nodes=$(jq -c '.inbounds[] | select(
        (.type=="vless" and (.tls.enabled == false or .tls == null)) or 
        (.type=="shadowsocks" and (.method == "aes-256-gcm" or .method == "2022-blake3-aes-128-gcm"))
    )' "$MAIN_CONFIG_FILE")

    if [ -z "$nodes" ]; then
        _error "未找到符合要求的落地节点协议。"
        _warn "要求: 本机已创建 VLESS-TCP 或特定 Shadowsocks 节点。"
        _warn "当前配置文件路径: $MAIN_CONFIG_FILE"
        return
    fi

    echo "================================================"
    echo "  请选择用作 [落地] 的节点 (将把流量转发到此节点)"
    echo "================================================"
    
    local i=1
    local node_list=()
    
    while IFS= read -r node; do
        local tag=$(echo "$node" | jq -r '.tag')
        local type=$(echo "$node" | jq -r '.type')
        local port=$(echo "$node" | jq -r '.listen_port')
        
        # 尝试从 metadata 中获取自定义名称
        local display_name="$tag"
        if [ -f "/usr/local/etc/sing-box/metadata.json" ]; then
            local node_meta=$(jq -r --arg t "$tag" '.[$t] // empty' "/usr/local/etc/sing-box/metadata.json" 2>/dev/null)
            if [ -n "$node_meta" ]; then
                local node_type=$(echo "$node_meta" | jq -r '.type // empty')
                if [ "$node_type" == "third-party-adapter" ]; then
                    # 第三方适配层：显示自定义适配层名称
                    local adapter_name=$(echo "$node_meta" | jq -r '.adapter_name // empty')
                    local adapter_type=$(echo "$node_meta" | jq -r '.adapter_type // empty')
                    if [ -n "$adapter_name" ]; then
                        display_name="${adapter_name} [${adapter_type}适配层]"
                    else
                        # 兼容旧版本（没有adapter_name字段）
                        local source_name=$(echo "$node_meta" | jq -r '.source_name // empty')
                        if [ -n "$source_name" ] && [ -n "$adapter_type" ]; then
                            display_name="${source_name} [${adapter_type}适配层]"
                        fi
                    fi
                fi
            fi
        fi
        
        local desc="${display_name} (${type}:${port})"
        
        echo -e " ${GREEN}$i)${NC} $desc"
        node_list+=("$node")
        ((i++))
    done <<< "$nodes"
    
    echo " 0) 返回"
    read -p "请输入选项: " choice
    
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        return
    fi
    
    local selected_node=${node_list[$((choice-1))]}
    local tag=$(echo "$selected_node" | jq -r '.tag')
    local type=$(echo "$selected_node" | jq -r '.type')
    local port=$(echo "$selected_node" | jq -r '.listen_port')
    
    # --- 提取字段并构建 Token JSON ---
    local token_json=""
    
    # 检测节点监听地址，如果是本地地址则使用 127.0.0.1
    local listen_addr=$(echo "$selected_node" | jq -r '.listen // "::"')
    local token_addr="$server_ip"
    
    if [[ "$listen_addr" == "127.0.0.1" || "$listen_addr" == "localhost" ]]; then
        token_addr="127.0.0.1"
        _warn "检测到本地节点（第三方适配层），Token 将使用 127.0.0.1"
    fi
    
    case "$type" in
        "vless")
            local uuid=$(echo "$selected_node" | jq -r '.users[0].uuid')
            # VLESS-TCP (无 TLS，无 Reality)
            token_json=$(jq -n \
                --arg ip "$token_addr" --arg p "$port" --arg u "$uuid" \
                '{type: "vless", addr: $ip, port: $p, uuid: $u}')
            ;;
        "shadowsocks")
            local method=$(echo "$selected_node" | jq -r '.method')
            local pw=$(echo "$selected_node" | jq -r '.password')
            token_json=$(jq -n \
                --arg ip "$token_addr" --arg p "$port" --arg m "$method" --arg pw "$pw" \
                '{type: "shadowsocks", addr: $ip, port: $p, method: $m, password: $pw}')
            ;;
    esac
    
    if [ -n "$token_json" ]; then
        local token_base64=$(echo "$token_json" | base64 | tr -d '\n')
        echo ""
        _success "Token 生成成功！"
        echo -e "${YELLOW}请复制以下 Token 到 [中转机] 使用：${NC}"
        echo "---------------------------------------------------"
        echo "$token_base64"
        echo "---------------------------------------------------"
    else
        _error "Token 生成失败 (未知错误)。"
    fi
    
    read -p "按回车键继续..."
}

# --- 通用：完成中转配置 (Inbound + Outbound写入) ---
# 参数: $1=dest_type, $2=dest_addr, $3=dest_port, $4=outbound_json
_finalize_relay_setup() {
    local dest_type="$1"
    local dest_addr="$2"
    local dest_port="$3"
    local outbound_json="$4"

    _success "已解析落地节点: ${dest_type} -> ${dest_addr}:${dest_port}"
    
    # --- 选择中转入口协议 ---
    echo "请选择本机的 [中转入口] 协议 :"
    echo " 1) VLESS-Reality"
    echo " 2) Hysteria2"
    echo " 3) TUICv5"
    echo " 4) AnyTLS"
    read -p "请输入选项 [1-4]: " relay_choice
    
    local relay_type=""
    case "$relay_choice" in
        1) relay_type="vless-reality" ;;
        2) relay_type="hysteria2" ;;
        3) relay_type="tuic" ;;
        4) relay_type="anytls" ;;
        *) _error "无效选项"; return ;;
    esac
    
    # --- 配置入口详细信息 ---
    read -p "请输入本机监听端口 (回车随机): " listen_port
    [[ -z "$listen_port" ]] && listen_port=$(shuf -i 10000-50000 -n 1)
    
    read -p "请输入伪装域名 SNI (回车默认 www.microsoft.com): " sni
    [[ -z "$sni" ]] && sni="www.microsoft.com"
    
    # 获取国旗前缀
    local server_flag=$(_get_country_flag)
    
    local default_name="${relay_type}-Relay-${listen_port}"
    read -p "请输入节点名称 (回车: ${default_name}): " node_name
    # 添加国旗前缀 (与主脚本保持一致)
    [[ -z "$node_name" ]] && node_name="${server_flag}${default_name}" || node_name="${server_flag}${node_name}"

    
    # --- 生成配置 ---
    local tag_suffix="${listen_port}"
    local inbound_tag="${relay_type}-in-${tag_suffix}"
    local outbound_tag="relay-out-${tag_suffix}" # 对应的出口
    
    # 更新 outbound_json 中的 tag
    # 注意：传入的 outbound_json 必须是 jq 构造好的对象，我们需要修改它的 tag 字段
    outbound_json=$(echo "$outbound_json" | jq --arg t "$outbound_tag" '.tag = $t')

    # 1. 生成 Inbound (本机入口)
    local inbound_json=""
    local link=""
    local keypair=""
    local pbk=""
    
    # 证书处理 (Hy2/Tuic 需要) - 存储在辅助目录
    if [[ "$relay_type" == "hysteria2" || "$relay_type" == "tuic" || "$relay_type" == "anytls" ]]; then
        local cert_path="${RELAY_AUX_DIR}/${inbound_tag}.pem"
        local key_path="${RELAY_AUX_DIR}/${inbound_tag}.key"
        _info "正在生成自签名证书..."
        openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1
        openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${sni}" >/dev/null 2>&1
    fi
    
    if [ "$relay_type" == "vless-reality" ]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        keypair=$($SINGBOX_BIN generate reality-keypair)
        local pk=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
        pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
        local sid=$($SINGBOX_BIN generate rand --hex 8)
        
        # 默认开启 XTLS-Vision 流控
        local flow="xtls-rprx-vision"

        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg f "$flow" --arg sn "$sni" --arg pk "$pk" --arg sid "$sid" \
            '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":$f}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
             
        local server_ip=$(_get_public_ip)
        link="vless://${uuid}@${server_ip}:${listen_port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#${node_name}"
        
    elif [ "$relay_type" == "hysteria2" ]; then
        local password=$($SINGBOX_BIN generate rand --hex 16)
        
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg sn "$sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"server_name":$sn,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')

        local server_ip=$(_get_public_ip)
        link="hysteria2://${password}@${server_ip}:${listen_port}?sni=${sni}&insecure=1#${node_name}"
        
    elif [ "$relay_type" == "tuic" ]; then
        local uuid=$($SINGBOX_BIN generate uuid)
        local password=$($SINGBOX_BIN generate rand --hex 16)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg u "$uuid" --arg pw "$password" --arg sn "$sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"server_name":$sn,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
            
        local server_ip=$(_get_public_ip)
        link="tuic://${uuid}:${password}@${server_ip}:${listen_port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#${node_name}"
        
    elif [ "$relay_type" == "anytls" ]; then
        local password=$($SINGBOX_BIN generate uuid)
        inbound_json=$(jq -n --arg t "$inbound_tag" --arg p "$listen_port" --arg pw "$password" --arg sn "$sni" --arg cert "$cert_path" --arg key "$key_path" \
            '{"type":"anytls","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"name":"default","password":$pw}],"padding_scheme":["stop=8","0=30-30","1=100-400","2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000","3=9-9,500-1000","4=500-1000","5=500-1000","6=500-1000","7=500-1000"],"tls":{"enabled":true,"server_name":$sn,"certificate_path":$cert,"key_path":$key}}')
            
        local server_ip=$(_get_public_ip)
        link="anytls://${password}@${server_ip}:${listen_port}?security=tls&sni=${sni}&insecure=1&allowInsecure=1&type=tcp#${node_name}"
    fi
    
    # 2. 写入配置到主配置文件
    _info "正在写入配置..."
    
    # [配置隔离] 使用 RELAY_CONFIG_FILE
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    
    # 如果配置文件不存在 (理论上 _init_relay_dirs 已创建，但做个保险)
    if [ ! -f "$CONFIG_FILE" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$CONFIG_FILE"
    fi
    
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    # === 新增：检查是否存在重复的 tag ===
    if jq -e ".inbounds[] | select(.tag == \"$inbound_tag\")" "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "中转入口 tag \"$inbound_tag\" 已存在！"
        _warn "请先删除现有的中转路由，或使用不同的端口。"
        echo ""
        echo "解决方法："
        echo "  1) 进阶功能 → 4) 删除中转路由"
        echo "  2) 或者重新选择一个不同的监听端口"
        return 1
    fi
    
    if jq -e ".outbounds[] | select(.tag == \"$outbound_tag\")" "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "中转出口 tag \"$outbound_tag\" 已存在！"
        _warn "请先删除现有的中转路由，或使用不同的端口。"
        return 1
    fi
    # === 检查结束 ===
    
    jq ".inbounds += [$inbound_json]" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    jq ".outbounds = [$outbound_json] + .outbounds" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    local rule_json=$(jq -n --arg it "$inbound_tag" --arg ot "$outbound_tag" '{"inbound": $it, "outbound": $ot}')
    
    if ! jq -e '.route' "$CONFIG_FILE" >/dev/null; then
         jq '. += {"route":{"rules":[]}}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
    if ! jq -e '.route.rules' "$CONFIG_FILE" >/dev/null; then
         jq '.route.rules = []' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
    
    jq ".route.rules += [$rule_json]" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 验证配置文件有效性
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        _error "配置文件格式错误！正在回滚..."
        mv "${CONFIG_FILE}.bak" "$CONFIG_FILE"
        _log_operation "CONFIG_ERROR" "配置验证失败，已回滚"
        return 1
    fi
    
    _success "配置已更新！正在重启服务..."
    
    if [ -f "/etc/init.d/sing-box" ]; then
        rc-service sing-box restart
    else
        systemctl restart sing-box
    fi
    
    # 3. 存储链接信息到辅助目录（增强元数据）
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    if [ ! -f "$LINKS_FILE" ]; then
        echo '{}' > "$LINKS_FILE"
    fi
    
    # 使用 jq 添加或更新链接（包含元数据）
    local metadata=$(jq -n \
        --arg link "$link" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        --arg relay_type "$relay_type" \
        --arg landing_type "$dest_type" \
        --arg landing_addr "${dest_addr}:${dest_port}" \
        --arg node_name "$node_name" \
        '{link: $link, created_at: $created, relay_type: $relay_type, landing_type: $landing_type, landing_addr: $landing_addr, node_name: $node_name}')
    
    jq --arg tag "$inbound_tag" --argjson meta "$metadata" '.[$tag] = $meta' "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
    
    # 记录操作日志
    _log_operation "CREATE_RELAY" "Type: $relay_type, Port: $listen_port, Landing: ${dest_type}@${dest_addr}:${dest_port}"
    
    # 4. 添加到中转机专用 YAML 配置
    local server_ip=$(_get_public_ip)
    local proxy_json=""
    
    if [ "$relay_type" == "vless-reality" ]; then
        local uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid')
        local sn=$(echo "$inbound_json" | jq -r '.tls.server_name')
        local flow=$(echo "$inbound_json" | jq -r '.users[0].flow')
        local pk=$(echo "$inbound_json" | jq -r '.tls.reality.private_key')
        local sid=$(echo "$inbound_json" | jq -r '.tls.reality.short_id[0]')
        
        # 获取公钥（从 keypair 中提取）
        local pbk=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
        
        proxy_json=$(jq -n \
            --arg n "$node_name" \
            --arg s "$server_ip" \
            --arg p "$listen_port" \
            --arg u "$uuid" \
            --arg sn "$sn" \
            --arg pbk "$pbk" \
            --arg sid "$sid" \
            --arg flow "$flow" \
            '{name:$n,type:"vless",server:$s,port:($p|tonumber),uuid:$u,tls:true,network:"tcp",flow:$flow,servername:$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
            
    elif [ "$relay_type" == "hysteria2" ]; then
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sni=$(echo "$inbound_json" | jq -r '.tls.server_name // "www.microsoft.com"')
        
        proxy_json=$(jq -n \
            --arg n "$node_name" \
            --arg s "$server_ip" \
            --arg p "$listen_port" \
            --arg pw "$password" \
            --arg sn "$sni" \
            '{name:$n,type:"hysteria2",server:$s,port:($p|tonumber),password:$pw,sni:$sn,"skip-cert-verify":true,alpn:["h3"]}')
            
    elif [ "$relay_type" == "tuic" ]; then
        local uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid')
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sni=$(echo "$inbound_json" | jq -r '.tls.server_name // "www.microsoft.com"')
        
        proxy_json=$(jq -n \
            --arg n "$node_name" \
            --arg s "$server_ip" \
            --arg p "$listen_port" \
            --arg u "$uuid" \
            --arg pw "$password" \
            --arg sn "$sni" \
            '{name:$n,type:"tuic",server:$s,port:($p|tonumber),uuid:$u,password:$pw,sni:$sn,"skip-cert-verify":true,alpn:["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
            
    elif [ "$relay_type" == "anytls" ]; then
        local password=$(echo "$inbound_json" | jq -r '.users[0].password')
        local sni=$(echo "$inbound_json" | jq -r '.tls.server_name // "www.microsoft.com"')
        
        proxy_json=$(jq -n \
            --arg n "$node_name" \
            --arg s "$server_ip" \
            --arg p "$listen_port" \
            --arg pw "$password" \
            --arg sn "$sni" \
            '{name:$n,type:"anytls",server:$s,port:($p|tonumber),password:$pw,"client-fingerprint":"chrome",udp:true,"idle-session-check-interval":30,"idle-session-timeout":30,"min-idle-session":0,sni:$sn,alpn:["h2","http/1.1"],"skip-cert-verify":true}')
    fi
    
    if [ -n "$proxy_json" ]; then
        _add_node_to_relay_yaml "$proxy_json"
    fi
    
    echo "==================================================="
    _success "中转配置成功！"
    echo -e "中转节点: ${YELLOW}$node_name${NC}"
    echo -e "分享链接: ${CYAN}$link${NC}"
    echo "==================================================="
    
    read -p "按回车键继续..."
}

# --- 2. 中转机配置 (智能导入：Token 或分享链接) ---
# --- 2. 中转机配置 (智能导入：Token 或分享链接) ---
_relay_config() {
    echo "================================================"
    echo "     配置为 [中转机] - 智能识别导入            "
    echo "================================================"
    echo -e "${CYAN}支持的导入格式：${NC}"
    echo "  ✓ Base64 编码的 JSON Token (兼容原格式)"
    echo "  ✓ VLESS/VMess/Shadowsocks/Trojan/Hysteria2 分享链接"
    echo "  ✓ Base64 编码的分享链接"
    echo ""
    echo -e "${YELLOW}请粘贴您的导入内容 (粘贴后按回车):${NC}"
    
    # 使用 -e 支持 readline 编辑
    read -r -e input
    
    # 清理输入中的空白字符 (空格、换行、回车)
    input=$(echo "$input" | tr -d '[:space:]')
    
    if [ -z "$input" ]; then 
        _error "输入为空。"
        return
    fi
    
    _info "正在解析输入..."
    
    # 调用智能解析函数
    local parsed_result=$(_parse_landing_input "$input")
    
    if [ $? -ne 0 ] || [ -z "$parsed_result" ]; then
        _error "解析失败！无法识别输入格式。"
        _warn "请检查是否完整复制了链接或 Token。"
        return
    fi
    
    # 分割结果: outbound_json|dest_type|dest_addr|dest_port
    IFS='|' read -r outbound_json dest_type dest_addr dest_port <<< "$parsed_result"
    
    # 再次检查解析出的 JSON 是否有效
    if [ -z "$outbound_json" ] || ! echo "$outbound_json" | jq . >/dev/null 2>&1; then
        _error "解析结果无效 (JSON 格式错误)"
        return
    fi
    
    if [ -z "$dest_type" ]; then
        _error "无法确定协议类型"
        return
    fi
    
    _finalize_relay_setup "$dest_type" "$dest_addr" "$dest_port" "$outbound_json"
}



# --- 3. 查看中转路由 ---
_view_relays() {
    _info "正在扫描本机配置的中转路由..."
    
    # [配置隔离] 使用 RELAY_CONFIG_FILE
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then _error "配置文件不存在。"; return; fi
    
    # 检查 route.rules 是否存在
    if ! jq -e '.route.rules' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "当前没有任何中转路由规则。"
        read -p "按回车键继续..."
        return
    fi
    
    # 查找中转路由规则：outbound tag 以 "relay-out-" 开头的
    # 这样可以排除第三方适配层的内部路由（outbound 是 third-party-xxx）
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null and (.outbound | startswith("relay-out-")))' "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$rules" ]; then
        _warn "当前没有任何中转路由规则。"
        read -p "按回车键继续..."
        return
    fi
    
    echo "==================================================="
    echo "              当前中转节点链接"
    echo "==================================================="
    
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local i=1
    
    while IFS= read -r rule; do
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local out_tag=$(echo "$rule" | jq -r '.outbound')
        
        local metadata=""
        local created_at=""
        local landing_info=""
        local landing_type=""
        local node_name=""
        
        if [ -f "$LINKS_FILE" ]; then
            metadata=$(jq -r --arg t "$in_tag" '.[$t] // empty' "$LINKS_FILE")
            if [ -n "$metadata" ]; then
                # 检查是否为新格式（对象）或旧格式（字符串）
                if echo "$metadata" | jq -e '.link' >/dev/null 2>&1; then
                    # 新格式：包含元数据
                    link=$(echo "$metadata" | jq -r '.link')
                    created_at=$(echo "$metadata" | jq -r '.created_at // "未知"')
                    landing_info=$(echo "$metadata" | jq -r '.landing_addr // "未知"')
                    landing_type=$(echo "$metadata" | jq -r '.landing_type // "未知"')
                    node_name=$(echo "$metadata" | jq -r '.node_name // "未命名"')
                else
                    # 旧格式：直接是链接字符串（向后兼容）
                    link="$metadata"
                    created_at="--"
                    landing_info="--"
                    landing_type="--"
                    node_name="未命名"
                fi
            fi
        fi
        
        if [ -n "$link" ]; then
            # 从 inbound 获取一些基本信息用于display
            local inbound=$(jq -c --arg t "$in_tag" '.inbounds[] | select(.tag == $t)' "$CONFIG_FILE")
            local port=$(echo "$inbound" | jq -r '.listen_port')
            local type=$(echo "$inbound" | jq -r '.type')
            
            echo -e "${CYAN}$i)${NC} [${node_name}] [$type] 端口: ${port} -> 落地: ${landing_type}@${landing_info}"
            echo -e "   ${GREEN}创建时间:${NC} $created_at"
            echo -e "   ${YELLOW}链接:${NC} $link"
        else
            _warn "$i) 无法找到链接信息 (标签: $in_tag)"
        fi
        
        ((i++))
    done <<< "$rules"
    
    echo "==================================================="
    read -p "按回车键继续..."
}

# --- 4. 删除中转路由 ---
_delete_relay() {
    _info "准备删除中转路由..."
    
    # [配置隔离] 使用 RELAY_CONFIG_FILE
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then _error "配置文件不存在。"; return; fi
    
    # 检查 route.rules 是否存在
    if ! jq -e '.route.rules' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "没有可删除的中转路由。"
        read -p "按回车键继续..."
        return
    fi
    
    # 仅查找真正的中转路由（outbound 以 relay-out- 开头）
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null and (.outbound | startswith("relay-out-")))' "$CONFIG_FILE")
    
    if [ -z "$rules" ]; then
        _warn "没有可删除的中转路由。"
        read -p "按回车键继续..."
        return
    fi
    
    echo "==================================================="
    echo "              删除中转路由"
    echo "==================================================="
    
    local i=1
    local rule_list=()
    
    while IFS= read -r rule; do
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local out_tag=$(echo "$rule" | jq -r '.outbound')
        local inbound=$(jq -c --arg t "$in_tag" '.inbounds[] | select(.tag == $t)' "$CONFIG_FILE")
        local port="Unknown"
        local type="Unknown"
        local node_name="未命名"
        
        if [ -n "$inbound" ]; then
             port=$(echo "$inbound" | jq -r '.listen_port')
             type=$(echo "$inbound" | jq -r '.type')
        fi
        
        # 尝试从链接文件获取节点名称
        local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
        if [ -f "$LINKS_FILE" ]; then
            local metadata=$(jq -r --arg t "$in_tag" '.[$t] // empty' "$LINKS_FILE")
            if [ -n "$metadata" ]; then
                if echo "$metadata" | jq -e '.node_name' >/dev/null 2>&1; then
                    node_name=$(echo "$metadata" | jq -r '.node_name')
                fi
            fi
        fi
        
        echo -e " ${RED}$i)${NC} [${node_name}] 端口: ${port} (类型: ${type}) [In: ${in_tag} -> Out: ${out_tag}]"
        rule_list+=("$rule")
        ((i++))
    done <<< "$rules"
    
    echo " 0) 取消"
    echo " A) 删除所有中转路由"
    read -p "请输入要删除的序号: " choice
    
    # 处理批量删除
    if [[ "$choice" == "A" || "$choice" == "a" ]]; then
        echo ""
        _warn "即将删除所有 $((i-1)) 个中转路由！"
        read -p "$(echo -e ${RED})确认删除所有? (yes/N): $(echo -e ${NC})" confirm_all
        if [[ "$confirm_all" == "yes" ]]; then
            _info "正在批量删除所有中转路由..."
            
            # 使用主配置文件
            cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
            
            # 仅删除中转路由规则（outbound 以 relay-out- 开头的）
            jq '.route.rules = [.route.rules[] | select((.outbound | startswith("relay-out-")) | not)]' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            
            # 删除所有中转相关的 inbounds 和 outbounds（通过筛选后的路由规则）
            while IFS= read -r rule; do
                local in_tag=$(echo "$rule" | jq -r '.inbound')
                local out_tag=$(echo "$rule" | jq -r '.outbound')
                jq "del(.inbounds[] | select(.tag == \"$in_tag\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
                jq "del(.outbounds[] | select(.tag == \"$out_tag\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
                rm -f "${RELAY_AUX_DIR}/${in_tag}.pem" "${RELAY_AUX_DIR}/${in_tag}.key"
            done <<< "$rules"
            
            # 清空链接存储
            local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
            echo '{}' > "$LINKS_FILE"
            
            # 清空 YAML 配置中的所有节点
            local YQ_BINARY="/usr/local/bin/yq"
            if [ -f "$RELAY_CLASH_YAML" ] && [ -f "$YQ_BINARY" ]; then
                ${YQ_BINARY} eval '.proxies = []' -i "$RELAY_CLASH_YAML"
                ${YQ_BINARY} eval '.proxy-groups[0].proxies = []' -i "$RELAY_CLASH_YAML"
                _info "已清空 YAML 配置中的所有节点"
            fi
            
            _log_operation "DELETE_ALL_RELAYS" "Deleted all $((i-1)) relay routes"
            
            # 重启服务
            if [ -f "/etc/init.d/sing-box" ]; then
                rc-service sing-box restart
            else
                systemctl restart sing-box
            fi
            
            _success "所有中转路由已删除！"
            read -p "按回车键继续..."
            return
        else
            _info "已取消批量删除"
            return
        fi
    fi
    
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        return
    fi
    
    local selected_rule=${rule_list[$((choice-1))]}
    local in_tag_del=$(echo "$selected_rule" | jq -r '.inbound')
    local out_tag_del=$(echo "$selected_rule" | jq -r '.outbound')
    
    # 添加删除确认
    echo ""
    _warn "即将删除中转路由: ${in_tag_del} -> ${out_tag_del}"
    read -p "$(echo -e ${YELLOW})确认删除? (y/N): $(echo -e ${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "已取消删除"
        return
    fi
    
    _info "正在删除中转路由: ${in_tag_del} -> ${out_tag_del}"
    
    # 修改配置文件
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    # 1. 删除 rule
    jq "del(.route.rules[] | select(.inbound == \"$in_tag_del\" and .outbound == \"$out_tag_del\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 2. 删除 inbound
    jq "del(.inbounds[] | select(.tag == \"$in_tag_del\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 3. 删除 outbound
    jq "del(.outbounds[] | select(.tag == \"$out_tag_del\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 4. 清理证书 (如果有) - 从辅助目录
    rm -f "${RELAY_AUX_DIR}/${in_tag_del}.pem" "${RELAY_AUX_DIR}/${in_tag_del}.key"
    
    # 5. 从 YAML 配置中删除节点（必须在删除链接文件前执行）
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    if [ -f "$LINKS_FILE" ]; then
        local node_name_yaml=$(jq -r --arg t "$in_tag_del" '.[$t].node_name // empty' "$LINKS_FILE")
        if [ -n "$node_name_yaml" ]; then
            _remove_node_from_relay_yaml "$node_name_yaml"
        fi
    fi
    
    # 6. 清理存储的链接
    if [ -f "$LINKS_FILE" ]; then
        jq --arg t "$in_tag_del" 'del(.[$t])' "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
    fi
    
    # 7. 清理旧备份文件（保留最近3个）
    ls -t ${CONFIG_FILE}.bak* 2>/dev/null | tail -n +4 | xargs -r rm 2>/dev/null
    
    # 记录删除操作
    _log_operation "DELETE_RELAY" "Tag: $in_tag_del, Outbound: $out_tag_del"
    
    _success "删除成功！正在重启服务..."
    
    if [ -f "/etc/init.d/sing-box" ]; then
        rc-service sing-box restart
    else
        systemctl restart sing-box
    fi
    
    _success "服务已重启。"
    read -p "按回车键继续..."
}

# --- 5. 修改中转路由端口 ---
_modify_relay_port() {
    _info "准备修改中转路由端口..."
    
    # [配置隔离] 使用 RELAY_CONFIG_FILE
    local CONFIG_FILE="$RELAY_CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        _error "配置文件不存在。"
        return
    fi
    
    # 检查 route.rules 是否存在
    if ! jq -e '.route.rules' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "没有可修改的中转路由。"
        read -p "按回车键继续..."
        return
    fi
    
    local rules=$(jq -c '.route.rules[] | select(.inbound != null and .outbound != null)' "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$rules" ]; then
        _warn "没有可修改的中转路由。"
        read -p "按回车键继续..."
        return
    fi
    
    echo "==================================================="
    echo "              修改中转路由端口"
    echo "==================================================="
    
    local i=1
    local rule_list=()
    local inbound_list=()
    
    while IFS= read -r rule; do
        local in_tag=$(echo "$rule" | jq -r '.inbound')
        local out_tag=$(echo "$rule" | jq -r '.outbound')
        local inbound=$(jq -c --arg t "$in_tag" '.inbounds[] | select(.tag == $t)' "$CONFIG_FILE")
        local port="Unknown"
        local type="Unknown"
        if [ -n "$inbound" ]; then
            port=$(echo "$inbound" | jq -r '.listen_port')
            type=$(echo "$inbound" | jq -r '.type')
        fi
        
        echo -e " ${CYAN}$i)${NC} 端口: ${GREEN}${port}${NC} (类型: ${YELLOW}${type}${NC}) [${in_tag}]"
        rule_list+=("$rule")
        inbound_list+=("$inbound")
        ((i++))
    done <<< "$rules"
    
    echo " 0) 返回"
    read -p "请输入要修改端口的序号: " choice
    
    if ! [[ "$choice" =~ ^[1-9][0-9]*$ ]] || [ "$choice" -ge "$i" ]; then
        return
    fi
    
    local index=$((choice-1))
    local selected_rule=${rule_list[$index]}
    local selected_inbound=${inbound_list[$index]}
    
    local in_tag=$(echo "$selected_rule" | jq -r '.inbound')
    local old_port=$(echo "$selected_inbound" | jq -r '.listen_port')
    local relay_type=$(echo "$selected_inbound" | jq -r '.type')
    
    _info "当前端口: ${old_port}"
    _info "节点类型: ${relay_type}"
    
    read -p "请输入新的端口号: " new_port
    
    # 验证端口
    if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        _error "无效的端口号！"
        return
    fi
    
    if [ "$new_port" -eq "$old_port" ]; then
        _warning "新端口与当前端口相同，无需修改。"
        return
    fi
    
    # 检查端口是否已被占用
    if jq -e ".inbounds[] | select(.listen_port == $new_port)" "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "端口 $new_port 已被其他节点使用！"
        return
    fi
    
    _info "正在修改端口: ${old_port} -> ${new_port}"
    
    # 备份配置
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    # 1. 修改 inbound 的端口
    jq "(.inbounds[] | select(.tag == \"$in_tag\") | .listen_port) = $new_port" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 2. 处理证书文件重命名（仅 Hysteria2 和 TUIC）
    if [ "$relay_type" == "hysteria2" ] || [ "$relay_type" == "tuic" ]; then
        local old_cert="${RELAY_AUX_DIR}/${in_tag}.pem"
        local old_key="${RELAY_AUX_DIR}/${in_tag}.key"
        
        # 从旧tag中提取前缀
        local tag_prefix=$(echo "$in_tag" | sed 's/-in-[0-9]*$//')
        local new_tag="${tag_prefix}-in-${new_port}"
        
        local new_cert="${RELAY_AUX_DIR}/${new_tag}.pem"
        local new_key="${RELAY_AUX_DIR}/${new_tag}.key"
        
        # 重命名证书文件
        if [ -f "$old_cert" ] && [ -f "$old_key" ]; then
            mv "$old_cert" "$new_cert"
            mv "$old_key" "$new_key"
            
            # 更新配置中的证书路径
            jq "(.inbounds[] | select(.tag == \"$in_tag\") | .tls.certificate_path) = \"$new_cert\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            jq "(.inbounds[] | select(.tag == \"$in_tag\") | .tls.key_path) = \"$new_key\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        fi
        
        # 更新 tag
        jq "(.inbounds[] | select(.tag == \"$in_tag\") | .tag) = \"$new_tag\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        
        # 更新路由规则中的 inbound tag
        jq "(.route.rules[] | select(.inbound == \"$in_tag\") | .inbound) = \"$new_tag\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        
        # 更新链接存储中的 key
        local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
        if [ -f "$LINKS_FILE" ]; then
            local link_data=$(jq --arg old "$in_tag" '.[$old]' "$LINKS_FILE")
            if [ "$link_data" != "null" ]; then
                # 更新链接中的端口号
                local old_link=$(echo "$link_data" | jq -r '.link')
                local new_link=$(echo "$old_link" | sed "s/:${old_port}/:${new_port}/g")
                
                # 删除旧 key，添加新 key
                jq --arg old "$in_tag" --arg new "$new_tag" --arg link "$new_link" \
                    'del(.[$old]) | .[$new] = (.[$old] // {}) | .[$new].link = $link' \
                    "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
            fi
        fi
        
        # 使用新tag作为当前操作的tag
        in_tag="$new_tag"
    else
        # 对于其他协议（VLESS Reality），只需要更新链接
        local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
        if [ -f "$LINKS_FILE" ]; then
            local link_data=$(jq --arg tag "$in_tag" '.[$tag]' "$LINKS_FILE")
            if [ "$link_data" != "null" ]; then
                local old_link=$(echo "$link_data" | jq -r '.link')
                local new_link=$(echo "$old_link" | sed "s/:${old_port}[?&]/:${new_port}?/g")
                jq --arg tag "$in_tag" --arg link "$new_link" '.[$tag].link = $link' "$LINKS_FILE" > "${LINKS_FILE}.tmp" && mv "${LINKS_FILE}.tmp" "$LINKS_FILE"
            fi
        fi
    fi
    
    # 3. 同步更新 YAML 配置文件中的端口
    local LINKS_FILE="${RELAY_AUX_DIR}/relay_links.json"
    local YQ_BINARY="/usr/local/bin/yq"
    
    if [ -f "$RELAY_CLASH_YAML" ] && [ -f "$YQ_BINARY" ]; then
        # 从链接文件获取节点名称
        local node_name_yaml=""
        if [ -f "$LINKS_FILE" ]; then
            node_name_yaml=$(jq -r --arg tag "$in_tag" '.[$tag].node_name // empty' "$LINKS_FILE")
        fi
        
        # 如果找到了节点名称，更新 YAML 中的端口
        if [ -n "$node_name_yaml" ]; then
            _info "正在同步更新 YAML 配置中的端口..."
            ${YQ_BINARY} eval '(.proxies[] | select(.name == "'${node_name_yaml}'") | .port) = '${new_port} -i "$RELAY_CLASH_YAML"
            _success "YAML 配置已同步更新"
        fi
    fi
    
    # 记录操作
    _log_operation "MODIFY_RELAY_PORT" "Tag: $in_tag, Old Port: $old_port, New Port: $new_port"
    
    _success "端口修改成功！正在重启服务..."
    
    if [ -f "/etc/init.d/sing-box" ]; then
        rc-service sing-box restart
    else
        systemctl restart sing-box
    fi
    
    _success "服务已重启。"
    read -p "按回车键继续..."
}

# --- 菜单 ---
_advanced_menu() {
    _check_deps
    _init_relay_dirs
    
    # 颜色定义（如果未定义）
    local CYAN='\033[0;36m'
    local GREEN='\033[0;32m'
    local YELLOW='\033[0;33m'
    local NC='\033[0m'
    
    while true; do
        clear
        # 小型 Logo
        echo -e "${CYAN}"
        echo '  ╔═══════════════════════════════════════╗'
        echo '  ║     sing-box 进阶功能 (中转/落地)     ║'
        echo '  ╚═══════════════════════════════════════╝'
        echo -e "${NC}"
        echo ""
        
        # 落地机配置
        echo -e "  ${CYAN}【落地机配置】${NC}"
        echo -e "    ${GREEN}[1]${NC} 落地机配置 (VLESS-TCP / Shadowsocks)"
        echo ""
        
        # 中转机配置
        echo -e "  ${CYAN}【中转机配置】${NC}"
        echo -e "    ${GREEN}[2]${NC} 中转机配置 (智能导入：Token/分享链接)"
        echo -e "    ${GREEN}[3]${NC} 查看中转节点链接"
        echo -e "    ${GREEN}[4]${NC} 删除中转路由"
        echo -e "    ${GREEN}[5]${NC} 修改中转端口"
        echo ""
        
        echo -e "  ─────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        
        read -p "  请输入选项: " choice
        
        case $choice in
            1) _landing_config ;;
            2) _relay_config ;;
            3) _view_relays ;;
            4) _delete_relay ;;
            5) _modify_relay_port ;;
            0) exit 0 ;;
            *) echo "无效选择" ;;
        esac
        
        echo ""
        echo -e "${YELLOW}按任意键返回中转菜单...${NC}"
        read -n 1 -s -r
    done
}

_advanced_menu
