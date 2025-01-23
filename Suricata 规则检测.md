# 1 概述

首先需要了解 suricata 规则，规则也叫做签名：[8.1. Rules Format — Suricata 8.0.0-dev documentation](https://docs.suricata.io/en/latest/rules/intro.html)

规则检测主要分为 规则加载与初始化设置，规则匹配。

## 1.1 规则加载

规则以专有格式编写并存放在.rules 文件内，通过配置文件指定规则路径和文件名。程序启动时从配置文件指定位置读取规则文件中的数据并解析，解析后用结构体 Signature 表示单条规则。

## 1.2 规则初始化设置

为了后续的规则匹配，前期需要做很多工作。比如对于 IPOnly 规则，suricata 使用 radix 树进行匹配，所以前期需要构建 radix 树。

为了加速规则匹配速度，尽量缩小规则匹配的范围，suricata 采取对规则进行分组：[12.1. Suricata.yaml — Suricata 8.0.0-dev documentation](https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#inspection-configuration) 。规则分组把规则按照协议(tcp,udp,icmp...)，端口，方向(toclient,toserver)分为规则组。

为了提高规则匹配速度，suricata 采取预过滤机制，从规则中挑选某个条件加入到预过滤引擎，suricata 首先匹配预过滤引擎中的条件，匹配成功的条件对应的签名进入后续进一步检测。预过滤引擎需要保证匹配高效，通常使用 mpm（多模匹配），也叫做 fast_pattern，并使用高效的多模匹配算法进行匹配。

# 2 实现

## 2.1 规则加载与初始化

### 如何设置预过滤条件

首先需要为每条签名选择预过滤条件，用于预过滤的规则条件一般是模式串，也可以是协议关键字；模式串可以使用多模匹配算法加速过滤。选择的预过滤模式串存放在 s->init_data->mpm_sm，s 表示签名结构 Signature，init_data 指代下面的结构。

```c
typedef struct SignatureInitData_ {
    // --- snip ---
    /* the fast pattern added from this signature */
    SigMatch *mpm_sm;
    // --- snip ---
} SignatureInitData;
```

在检测引擎构建的 stage4 中，首先把同一个规则分组下的用于预过滤的模式串聚合，这里使用位数组记录签名，构建 MpmStore 结构，然后调用 MpmStoreSetup 把预过滤模式串添加到多模匹配算法所管理的上下文中，对应 Mpmstore 中的成员 mpm_ctx。然后把该结构插入到检测引擎上下文中的哈希表中 。de_ctx->mpm_hash_table。

```c
typedef struct MpmStore_ {
    uint8_t *sid_array;
    uint32_t sid_array_size;

    int direction;
    enum MpmBuiltinBuffers buffer;
    int sm_list;
    int32_t sgh_mpm_context;
    AppProto alproto;
    MpmCtx *mpm_ctx;

} MpmStore;
```

遍历添加模式串的代码位置：

```c
static void MpmStoreSetup(const DetectEngineCtx *de_ctx, MpmStore *ms)
{
// snip ---
    /* add the patterns */
    for (sig = 0; sig < (ms->sid_array_size * 8); sig++) {
    // snip --
                PopulateMpmHelperAddPattern(
                        ms->mpm_ctx, cd, s, flags, (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP));
            }
        }
    }
// snip ---
```

### 规则分组实现

规则基于端口，协议进行分组。

#### 基于端口分组

端口使用 DetectPort 结构表示：

```c
typedef struct DetectPort_ {
    uint16_t port;
    uint16_t port2;

    uint8_t flags;  /**< flags for this port */

    /* signatures that belong in this group
     *
     * If the PORT_SIGGROUPHEAD_COPY flag is set, we don't own this pointer
     * (memory is freed elsewhere).
     */
    struct SigGroupHead_ *sh;

    struct DetectPort_ *prev;
    struct DetectPort_ *next;
    struct DetectPort_ *last; /* Pointer to the last node in the list */
}   DetectPort;
```

使用 port，port2 可以实现表示单一端口，端口范围，多个端口则使用链表结构组织。
sh 中记录了跟端口相关得规则，实现方式是使用位数组记录规则 id，最终基于端口分好的组挂载在 de_ctx->flow_gh 的 tcp udp 成员上。

#### 基于协议的分组

支持基于以下协议进行分组：

1. 传输层协议：tcp, tcp-pkt, tcp-stream, udp, icmpv4, icmpv6, sctp
2. 应用层协议：注册过协议解码的应用层协议，也即是支持解析的应用层协议。
   ip 层协议被认为等同于 any。

最终基于协议分好的组挂载在 de_ctx->flow_gh 的 sgh 指针数组上。
