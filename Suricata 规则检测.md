# 1 概述
首先需要了解suricata规则，规则也叫做签名：[8.1. Rules Format — Suricata 8.0.0-dev documentation](https://docs.suricata.io/en/latest/rules/intro.html) 

规则检测主要分为 规则加载与初始化设置，规则匹配。

# 2 规则加载
规则以专有格式编写并存放在.rules文件内，通过配置文件指定规则路径和文件名。程序启动时从配置文件指定位置读取规则文件中的数据并解析，解析后用结构体Signature表示单条规则。

# 3 规则初始化设置
为了后续的规则匹配，前期需要做很多工作。比如对于IPOnly规则，suricata使用radix树进行匹配，所以前期需要构建radix树。

为了加速规则匹配速度，尽量缩小规则匹配的范围，suricata采取对规则进行分组：[12.1. Suricata.yaml — Suricata 8.0.0-dev documentation](https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#inspection-configuration) 。规则分组把规则按照协议(tcp,udp,icmp...)，端口，方向(toclient,toserver)分为规则组。

为了提高规则匹配速度，suricata采取预过滤机制，从规则中挑选某个条件加入到预过滤引擎，suricata首先匹配预过滤引擎中的条件，匹配成功的条件对应的签名进入后续进一步检测。预过滤引擎需要保证匹配高效，通常使用mpm（多模匹配），也叫做fast_pattern，并使用高效的多模匹配算法进行匹配。

