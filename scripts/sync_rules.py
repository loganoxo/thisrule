#!/usr/bin/env python3
# python scripts/sync_rules.py --upstream test/ios_rule_script

import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path
import config  # 导入本地配置文件

# 定义不同代理规则类型的排序优先级
RULE_ORDER = {
  "DOMAIN": 0,
  "HOST": 1,
  "DOMAIN-SUFFIX": 2,
  "HOST-SUFFIX": 3,
  "DOMAIN-KEYWORD": 4,
  "HOST-KEYWORD": 5,
  "DOMAIN-WILDCARD": 6,
  "HOST-WILDCARD": 7,
  "DOMAIN-REGEX": 8,
  "IP-CIDR": 9,
  "IP-CIDR6": 10,
  "IP6-CIDR": 11,
  "IP-ASN": 12,
  "USER-AGENT": 13,
  "URL-REGEX": 14,
}

# 定义支持的客户端, 统一使用 .list 格式
CLIENTS = [
  "Loon",
  "Surge",
  "Clash",
  "QuantumultX",
  "Shadowrocket",
]

# 定义需要处理 no-resolve 逻辑的特定客户端
CLIENTS_WITH_NO_RESOLVE = {
  "Loon",
  "Surge",
  "Clash",
  "Shadowrocket",
}

# 定义 Loon 到 QuantumultX 的规则类型映射
QX_TYPE_MAPPING = {
  "DOMAIN": "HOST",
  "DOMAIN-SUFFIX": "HOST-SUFFIX",
  "DOMAIN-KEYWORD": "HOST-KEYWORD",
  "DOMAIN-WILDCARD": "HOST-WILDCARD",
  "IP-CIDR6": "IP6-CIDR",
}

# 定义 QuantumultX 允许的规则类型白名单
QX_ALLOWED_TYPES = {
  "USER-AGENT",
  "HOST",
  "HOST-KEYWORD",
  "HOST-WILDCARD",
  "HOST-SUFFIX",
  "IP6-CIDR",
  "IP-CIDR",
  "GEOIP",
  "IP-ASN",
}


def parse_lines(path: Path) -> list[str]:
  # 解析文件, 返回有效的规则行列表
  if not path.exists():
    return []
  lines = []
  for raw in path.read_text(errors="ignore").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
      continue
    lines.append(line)
  return lines


def convert_to_qx(rule: str) -> str:
  # 将单个 Loon 格式规则转换为 QuantumultX 格式
  rule_type, sep, rest = rule.partition(",")
  rule_type_clean = rule_type.strip().upper()
  if rule_type_clean in QX_TYPE_MAPPING:
    return f"{QX_TYPE_MAPPING[rule_type_clean]}{sep}{rest}"
  return rule


def sort_key(rule: str) -> tuple[int, str, str]:
  # 按照第一个逗号前的字符(去除前后空格, 不区分大小写)进行优先级映射和排序
  rule_type, _, rest = rule.partition(",")
  rule_type_clean = rule_type.strip().upper()

  # 排序优先级: 1. RULE_ORDER定义的顺序 2. 规则类型名称字母顺序 3. 逗号后的内容
  return RULE_ORDER.get(rule_type_clean, 99), rule_type_clean, rest


def build_header(name: str, client: str, updated: str, counts: Counter) -> list[str]:
  # 构建包含数量统计的头部信息
  header = [
    f"# NAME: {name}",
    f"# CLIENT: {client}",
    f"# UPDATED: {updated}",
  ]
  sorted_keys = sorted(counts.keys(), key=lambda k: RULE_ORDER.get(k.upper(), 99))
  for key in sorted_keys:
    header.append(f"# {key}: {counts[key]}")
  header.append(f"# TOTAL: {sum(counts.values())}")
  return header


def main() -> None:
  # 检查配置文件中是否存在 TASKS 列表, 如果不存在则抛出错误
  if not hasattr(config, 'TASKS'):  # 检查配置属性是否存在
    print("❌ 错误: send_msg_config.py 中未找到 'TASKS' 列表配置")  # 打印错误提示
    return  # 退出程序

  parser = argparse.ArgumentParser()
  parser.add_argument("--upstream", required=True, help="ios_rule_script 本地仓库的绝对或相对路径")
  args = parser.parse_args()

  upstream_root = Path(args.upstream)
  local_repo_root = Path(__file__).resolve().parents[1]

  # 外层循环: 遍历规则大类 (如 AI)
  for task_name, sources in config.TASKS.items():
    task_dir = local_repo_root / "rule" / task_name

    # 建立并初始化当前分类下的全局 z-custom 目录及文件
    z_custom_dir = task_dir / "z-custom"
    z_custom_dir.mkdir(parents=True, exist_ok=True)

    global_add_file = z_custom_dir / "add.list"
    global_remove_file = z_custom_dir / "remove.list"

    if not global_add_file.exists():
      global_add_file.write_text("")
    if not global_remove_file.exists():
      global_remove_file.write_text("")

    # 提前载入全局共享的自定义列表
    global_rules_to_remove = set(parse_lines(global_remove_file))
    global_rules_to_add = set(parse_lines(global_add_file))

    # 内层循环: 遍历每个客户端 (如 Clash, Surge)
    for client in CLIENTS:
      ext = ".list"

      # 定义当前客户端的专属工作目录: thisrule/rule/{task_name}/{client}
      target_dir = task_dir / client
      target_dir.mkdir(parents=True, exist_ok=True)

      # 建立并初始化当前客户端特有的 custom 目录及文件
      custom_dir = target_dir / "custom"
      custom_dir.mkdir(parents=True, exist_ok=True)

      client_add_file = custom_dir / "add.list"
      client_remove_file = custom_dir / "remove.list"

      if not client_add_file.exists():
        client_add_file.write_text("")
      if not client_remove_file.exists():
        client_remove_file.write_text("")

      # 将全局的 z-custom 配置与客户端专属的 custom 配置进行聚合 (取并集)
      rules_to_remove = global_rules_to_remove | set(parse_lines(client_remove_file))
      rules_to_add = global_rules_to_add | set(parse_lines(client_add_file))

      # ====== 针对 QuantumultX 的特殊规则转换与白名单过滤 ======
      if client == "QuantumultX":
        filtered_qx_add = set()
        # 仅对 rules_to_add 进行格式转换
        for rule in rules_to_add:
          converted_rule = convert_to_qx(rule)
          rule_type = converted_rule.partition(",")[0].strip().upper()
          # 仅对转换后的 rules_to_add 执行白名单过滤
          if rule_type in QX_ALLOWED_TYPES:
            filtered_qx_add.add(converted_rule)

        rules_to_add = filtered_qx_add
        # rules_to_remove 保持原样, 不做任何转换和过滤

      # 基础整行匹配去重集合
      merged_rules: set[str] = set()

      # 合并上游规则
      for source in sources:
        # 上游的读取路径保持不变
        source_path = upstream_root / "rule" / client / source / f"{source}{ext}"
        if not source_path.exists():
          print(f"  [警告] 上游缺少文件: {source_path}")
          continue
        for line in parse_lines(source_path):
          merged_rules.add(line)

      # 执行删除 (严格校验整行文本是否在移除列表中)
      final_rules = {rule for rule in merged_rules if rule not in rules_to_remove}

      # 执行添加
      final_rules.update(rules_to_add)

      supports_no_resolve = client in CLIENTS_WITH_NO_RESOLVE

      main_rules_set = set()
      resolve_rules_set = set()
      for rule in final_rules:
        rule_type = rule.partition(",")[0].strip().upper()
        if rule_type in ("IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"):
          # 从右向左寻找第一个逗号进行分割, 最多分割一次
          parts = rule.rsplit(",", 1)

          # 判断切分出的最后一段是否为 no-resolve (去除前后空格, 忽略大小写)
          if len(parts) == 2 and parts[1].strip().lower() == "no-resolve":
            # 原规则已包含 no-resolve
            main_rules_set.add(rule)
            # 删除 no-resolve: 取逗号前的内容, 并去除可能多余的尾部空格
            resolve_rules_set.add(parts[0].rstrip())
          else:
            # 原规则未包含 no-resolve
            main_rules_set.add(f"{rule},no-resolve")
            resolve_rules_set.add(rule)
        else:
          main_rules_set.add(rule)
          resolve_rules_set.add(rule)

      if not supports_no_resolve:
        # 若不支持
        main_rules_set = set(resolve_rules_set)
        resolve_rules_set = set()

      # ====== 统一执行最后一步: 转换为列表并执行排序 ======
      main_rules = sorted(list(main_rules_set), key=sort_key)
      updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

      # 统计主文件规则数量并写入
      main_counts = Counter(rule.partition(",")[0].strip().upper() for rule in main_rules)
      main_header = build_header(task_name, client, updated, main_counts)

      main_output_path = target_dir / f"{task_name}{ext}"
      main_output_path.write_text("\n".join(main_header + main_rules) + "\n")

      # 仅对支持的客户端生成并写入解析规则文件
      if supports_no_resolve:
        resolve_rules = sorted(list(resolve_rules_set), key=sort_key)
        resolve_counts = Counter(rule.partition(",")[0].strip().upper() for rule in resolve_rules)
        resolve_header = build_header(f"{task_name}_Resolve", client, updated, resolve_counts)

        resolve_output_path = target_dir / f"{task_name}_Resolve{ext}"
        resolve_output_path.write_text("\n".join(resolve_header + resolve_rules) + "\n")

        print(f"[{task_name}] - [{client}] 处理完成, 主文件包含 {len(main_rules)} 条规则.")
      else:
        print(f"[{task_name}] - [{client}] 处理完成, 包含 {len(main_rules)} 条规则 (不生成 Resolve 文件).")


if __name__ == "__main__":
  main()
