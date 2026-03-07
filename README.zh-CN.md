# License Skill 工作区

这个仓库包含一个开源协议审查技能，重点包括：

- 从代码仓库中提取协议证据
- 解析 SPDX 表达式（`AND` / `OR` / `WITH`，并给出风险区间）
- 提取 CycloneDX/SPDX SBOM 中的许可证信息
- 输出可执行的合规建议、风险提醒与回馈开源建议

## 项目结构

- `oss-license-review/SKILL.md`：技能行为与工作流
- `oss-license-review/scripts/license_inventory.py`：主分析 CLI
- `oss-license-review/references/license-obligations.md`：协议义务参考
- `oss-license-review/tests/`：单元测试与 CLI 集成测试

## 快速开始

分析项目（人类可读输出）：

```bash
python3 oss-license-review/scripts/license_inventory.py /path/to/repo --use-case saas --modified
```

输出 JSON：

```bash
python3 oss-license-review/scripts/license_inventory.py /path/to/repo --use-case binary --json
```

## 测试

运行测试：

```bash
python3 -m unittest discover -s oss-license-review/tests -v
```

## 说明

- 输出属于技术合规评估，不构成法律意见。
- 对于大型 SBOM 文件，在安装可选依赖 `ijson` 时会优先使用流式解析。
