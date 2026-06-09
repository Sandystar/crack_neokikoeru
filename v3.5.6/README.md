# Neokikoeru v3.5.6

- `crack.py`：本地二进制补丁
- `crack_docker.py`：Docker 容器补丁

## 安装

```bash
pip install -r requirements.txt
```

## 本地补丁

```bash
python crack.py --input <binary>
python crack.py --input <binary> --output <patched_binary> --force
```

- 自动识别 `PE` / `ELF` / `Mach-O`
- 自动识别 `amd64` / `arm64`
- 按对应架构直接全量补丁

## Docker 补丁

1. 修改 `patch_config_docker.json`
2. 运行

```bash
python crack_docker.py
```

流程
- SSH -> 停容器 -> 拉取文件 -> 本地补丁 -> 回推 -> 启动容器

说明
- `patch_config.json`：补丁点配置
- `patch_config_docker.json`：SSH / Docker 配置
- `docker.remote_stage_dir`：远端中转目录，执行后自动删除