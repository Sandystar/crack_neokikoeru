from __future__ import annotations

import argparse
import json
import os
import shlex
import time
from pathlib import Path
from typing import Any

from crack import (
    detect_binary_info,
    load_config,
    parse_hex_bytes,
    select_targets,
    sha256_file,
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


DEFAULT_SSH_ENV = {
    'host': 'NEOKIKOERU_DOCKER_HOST',
    'username': 'NEOKIKOERU_DOCKER_USER',
    'password': 'NEOKIKOERU_DOCKER_PASSWORD',
    'sudo_password': 'NEOKIKOERU_DOCKER_SUDO_PASSWORD',
    'key_filename': 'NEOKIKOERU_DOCKER_KEY',
}


def cfg_value(section: dict[str, Any], key: str, default: Any = None) -> Any:
    value = section.get(key, default)
    env_name = section.get('env', DEFAULT_SSH_ENV).get(key)
    if (value is None or value == '') and env_name:
        return os.environ.get(env_name, default)
    return value


def require_text(value: Any, name: str) -> str:
    if value is None or str(value) == '':
        raise SystemExit(f'missing required docker config value: {name}')
    return str(value)


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0

    text = str(value).strip().lower()
    if text in {'1', 'true', 'yes', 'y', 'on'}:
        return True
    if text in {'0', 'false', 'no', 'n', 'off'}:
        return False
    raise SystemExit(f'invalid boolean config value: {value!r}')


def apply_compat_defaults(docker_config: dict[str, Any]) -> dict[str, Any]:
    targets = docker_config.get('targets', [])
    if isinstance(targets, list):
        for index, target in enumerate(targets):
            if not isinstance(target, dict):
                continue
            target.setdefault('required', index == 0)
            target.setdefault('role', 'runtime_entrypoint' if index == 0 else 'volume_copy_if_present')
    return docker_config


def validate_effective_configs(docker_config: dict[str, Any], patch_config: dict[str, Any], patch_config_path: Path) -> None:
    for section in ('ssh', 'docker', 'patch', 'targets'):
        if section not in docker_config:
            raise SystemExit(f'missing docker config section: {section}')

    if not patch_config_path.exists():
        raise SystemExit(f'patch config file not found: {patch_config_path}')

    architectures = patch_config.get('architectures')
    if not isinstance(architectures, dict) or not architectures:
        raise SystemExit('patch config has no architectures')

    patch_section = docker_config['patch']
    configured_arch = patch_section.get('arch', 'auto')
    if configured_arch != 'auto' and configured_arch not in architectures:
        raise SystemExit(f'unsupported configured Docker arch: {configured_arch}')
    if 'patch_config_file' not in patch_section:
        raise SystemExit('missing docker config value: patch.patch_config_file')
    if 'local_workspace_dir' not in patch_section:
        raise SystemExit('missing docker config value: patch.local_workspace_dir')

    docker_section = docker_config['docker']
    if not docker_section.get('container_name'):
        raise SystemExit('missing docker config value: docker.container_name')
    if not docker_section.get('remote_stage_dir'):
        raise SystemExit('missing docker config value: docker.remote_stage_dir')

    targets = docker_config['targets']
    if not isinstance(targets, list) or not targets:
        raise SystemExit('docker config has no targets')
    required_target_count = 0
    for index, target in enumerate(targets):
        for key in ('remote_path', 'local_backup_name', 'local_patched_name'):
            if not target.get(key):
                raise SystemExit(f'missing docker target[{index}] value: {key}')
        if as_bool(target.get('required', True), True):
            required_target_count += 1

    if required_target_count == 0:
        raise SystemExit('docker config must contain at least one required target')


def safe_config_summary(
    docker_config_path: Path,
    docker_config: dict[str, Any],
    patch_config_path: Path,
    patch_config: dict[str, Any],
) -> dict[str, Any]:
    ssh_cfg = docker_config['ssh']
    return {
        'docker_config': str(docker_config_path),
        'patch_config': str(patch_config_path),
        'patch_version': patch_config.get('version'),
        'patch_architectures': sorted(patch_config.get('architectures', {}).keys()),
        'ssh_ready': bool(cfg_value(ssh_cfg, 'host') and cfg_value(ssh_cfg, 'username')),
        'ssh_host_configured': bool(cfg_value(ssh_cfg, 'host')),
        'ssh_username_configured': bool(cfg_value(ssh_cfg, 'username')),
        'ssh_password_configured': bool(cfg_value(ssh_cfg, 'password')),
        'ssh_key_configured': bool(cfg_value(ssh_cfg, 'key_filename')),
        'container_name': docker_config['docker'].get('container_name'),
        'remote_stage_dir': docker_config['docker'].get('remote_stage_dir'),
        'use_sudo': as_bool(docker_config['docker'].get('use_sudo', True), True),
        'stop_before_patch': as_bool(docker_config['docker'].get('stop_before_patch', True), True),
        'start_after_patch': as_bool(docker_config['docker'].get('start_after_patch', True), True),
        'configured_arch': docker_config['patch'].get('arch', 'auto'),
        'local_workspace_dir': docker_config['patch'].get('local_workspace_dir'),
        'targets': [
            {
                'remote_path': item['remote_path'],
                'role': item.get('role'),
                'required': as_bool(item.get('required', True), True),
                'local_backup_name': item['local_backup_name'],
                'local_patched_name': item['local_patched_name'],
            }
            for item in docker_config.get('targets', [])
        ],
    }


class RemoteHost:
    def __init__(self, config: dict[str, Any]) -> None:
        try:
            import paramiko  # type: ignore
        except ModuleNotFoundError as exc:
            raise SystemExit('paramiko is required for Docker patching; run: pip install -r requirements.txt') from exc

        self.host = require_text(cfg_value(config, 'host'), 'ssh.host')
        self.port = int(cfg_value(config, 'port', 22))
        self.username = require_text(cfg_value(config, 'username'), 'ssh.username')
        self.password = str(cfg_value(config, 'password', '') or '')
        self.sudo_password = str(cfg_value(config, 'sudo_password', '') or self.password)
        self.key_filename = str(cfg_value(config, 'key_filename', '') or '')
        self.timeout = int(cfg_value(config, 'timeout_seconds', 30))

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, Any] = {
            'hostname': self.host,
            'port': self.port,
            'username': self.username,
            'timeout': self.timeout,
        }
        if self.password:
            connect_kwargs['password'] = self.password
        if self.key_filename:
            connect_kwargs['key_filename'] = self.key_filename

        self.client.connect(**connect_kwargs)
        transport = self.client.get_transport()
        if transport is None:
            raise SystemExit('ssh transport not available')
        self.sftp = paramiko.SFTPClient.from_transport(transport)

    def close(self) -> None:
        try:
            self.sftp.close()
        finally:
            self.client.close()

    def run(self, command: str, *, sudo: bool = False, check: bool = True) -> dict[str, Any]:
        actual = command
        if sudo:
            if self.sudo_password:
                actual = (
                    f"printf '%s\\n' {shlex.quote(self.sudo_password)} | "
                    f"sudo -S -p '' sh -lc {shlex.quote(command)}"
                )
            else:
                actual = f"sudo -n sh -lc {shlex.quote(command)}"

        _stdin, stdout, stderr = self.client.exec_command(actual, timeout=self.timeout)
        exit_code = stdout.channel.recv_exit_status()
        result = {
            'command': command,
            'sudo': sudo,
            'exit_code': exit_code,
            'stdout': stdout.read().decode('utf-8', 'replace'),
            'stderr': stderr.read().decode('utf-8', 'replace'),
        }
        if check and exit_code != 0:
            raise SystemExit(json.dumps(result, ensure_ascii=False, indent=2))
        return result

    def get_file(self, remote_path: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        self.sftp.get(remote_path, str(local_path))

    def put_file(self, local_path: Path, remote_path: str) -> None:
        self.sftp.put(str(local_path), remote_path)


def resolve_local_path(base_dir: Path, workspace_dir: str, filename: str) -> Path:
    return (base_dir / workspace_dir / filename).resolve()


def get_arch_config(config: dict[str, Any], arch: str) -> dict[str, Any]:
    arch_cfg = config['architectures'].get(arch)
    if arch_cfg is None:
        raise SystemExit(f'unsupported architecture in patch config: {arch}')
    return arch_cfg


def find_all_offsets(blob: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        offset = blob.find(needle, start)
        if offset == -1:
            return hits
        hits.append(offset)
        start = offset + 1


def find_patch_window(blob: bytes, target: dict[str, Any], original: bytes, patched: bytes) -> tuple[int, str]:
    prefix = parse_hex_bytes(target['prefix_bytes'])
    prefix_hits = find_all_offsets(blob, prefix)
    if len(prefix_hits) == 1:
        return prefix_hits[0], 'original_prefix'
    if len(prefix_hits) > 1:
        raise SystemExit(f"prefix not unique for {target['name']}: {[hex(x) for x in prefix_hits]}")

    relative = int(target['patch_offset_from_prefix'])
    patched_prefix = prefix[:relative] + patched + prefix[relative + len(original):]
    patched_hits = find_all_offsets(blob, patched_prefix)
    if len(patched_hits) == 1:
        return patched_hits[0], 'patched_prefix'
    if len(patched_hits) > 1:
        raise SystemExit(f"patched prefix not unique for {target['name']}: {[hex(x) for x in patched_hits]}")

    raise SystemExit(f"prefix not found in either original or patched form: {target['name']}")


def patch_bytes_relaxed(blob: bytearray, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for target in targets:
        original = parse_hex_bytes(target['orig_bytes'])
        patched = parse_hex_bytes(target['patched_bytes'])
        prefix_offset, prefix_state = find_patch_window(blob, target, original, patched)
        patch_offset = prefix_offset + int(target['patch_offset_from_prefix'])
        actual = bytes(blob[patch_offset:patch_offset + len(original)])

        if actual == original:
            blob[patch_offset:patch_offset + len(patched)] = patched
            state = 'patched'
        elif actual == patched:
            state = 'already_patched'
        else:
            raise SystemExit(
                f"byte mismatch at {target['name']} patch_off=0x{patch_offset:x}: "
                f"expected {target['orig_bytes']} or {target['patched_bytes']}, got {actual.hex(' ')}"
            )

        report.append(
            {
                'name': target['name'],
                'scope': target['scope'],
                'confidence': target['confidence'],
                'state': state,
                'prefix_state': prefix_state,
                'prefix_offset': hex(prefix_offset),
                'patch_offset': hex(patch_offset),
                'orig_bytes': target['orig_bytes'],
                'patched_bytes': target['patched_bytes'],
            }
        )
    return report


def resolve_patch_arch(binary_arch: str | None, configured_arch: str) -> str:
    if binary_arch is None:
        raise SystemExit('unsupported or ambiguous Docker binary architecture')
    if configured_arch == 'auto':
        return binary_arch
    if binary_arch != configured_arch:
        raise SystemExit(f'architecture mismatch for Docker target: expected {configured_arch}, detected {binary_arch}')
    return configured_arch


def patch_local_binary(src: Path, dst: Path, patch_config: dict[str, Any], configured_arch: str) -> dict[str, Any]:
    payload = bytearray(src.read_bytes())
    binary_info = detect_binary_info(payload)
    if binary_info['format'] == 'unknown':
        raise SystemExit(f'unsupported binary format: {src}')

    arch = resolve_patch_arch(binary_info['arch'], configured_arch)
    arch_cfg = get_arch_config(patch_config, arch)
    targets = select_targets(arch_cfg)
    report = patch_bytes_relaxed(payload, targets)

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(payload)

    return {
        'input': str(src),
        'output': str(dst),
        'format': binary_info['format'],
        'arch': arch,
        'input_sha256': sha256_file(src),
        'output_sha256': sha256_file(dst),
        'targets': report,
    }


def docker_command(command: str, use_sudo: bool) -> tuple[str, bool]:
    return command, use_sudo


def inspect_container(remote: RemoteHost, container_name: str, use_sudo: bool) -> dict[str, str]:
    command, sudo = docker_command(
        f"docker inspect {shlex.quote(container_name)} --format '{{{{.State.Status}}}}|{{{{.Config.Image}}}}'",
        use_sudo,
    )
    result = remote.run(command, sudo=sudo)
    status, image = result['stdout'].strip().split('|', 1)
    return {'name': container_name, 'status': status, 'image': image}


def query_modes(remote: RemoteHost, container_name: str, targets: list[dict[str, Any]], use_sudo: bool) -> dict[str, str]:
    modes: dict[str, str] = {}
    for item in targets:
        remote_path = item['remote_path']
        required = as_bool(item.get('required', True), True)
        inner = f"stat -c %a {shlex.quote(remote_path)}"
        command, sudo = docker_command(
            f"docker exec {shlex.quote(container_name)} sh -lc {shlex.quote(inner)}",
            use_sudo,
        )
        result = remote.run(command, sudo=sudo, check=required)
        if result['exit_code'] != 0:
            continue
        modes[remote_path] = result['stdout'].strip() or item.get('remote_mode', '755')
    return modes


def stop_container(remote: RemoteHost, container_name: str, status: str, use_sudo: bool) -> str:
    if status in {'running', 'restarting'}:
        command, sudo = docker_command(f"docker stop {shlex.quote(container_name)}", use_sudo)
        result = remote.run(command, sudo=sudo)
        return result['stdout'].strip() or container_name
    return status


def start_container(remote: RemoteHost, container_name: str, use_sudo: bool) -> str:
    command, sudo = docker_command(f"docker start {shlex.quote(container_name)}", use_sudo)
    result = remote.run(command, sudo=sudo)
    return result['stdout'].strip() or container_name


def docker_cp_from_container(
    remote: RemoteHost,
    container_name: str,
    source_path: str,
    staged_path: str,
    use_sudo: bool,
    required: bool = True,
) -> bool:
    command, sudo = docker_command(
        f"docker cp {shlex.quote(container_name + ':' + source_path)} {shlex.quote(staged_path)}",
        use_sudo,
    )
    result = remote.run(command, sudo=sudo, check=required)
    if result['exit_code'] != 0:
        return False
    remote.run(f"chmod a+r {shlex.quote(staged_path)}", sudo=use_sudo, check=False)
    return True


def docker_cp_to_container(remote: RemoteHost, container_name: str, staged_path: str, target_path: str, use_sudo: bool) -> None:
    command, sudo = docker_command(
        f"docker cp {shlex.quote(staged_path)} {shlex.quote(container_name + ':' + target_path)}",
        use_sudo,
    )
    remote.run(command, sudo=sudo)


def restore_modes(remote: RemoteHost, container_name: str, modes: dict[str, str], use_sudo: bool) -> None:
    for remote_path, mode in modes.items():
        inner = f"chmod {shlex.quote(mode)} {shlex.quote(remote_path)}"
        command, sudo = docker_command(
            f"docker exec {shlex.quote(container_name)} sh -lc {shlex.quote(inner)}",
            use_sudo,
        )
        remote.run(command, sudo=sudo)


def create_remote_stage_dir(remote: RemoteHost, remote_stage_dir: str, use_sudo: bool) -> str:
    cleanup_remote_stage_dir(remote, remote_stage_dir, use_sudo)
    remote.run(f"mkdir -p {shlex.quote(remote_stage_dir)}")
    return remote_stage_dir


def cleanup_remote_stage_dir(remote: RemoteHost, remote_stage_dir: str, use_sudo: bool) -> None:
    remote.run(f"rm -rf {shlex.quote(remote_stage_dir)}", sudo=use_sudo, check=False)


def wait_for_container_status(
    remote: RemoteHost,
    container_name: str,
    expected_status: str,
    use_sudo: bool,
    timeout_seconds: int = 60,
    poll_interval_seconds: float = 1.0,
) -> dict[str, str]:
    deadline = time.monotonic() + timeout_seconds
    last_info: dict[str, str] | None = None
    while time.monotonic() < deadline:
        last_info = inspect_container(remote, container_name, use_sudo)
        if last_info['status'] == expected_status:
            return last_info
        time.sleep(poll_interval_seconds)

    raise SystemExit(f'container did not reach status={expected_status} within {timeout_seconds}s: {last_info}')


def remote_sha256(remote: RemoteHost, container_name: str, paths: list[str], use_sudo: bool) -> list[str]:
    inner = 'sha256sum ' + ' '.join(shlex.quote(path) for path in paths)
    command, sudo = docker_command(
        f"docker exec {shlex.quote(container_name)} sh -lc {shlex.quote(inner)}",
        use_sudo,
    )
    result = remote.run(command, sudo=sudo)
    return result['stdout'].strip().splitlines()


def load_effective_configs(base_dir: Path, docker_config_path: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    docker_config = apply_compat_defaults(load_json(docker_config_path))
    patch_config_path = (base_dir / docker_config['patch']['patch_config_file']).resolve()
    patch_config = load_config(patch_config_path)
    return docker_config, patch_config, patch_config_path


def main() -> int:
    base_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description='Patch Neokikoeru Docker container over SSH')
    parser.add_argument(
        '--config',
        default=str(base_dir / 'patch_config_docker.json'),
        help='Docker patch config path',
    )
    parser.add_argument(
        '--check-config',
        action='store_true',
        help='Parse config and print effective non-secret settings without connecting',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Extract targets and validate local patchability without writing back to the container',
    )
    args = parser.parse_args()

    docker_config_path = Path(args.config).resolve()
    docker_config, patch_config, patch_config_path = load_effective_configs(base_dir, docker_config_path)
    validate_effective_configs(docker_config, patch_config, patch_config_path)

    if args.check_config:
        safe = safe_config_summary(docker_config_path, docker_config, patch_config_path, patch_config)
        print(json.dumps(safe, ensure_ascii=False, indent=2))
        return 0

    docker_cfg = docker_config['docker']
    patch_cfg = docker_config['patch']
    targets = docker_config['targets']
    use_sudo = as_bool(docker_cfg.get('use_sudo', True), True)

    remote = RemoteHost(docker_config['ssh'])
    remote_stage_dir: str | None = None
    try:
        container_name = docker_cfg['container_name']
        remote_stage_dir = create_remote_stage_dir(remote, docker_cfg['remote_stage_dir'], use_sudo)
        local_workspace_dir = patch_cfg['local_workspace_dir']
        configured_arch = patch_cfg.get('arch', 'auto')

        container_info = inspect_container(remote, container_name, use_sudo)
        was_running = container_info['status'] in {'running', 'restarting'}
        if was_running:
            modes = query_modes(remote, container_name, targets, use_sudo)
        else:
            modes = {item['remote_path']: item.get('remote_mode', '755') for item in targets}

        stopped_for_patch = False
        stop_result = 'dry_run_not_stopped' if args.dry_run else container_info['status']
        if not args.dry_run and as_bool(docker_cfg.get('stop_before_patch', True), True):
            stop_result = stop_container(remote, container_name, container_info['status'], use_sudo)
            stopped_for_patch = was_running

        patched_targets: list[dict[str, Any]] = []
        skipped_targets: list[dict[str, Any]] = []
        for item in targets:
            remote_path = item['remote_path']
            role = str(item.get('role') or 'unspecified')
            required = as_bool(item.get('required', True), True)
            backup_name = item['local_backup_name']
            patched_name = item['local_patched_name']

            local_backup_path = resolve_local_path(base_dir, local_workspace_dir, backup_name)
            local_patched_path = resolve_local_path(base_dir, local_workspace_dir, patched_name)
            remote_backup_path = f'{remote_stage_dir}/{backup_name}'
            remote_patched_path = f'{remote_stage_dir}/{patched_name}'
            mode = modes.get(remote_path, item.get('remote_mode', '755'))

            copied = docker_cp_from_container(
                remote,
                container_name,
                remote_path,
                remote_backup_path,
                use_sudo,
                required=required,
            )
            if not copied:
                skipped_targets.append(
                    {
                        'remote_path': remote_path,
                        'role': role,
                        'required': required,
                        'reason': 'not_found_or_copy_failed',
                    }
                )
                continue

            remote.get_file(remote_backup_path, local_backup_path)
            try:
                patch_report = patch_local_binary(local_backup_path, local_patched_path, patch_config, configured_arch)
            except SystemExit as exc:
                if required:
                    raise
                skipped_targets.append(
                    {
                        'remote_path': remote_path,
                        'role': role,
                        'required': required,
                        'local_backup_path': str(local_backup_path),
                        'reason': str(exc),
                    }
                )
                continue

            if not args.dry_run:
                remote.put_file(local_patched_path, remote_patched_path)
                remote.run(f"chmod {shlex.quote(mode)} {shlex.quote(remote_patched_path)}")
                docker_cp_to_container(remote, container_name, remote_patched_path, remote_path, use_sudo)

            patched_targets.append(
                {
                    'remote_path': remote_path,
                    'role': role,
                    'required': required,
                    'local_backup_path': str(local_backup_path),
                    'local_patched_path': str(local_patched_path),
                    'remote_backup_path': remote_backup_path,
                    'remote_patched_path': None if args.dry_run else remote_patched_path,
                    'mode': mode,
                    'dry_run': args.dry_run,
                    'patch_report': patch_report,
                }
            )

        if not patched_targets:
            raise SystemExit('no Docker targets were patchable')

        should_start = (not args.dry_run) and as_bool(docker_cfg.get('start_after_patch', True), True) and (
            stopped_for_patch or ((not was_running) and as_bool(docker_cfg.get('start_if_previously_stopped', False), False))
        )
        start_result = 'dry_run_not_started' if args.dry_run else 'not_started'
        if should_start:
            start_result = start_container(remote, container_name, use_sudo)
            wait_for_container_status(
                remote,
                container_name,
                'running',
                use_sudo,
                timeout_seconds=int(docker_cfg.get('start_timeout_seconds', 60)),
            )
            restore_modes(remote, container_name, {item['remote_path']: item['mode'] for item in patched_targets}, use_sudo)

        final_info = inspect_container(remote, container_name, use_sudo)
        sha_lines = []
        if (not args.dry_run) and final_info['status'] == 'running':
            sha_lines = remote_sha256(remote, container_name, [item['remote_path'] for item in patched_targets], use_sudo)

        cleanup_remote_stage_dir(remote, remote_stage_dir, use_sudo)
        remote_stage_dir = None

        result = {
            'dry_run': args.dry_run,
            'patch_config': str(patch_config_path),
            'container_before': container_info,
            'stop_result': stop_result,
            'start_result': start_result,
            'container_after': final_info,
            'configured_arch': configured_arch,
            'targets': patched_targets,
            'skipped_targets': skipped_targets,
            'remote_sha256': sha_lines,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    finally:
        if remote_stage_dir is not None:
            cleanup_remote_stage_dir(remote, remote_stage_dir, use_sudo)
        remote.close()


if __name__ == '__main__':
    raise SystemExit(main())