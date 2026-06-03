from __future__ import annotations

import argparse
import json
import shlex
import time
from pathlib import Path

import paramiko

from crack import (
    detect_binary_info,
    load_config,
    parse_hex_bytes,
    select_targets,
    sha256_file,
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


class RemoteHost:
    def __init__(self, host: str, port: int, username: str, password: str, sudo_password: str | None, timeout: int) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.timeout = timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, port=port, username=username, password=password, timeout=timeout)
        transport = self.client.get_transport()
        if transport is None:
            raise SystemExit('ssh transport not available')
        self.sftp = paramiko.SFTPClient.from_transport(transport)

    def close(self) -> None:
        try:
            self.sftp.close()
        finally:
            self.client.close()

    def run(self, command: str, *, sudo: bool = False, check: bool = True) -> dict:
        actual = command
        if sudo:
            actual = (
                f"printf '%s\\n' {shlex.quote(self.sudo_password)} | "
                f"sudo -S -p '' sh -lc {shlex.quote(command)}"
            )
        stdin, stdout, stderr = self.client.exec_command(actual, timeout=self.timeout)
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


def get_arch_config(config: dict, arch: str) -> dict:
    arch_cfg = config['architectures'].get(arch)
    if arch_cfg is None:
        raise SystemExit(f'unsupported architecture in docker config: {arch}')
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


def find_patch_window(blob: bytes, target: dict, original: bytes, patched: bytes) -> tuple[int, str]:
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


def patch_bytes_relaxed(blob: bytearray, targets: list[dict]) -> list[dict]:
    report: list[dict] = []
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


def patch_local_binary(src: Path, dst: Path, patch_config: dict, arch: str) -> dict:
    payload = bytearray(src.read_bytes())
    binary_info = detect_binary_info(payload)
    if binary_info['format'] == 'unknown':
        raise SystemExit(f'unsupported binary format: {src}')
    if binary_info['arch'] != arch:
        raise SystemExit(
            f"architecture mismatch for docker target: expected {arch}, detected {binary_info['arch']}"
        )

    arch_cfg = get_arch_config(patch_config, arch)
    targets = select_targets(arch_cfg)
    report = patch_bytes_relaxed(payload, targets)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(payload)

    binary_sha256 = sha256_file(src)
    return {
        'input': str(src),
        'output': str(dst),
        'format': binary_info['format'],
        'arch': arch,
        'input_sha256': binary_sha256,
        'targets': report,
    }


def inspect_container(remote: RemoteHost, container_name: str) -> dict:
    result = remote.run(
        f"docker inspect {shlex.quote(container_name)} --format '{{{{.State.Status}}}}|{{{{.Config.Image}}}}'",
        sudo=True,
    )
    status, image = result['stdout'].strip().split('|', 1)
    return {'name': container_name, 'status': status, 'image': image}


def query_modes(remote: RemoteHost, container_name: str, targets: list[dict]) -> dict[str, str]:
    modes: dict[str, str] = {}
    for item in targets:
        remote_path = item['remote_path']
        result = remote.run(
            f"docker exec {shlex.quote(container_name)} sh -lc {shlex.quote(f'stat -c %a {shlex.quote(remote_path)}')}",
            sudo=True,
        )
        modes[remote_path] = result['stdout'].strip() or item.get('remote_mode', '755')
    return modes


def stop_container(remote: RemoteHost, container_name: str, status: str) -> str:
    if status in {'running', 'restarting'}:
        result = remote.run(f"docker stop {shlex.quote(container_name)}", sudo=True)
        return result['stdout'].strip() or container_name
    return status


def start_container(remote: RemoteHost, container_name: str) -> str:
    result = remote.run(f"docker start {shlex.quote(container_name)}", sudo=True)
    return result['stdout'].strip() or container_name


def docker_cp_from_container(remote: RemoteHost, container_name: str, source_path: str, staged_path: str) -> None:
    remote.run(
        f"docker cp {shlex.quote(container_name + ':' + source_path)} {shlex.quote(staged_path)}",
        sudo=True,
    )


def docker_cp_to_container(remote: RemoteHost, container_name: str, staged_path: str, target_path: str) -> None:
    remote.run(
        f"docker cp {shlex.quote(staged_path)} {shlex.quote(container_name + ':' + target_path)}",
        sudo=True,
    )


def restore_modes(remote: RemoteHost, container_name: str, modes: dict[str, str]) -> None:
    for remote_path, mode in modes.items():
        remote.run(
            f"docker exec {shlex.quote(container_name)} chmod {shlex.quote(mode)} {shlex.quote(remote_path)}",
            sudo=True,
        )


def create_remote_stage_dir(remote: RemoteHost, remote_stage_dir: str) -> str:
    cleanup_remote_stage_dir(remote, remote_stage_dir)
    remote.run(f"mkdir -p {shlex.quote(remote_stage_dir)}")
    return remote_stage_dir


def cleanup_remote_stage_dir(remote: RemoteHost, remote_stage_dir: str) -> None:
    remote.run(f"rm -rf {shlex.quote(remote_stage_dir)}", sudo=True, check=False)


def wait_for_container_status(
    remote: RemoteHost,
    container_name: str,
    expected_status: str,
    timeout_seconds: int = 60,
    poll_interval_seconds: float = 1.0,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last_info: dict | None = None
    while time.monotonic() < deadline:
        last_info = inspect_container(remote, container_name)
        if last_info['status'] == expected_status:
            return last_info
        time.sleep(poll_interval_seconds)

    raise SystemExit(
        f"container did not reach status={expected_status} within {timeout_seconds}s: {last_info}"
    )


def main() -> int:
    base_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description='Patch Neokikoeru Docker container over SSH')
    parser.add_argument(
        '--config',
        default=str(base_dir / 'patch_config_docker.json'),
        help='Docker patch config path',
    )
    args = parser.parse_args()

    docker_config_path = Path(args.config).resolve()
    docker_config = load_json(docker_config_path)
    patch_config_path = (base_dir / docker_config['patch']['patch_config_file']).resolve()
    patch_config = load_config(patch_config_path)

    ssh_cfg = docker_config['ssh']
    docker_cfg = docker_config['docker']
    patch_cfg = docker_config['patch']
    targets = docker_config['targets']

    remote = RemoteHost(
        host=ssh_cfg['host'],
        port=int(ssh_cfg.get('port', 22)),
        username=ssh_cfg['username'],
        password=ssh_cfg['password'],
        sudo_password=ssh_cfg.get('sudo_password'),
        timeout=int(ssh_cfg.get('timeout_seconds', 30)),
    )
    remote_stage_dir: str | None = None
    try:
        container_name = docker_cfg['container_name']
        remote_stage_dir = docker_cfg['remote_stage_dir']
        remote_stage_dir = create_remote_stage_dir(remote, remote_stage_dir)
        local_workspace_dir = patch_cfg['local_workspace_dir']
        arch = patch_cfg['arch']

        container_info = inspect_container(remote, container_name)
        if container_info['status'] == 'running':
            modes = query_modes(remote, container_name, targets)
        else:
            modes = {
                item['remote_path']: item.get('remote_mode', '755')
                for item in targets
            }
        stop_result = stop_container(remote, container_name, container_info['status'])

        patched_targets: list[dict] = []
        for item in targets:
            remote_path = item['remote_path']
            backup_name = item['local_backup_name']
            patched_name = item['local_patched_name']

            local_backup_path = resolve_local_path(base_dir, local_workspace_dir, backup_name)
            local_patched_path = resolve_local_path(base_dir, local_workspace_dir, patched_name)
            remote_backup_path = f"{remote_stage_dir}/{backup_name}"
            remote_patched_path = f"{remote_stage_dir}/{patched_name}"

            docker_cp_from_container(remote, container_name, remote_path, remote_backup_path)
            remote.get_file(remote_backup_path, local_backup_path)
            patch_report = patch_local_binary(local_backup_path, local_patched_path, patch_config, arch)
            remote.put_file(local_patched_path, remote_patched_path)
            remote.run(
                f"chmod {shlex.quote(modes.get(remote_path, item.get('remote_mode', '755')))} {shlex.quote(remote_patched_path)}"
            )
            docker_cp_to_container(remote, container_name, remote_patched_path, remote_path)

            patched_targets.append(
                {
                    'remote_path': remote_path,
                    'local_backup_path': str(local_backup_path),
                    'local_patched_path': str(local_patched_path),
                    'remote_backup_path': remote_backup_path,
                    'remote_patched_path': remote_patched_path,
                    'mode': modes.get(remote_path, item.get('remote_mode', '755')),
                    'patch_report': patch_report,
                }
            )

        start_result = start_container(remote, container_name)
        final_info = wait_for_container_status(remote, container_name, 'running', timeout_seconds=60)
        restore_modes(remote, container_name, {item['remote_path']: item['mode'] for item in patched_targets})
        final_info = inspect_container(remote, container_name)
        sha_result = remote.run(
            'docker exec ' + shlex.quote(container_name) + ' sh -lc ' + shlex.quote(
                'sha256sum ' + ' '.join(shlex.quote(item['remote_path']) for item in patched_targets)
            ),
            sudo=True,
        )
        cleanup_remote_stage_dir(remote, remote_stage_dir)
        remote_stage_dir = None

        result = {
            'container_before': container_info,
            'stop_result': stop_result,
            'start_result': start_result,
            'container_after': final_info,
            'arch': arch,
            'targets': patched_targets,
            'remote_sha256': sha_result['stdout'].strip().splitlines(),
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    finally:
        if remote_stage_dir is not None:
            cleanup_remote_stage_dir(remote, remote_stage_dir)
        remote.close()


if __name__ == '__main__':
    raise SystemExit(main())