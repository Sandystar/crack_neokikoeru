from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def parse_hex_bytes(text: str) -> bytes:
    return bytes.fromhex(text)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def detect_binary_info(blob: bytes) -> dict:
    if blob.startswith(b'MZ'):
        if len(blob) < 0x40:
            return {'format': 'pe', 'arch': None}
        peoff = int.from_bytes(blob[0x3C:0x40], 'little')
        machine = int.from_bytes(blob[peoff + 4:peoff + 6], 'little') if len(blob) >= peoff + 6 else None
        machine_map = {0x8664: 'amd64', 0xAA64: 'arm64'}
        return {'format': 'pe', 'arch': machine_map.get(machine)}
    if blob.startswith(b'\x7fELF'):
        machine = int.from_bytes(blob[18:20], 'little') if len(blob) >= 20 else None
        machine_map = {0x3E: 'amd64', 0xB7: 'arm64'}
        return {'format': 'elf', 'arch': machine_map.get(machine)}

    magic_be = int.from_bytes(blob[:4], 'big') if len(blob) >= 4 else None
    magic_le = int.from_bytes(blob[:4], 'little') if len(blob) >= 4 else None
    if magic_be == 0xFEEDFACF:
        cputype = int.from_bytes(blob[4:8], 'big', signed=True) if len(blob) >= 8 else None
        return {'format': 'macho', 'arch': 'amd64' if cputype == 0x01000007 else 'arm64' if cputype == 0x0100000C else None}
    if magic_le == 0xFEEDFACF:
        cputype = int.from_bytes(blob[4:8], 'little', signed=True) if len(blob) >= 8 else None
        return {'format': 'macho', 'arch': 'amd64' if cputype == 0x01000007 else 'arm64' if cputype == 0x0100000C else None}
    if magic_be in (0xCAFEBABE, 0xCAFED00D):
        return {'format': 'macho-fat', 'arch': None}
    return {'format': 'unknown', 'arch': None}


def infer_platform_from_format(binary_format: str) -> str | None:
    return {
        'pe': 'windows',
        'elf': 'linux',
        'macho': 'macos',
    }.get(binary_format)


def get_arch_config(config: dict, arch: str) -> dict:
    arch_cfg = config['architectures'].get(arch)
    if arch_cfg is None:
        raise SystemExit(f'unsupported architecture: {arch}')
    return arch_cfg


def select_targets(arch_cfg: dict) -> list[dict]:
    targets = arch_cfg.get('targets')
    if not isinstance(targets, list) or not targets:
        raise SystemExit('no patch targets configured for selected architecture')
    return targets


def find_unique_prefix(blob: bytes, prefix: bytes) -> int:
    first = blob.find(prefix)
    if first == -1:
        raise SystemExit(f'prefix not found: {prefix.hex(" ")}')
    second = blob.find(prefix, first + 1)
    if second != -1:
        raise SystemExit(f'prefix not unique: first=0x{first:x}, second=0x{second:x}')
    return first


def default_output_path(src: Path) -> Path:
    if src.suffix:
        return src.with_name(f'{src.stem}.cracked{src.suffix}')
    return src.with_name(f'{src.name}.cracked')


def patch_bytes(blob: bytearray, targets: list[dict]) -> list[dict]:
    report: list[dict] = []
    for target in targets:
        prefix = parse_hex_bytes(target['prefix_bytes'])
        prefix_offset = find_unique_prefix(blob, prefix)
        patch_offset = prefix_offset + int(target['patch_offset_from_prefix'])
        original = parse_hex_bytes(target['orig_bytes'])
        patched = parse_hex_bytes(target['patched_bytes'])
        actual = bytes(blob[patch_offset:patch_offset + len(original)])
        if actual != original:
            raise SystemExit(
                f"byte mismatch at {target['name']} patch_off=0x{patch_offset:x}: "
                f"expected {target['orig_bytes']}, got {actual.hex(' ')}"
            )
        blob[patch_offset:patch_offset + len(patched)] = patched
        report.append(
            {
                'name': target['name'],
                'scope': target['scope'],
                'confidence': target['confidence'],
                'prefix_offset': hex(prefix_offset),
                'patch_offset': hex(patch_offset),
                'orig_bytes': target['orig_bytes'],
                'patched_bytes': target['patched_bytes'],
            }
        )
    return report


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    config = load_config(base_dir / 'patch_config.json')

    parser = argparse.ArgumentParser(description='Patch Neokikoeru binaries')
    parser.add_argument('--input', required=True, help='Binary file to patch')
    parser.add_argument(
        '--arch',
        required=False,
        choices=sorted(config['architectures'].keys()),
        help='Optional architecture override for safety check',
    )
    parser.add_argument('--output', required=False, default=None, help='Patched output path')
    parser.add_argument('--force', action='store_true', help='Overwrite output if it exists')
    args = parser.parse_args()

    src = Path(args.input)
    if not src.exists():
        raise SystemExit(f'input file not found: {src}')

    binary_sha256 = sha256_file(src)
    payload = bytearray(src.read_bytes())
    binary_info = detect_binary_info(payload)
    if binary_info['format'] == 'unknown':
        raise SystemExit(f'unsupported binary format: {src}')
    if binary_info['arch'] is None:
        raise SystemExit(
            f"unsupported or ambiguous architecture for {binary_info['format']}: {src}"
        )
    if args.arch is not None and binary_info['arch'] != args.arch:
        raise SystemExit(
            f"architecture mismatch: expected {args.arch}, detected {binary_info['arch']}"
        )

    arch = args.arch or binary_info['arch']
    arch_cfg = get_arch_config(config, arch)
    out = Path(args.output) if args.output else default_output_path(src)
    if out.exists() and not args.force:
        raise SystemExit(f'output already exists: {out} (use --force to overwrite)')

    targets = select_targets(arch_cfg)
    report = patch_bytes(payload, targets)
    out.write_bytes(payload)

    result = {
        'version': config['version'],
        'platform': infer_platform_from_format(binary_info['format']),
        'format': binary_info['format'],
        'arch': arch,
        'input': str(src),
        'output': str(out),
        'input_sha256': binary_sha256,
        'targets': report,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())