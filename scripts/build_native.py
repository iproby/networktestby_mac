"""Build a terminal executable with its own Python runtime on the target OS."""
import argparse
import hashlib
import platform
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--identity', help='macOS Developer ID signing identity, already in the keychain')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    machine = platform.machine().lower()
    arch = 'arm64' if machine in ('aarch64', 'arm64') else 'x86_64' if machine in ('amd64', 'x86_64') else machine
    name = f'netwatch-{platform.system()}-{arch}'
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--console', '--specpath', str(root / 'build'),
               '--name', name, '--paths', str(root), '--collect-all', 'textual', '--collect-all', 'rich',
               '--collect-all', 'dns', '--collect-all', 'certifi', '--copy-metadata', 'networktestby-netwatch']
    if platform.system() == 'Darwin':
        command += ['--hidden-import', 'CoreWLAN', '--collect-submodules', 'CoreWLAN']
        if args.identity:
            command += ['--codesign-identity', args.identity]
    subprocess.run(command + [str(root / 'scripts' / 'frozen_entry.py')], cwd=root, check=True)
    binary = root / 'dist' / (name + ('.exe' if sys.platform == 'win32' else ''))
    subprocess.run([str(binary), '--version'], check=True, cwd=root)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (root / 'dist' / (binary.name + '.sha256')).write_text(f'{digest}  {binary.name}\n', encoding='ascii')
    print(binary)


if __name__ == '__main__':
    main()
