#!/usr/bin/env python3
"""Native root, private random credentials and real PTYs; never echo captured output."""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import secrets
import shutil
import select
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'lib/safety.py'
MENU = b'1. Install\n2. Update\n3. Check\n4. Repair\n5. Show current WEB link\n6. Uninstall Telemt\n7. Exit\n'
COUNT = 0


def require(ok, reason):
    if not ok:
        raise AssertionError(reason)  # Never pass secrets/captured output as reason.


def passed(reason):
    global COUNT
    COUNT += 1
    print('ok - '+reason, flush=True)


def terminal(command, answer=b'', env=None, input_tty=True, output_tty=True):
    master, slave = pty.openpty()
    child = subprocess.Popen(command, stdin=slave if input_tty else subprocess.PIPE,
                             stdout=slave if output_tty else subprocess.PIPE,
                             stderr=slave if output_tty else subprocess.STDOUT,
                             cwd=ROOT, env=env, start_new_session=True)
    os.close(slave)
    captured = bytearray()
    try:
        if input_tty:
            os.write(master, answer)
        else:
            child.stdin.close()
            child.stdin = None
        deadline = time.monotonic()+30
        if not output_tty:
            captured.extend(child.communicate(timeout=30)[0])
        else:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], .1)
                if ready:
                    try:
                        block = os.read(master, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not block:
                        break
                    captured.extend(block)
                elif child.poll() is not None:
                    break
            require(time.monotonic() < deadline, 'PTY process timeout')
        result = child.wait(timeout=5)
        return result, bytes(captured).replace(b'\r\n', b'\n')
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        os.close(master)


def snapshot(root):
    values = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        values[str(path.relative_to(root))] = (info.st_uid, info.st_gid, info.st_mode,
                                             hashlib.sha256(path.read_bytes()).hexdigest()
                                             if path.is_file() and not path.is_symlink() else None)
    return values


def main():
    require(os.geteuid() == 0, 'native root required')
    with tempfile.TemporaryDirectory(prefix='twm-link-') as directory:
        root = Path(directory)
        state = root/'state'; state.mkdir(mode=0o700)
        config = root/'telemt.toml'
        link = state/'web-link.txt'; manifest = state/'manifest.json'
        token = secrets.token_hex(16)
        expected = f'tg://webproxy?server=proxy.example.com&secret=dd{token}'.encode()
        original = {
            manifest: json.dumps(dict(schema=1, domain='proxy.example.com', public_ip='203.0.113.10',
                                      unit_sha256='a'*64, nginx_sha256='b'*64, acme_webroot=None)).encode(),
            link: expected+b'\n',
            config: (f'[access.users]\nweb-user = "{token}"\n[web]\nenabled = true\n'
                     '[[web.vhosts]]\nhost = "proxy.example.com"\n[[web.vhosts.profiles]]\n'
                     'user = "web-user"\nsecret_mode = "dd"\n').encode(),
        }
        def reset():
            for path, value in original.items():
                if path.is_symlink() or path.exists(): path.unlink()
                path.write_bytes(value); path.chmod(0o640 if path == config else 0o600)
            state.chmod(0o700)
        reset()
        for name in ('unit', 'nginx', 'certificate', 'renewal'):
            (root/name).write_text('unchanged fixture '+name)
        (root/'backups').mkdir()
        (state/'certificate.json').write_text('independent preserved ownership fixture')
        lock = root/'lock'; lock.touch(mode=0o600)
        code = '''source ./telemt-web-manager.sh
STATE=$1 CONFIG=$2 LOCK=$3
systemctl() { exit 91; }
nginx() { exit 92; }
backup_begin() { exit 93; }
main
'''
        command = ['bash', '-c', code, 'fixture', str(state), str(config), str(lock)]
        env = dict(os.environ, TERM='xterm', PYTHONDONTWRITEBYTECODE='1')
        env.pop('NO_COLOR', None)
        # Actual Show operation with only its three tools plus startup dirname/bash.
        # No conntrack, Nginx, Certbot, systemd tooling or runtime health is available.
        tools = root/'minimal-tools'; tools.mkdir()
        for name in ('bash', 'dirname', 'python3', 'flock', 'stat'):
            target = shutil.which(name)
            require(target is not None, 'missing fixture tool: '+name)
            (tools/name).symlink_to(target)
        result, output = terminal(command, b'5\n', dict(env, PATH=str(tools)))
        require(result == 0 and expected in output, 'Show link gained unrelated dependencies')
        passed('actual Show link succeeds with conntrack/Nginx/Certbot/systemd tools absent')

        # Native root runner: invoke the real platform guards with controlled facts.
        # The apt function cannot mutate packages even if a guard regresses.
        for reason, facts in [
            ('Supported OS: Ubuntu', 'source() { ID=debian; VERSION_ID=12; }'),
            ('Unsupported architecture', 'source() { ID=ubuntu; VERSION_ID=24.04; }; uname() { printf riscv64; }'),
            ('active init system', 'read() { init=fixture-init; }'),
        ]:
            script = ('source "$1"; '+facts+'; MENU_ACTION=1; '
                      'apt-get() { printf UNEXPECTED_APT; return 98; }; preflight --install')
            process = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT/'telemt-web-manager.sh')],
                                     cwd=ROOT, capture_output=True, timeout=5)
            captured = process.stdout+process.stderr
            require(process.returncode != 0 and reason.encode() in captured
                    and b'UNEXPECTED_APT' not in captured, 'immutable platform guard: '+reason)
            passed('real platform guard before apt: '+reason)
        before = snapshot(root)
        for name, extra, colored in [('color', {}, True), ('NO_COLOR', {'NO_COLOR':'1'}, False),
                                     ('TERM=dumb', {'TERM':'dumb'}, False)]:
            result, output = terminal(command, b'5\n', dict(env, **extra))
            require(result == 0 and MENU in output, 'exact seven-entry menu')
            require(expected in output and output.count(expected) == 1, 'exact current TOML/domain link display')
            require((b'\x1b[' in output) == colored, 'terminal color policy')
            require(b'WARNING: This link contains a bearer secret.' in output, 'bearer warning')
            require(snapshot(root) == before, 'show operation mutated managed files')
            passed('read-only exact menu/link '+name+'; no service, Nginx or backup operation')
        result = subprocess.run(['python3', str(HELPER), 'web-link-validate', str(state), str(config)],
                                capture_output=True, timeout=5)
        require(result.returncode == 0 and not result.stdout and not result.stderr, 'silent validation')
        passed('validation-only helper emits no secret or diagnostics on success')
        for input_tty, output_tty in [(True,False),(False,True),(False,False)]:
            result, output = terminal(command, b'5\n', env, input_tty, output_tty)
            require(result != 0 and expected not in output and token.encode() not in output
                    and b'\x1b' not in output, 'noninteractive secret/color disclosure')
        for action in ('web-link-display',):
            result = subprocess.run(['python3', str(HELPER), action, str(state), str(config)],
                                    capture_output=True, timeout=5)
            require(result.returncode != 0 and token.encode() not in result.stdout+result.stderr
                    and b'\x1b' not in result.stdout+result.stderr, 'non-TTY helper disclosure')
        result = subprocess.run(['bash', str(ROOT/'telemt-web-manager.sh'), '--show-link'], capture_output=True)
        require(result.returncode != 0 and token.encode() not in result.stdout+result.stderr, 'unrequested public CLI')
        passed('stdin/stdout TTY gates, redirected output and absent --show-link CLI')

        def invalid(name, change):
            reset(); change()
            result = subprocess.run(['python3', str(HELPER), 'web-link-validate', str(state), str(config)],
                                    capture_output=True, timeout=5)
            require(result.returncode != 0 and not result.stdout
                    and result.stderr == b'Safety validation failed; manual review required (no credentials displayed).\n',
                    'unsafe file validation: '+name)
            result, output = terminal(command, b'5\n', env)
            require(result != 0 and b'tg://' not in output and token.encode() not in output,
                    'failure secret disclosure: '+name)
            require(b'No valid manager-owned WEB link is available.' in output, 'failure UX: '+name)
            passed('refusal without secret: '+name)

        invalid('missing link', lambda: link.unlink())
        invalid('missing manifest', lambda: manifest.unlink())
        invalid('link symlink', lambda: (link.unlink(), link.symlink_to(config)))
        invalid('manifest symlink', lambda: (manifest.unlink(), manifest.symlink_to(config)))
        invalid('config symlink', lambda: (config.unlink(), config.symlink_to(root/'unit')))
        invalid('wrong link mode', lambda: link.chmod(0o640))
        invalid('wrong manifest mode', lambda: manifest.chmod(0o644))
        invalid('wrong config mode', lambda: config.chmod(0o644))
        invalid('wrong link owner', lambda: os.chown(link,65534,65534))
        invalid('wrong manifest owner', lambda: os.chown(manifest,65534,65534))
        invalid('wrong config owner', lambda: os.chown(config,65534,65534))
        invalid('unsafe state mode', lambda: state.chmod(0o755))
        invalid('multiline', lambda: link.write_bytes(original[link]+b'\n'))
        invalid('malformed URL', lambda: link.write_bytes(b'https://example.com\n'))
        invalid('domain mismatch', lambda: link.write_bytes(original[link].replace(b'proxy.example.com',b'foreign.example.com')))
        invalid('secret mismatch', lambda: link.write_bytes(original[link].replace(token.encode(),secrets.token_hex(16).encode())))
        invalid('TOML secret mismatch', lambda: config.write_bytes(original[config].replace(token.encode(),secrets.token_hex(16).encode())))
        invalid('malformed manifest', lambda: manifest.write_bytes(b'{'))
        invalid('unsupported manifest', lambda: manifest.write_bytes(original[manifest].replace(b'"schema": 1',b'"schema": 2')))
        invalid('FIFO', lambda: (link.unlink(), os.mkfifo(link,0o600)))
        reset()
        alias = root/'alias'
        invalid('hardlink', lambda: os.link(link,alias))
        alias.unlink(); reset()
        old_state = root/'old-state'; state.rename(old_state); state.symlink_to(old_state)
        try:
            result = subprocess.run(['python3', str(HELPER), 'web-link-validate', str(state), str(config)],capture_output=True)
            require(result.returncode != 0 and token.encode() not in result.stdout+result.stderr, 'state symlink refusal')
        finally:
            state.unlink(); old_state.rename(state)
        passed('state symlink refused')
        root.chmod(0o777)
        try:
            result = subprocess.run(['python3', str(HELPER), 'web-link-validate', str(state), str(config)],capture_output=True)
            require(result.returncode != 0 and token.encode() not in result.stdout+result.stderr, 'unsafe ancestor refusal')
        finally: root.chmod(0o700)
        passed('unsafe ancestor refused')
        with lock.open('r+') as held:
            fcntl.flock(held, fcntl.LOCK_SH)
            result, output = terminal(command,b'5\n',env)
            require(result == 0 and expected in output, 'concurrent shared read blocked')
            fcntl.flock(held, fcntl.LOCK_EX)
            result, output = terminal(command,b'5\n',env)
            require(result != 0 and token.encode() not in output, 'exclusive mutation not respected')
        passed('shared lock coexists with reader and refuses concurrent exclusive mutation')

        # Actual menu provenance flag, without invoking unrelated production setup.
        route = '''source ./telemt-web-manager.sh
preflight() { :; }
take_lock() { :; }
install_manager() { [[ $INTERACTIVE_INSTALL == "$1" ]]; }
'''
        # The mock accepts no arguments from main, so the desired flag is literal in its body.
        for argument, expected_flag, answer in [('', '1', b'1\n'), ('--install','0',b'')]:
            script = route.replace('"$1"', expected_flag)+'main '+argument
            result, _ = terminal(['bash','-c',script],answer,env)
            require(result == 0, 'menu versus CLI Install provenance flag')
        passed('only actual menu selection sets interactive Install provenance')
        fresh = ['bash', str(ROOT/'tests/fresh.sh')]
        fresh_env = dict(env,FIXTURE_LINK_UX='1')
        result, output = terminal(fresh, env=fresh_env)
        require(result == 0 and output.count(b'tg://webproxy?server=') == 1
                and output.index(b'FIXTURE_COMMITTED') < output.index(b'tg://webproxy?server='),
                'interactive fresh committed display')
        passed('actual fresh transaction displays validated link only after ARMED=0, manifest and health commit')
        result, output = terminal(fresh,env=dict(fresh_env,FIXTURE_INCOMPATIBLE='1'))
        require(result != 0 and b'tg://' not in output and b'FIXTURE_COMMITTED' not in output,
                'rejected interactive Install disclosed link')
        passed('interactive candidate failure/rollback does not present link')
        for settings, output_tty in [({'FIXTURE_MENU_INSTALL':'0'},True), ({},False)]:
            result, output = terminal(fresh,env=dict(fresh_env,**settings),output_tty=output_tty)
            require(result == 0 and b'tg://' not in output and b'\x1b' not in output
                    and b'Private WEB link:' in output and b'FIXTURE_COMMITTED' not in output,
                    'CLI/redirected fresh Install disclosed link')
        passed('CLI Install even on PTY and redirected menu Install show saved path only')
    print(f'WEB link regression: {COUNT} checks passed; captured credentials never printed.')


if __name__ == '__main__':
    main()
