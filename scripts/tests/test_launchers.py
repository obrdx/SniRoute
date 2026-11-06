"""Offline deployment checks: python3 -m unittest discover -s scripts/tests -v."""
import json
import os
from pathlib import Path
import signal
import pty
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
FAKE = r'''#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
if args == ['version']:
    print('test'); sys.exit(0)
if args == ['genkey']:
    print('a' * 64); sys.exit(0)
state = Path(os.environ['FAKE_STATE'])
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps(args) + '\n')
if args[:2] == ['server', 'status']:
    print('running (pid 1)' if state.exists() else 'stopped'); sys.exit(0)
if args[:2] == ['server', 'start']:
    state.touch(); sys.exit(0)
if args[:2] == ['server', 'stop']:
    state.unlink(missing_ok=True); sys.exit(0)
if os.environ.get('FAKE_WAIT') == '1':
    def finish(signum, frame):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        time.sleep(.4)
        Path('partial-report.md').write_text('partial evidence')
        sys.exit(0)
    signal.signal(signal.SIGINT, finish)
    Path(os.environ['FAKE_READY']).write_text(str(os.getpid()))
    while True: time.sleep(.05)
if args[:2] == ['client', 'menu']:
    Path('input.txt').write_text(sys.stdin.readline())
sys.exit(int(os.environ.get('FAKE_EXIT', '0')))
'''


class Launchers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sniroute-scripts-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.binary = self.base / 'fake'
        self.binary.write_text(FAKE)
        self.binary.chmod(0o700)
        self.tmp = self.base / 'tmp'
        self.tmp.mkdir()
        self.log = self.base / 'calls'
        self.env = dict(os.environ, SR_BIN=str(self.binary), TMPDIR=str(self.tmp),
                        SR_STATE_DIR=str(self.base / 'state'), SR_NO_SYSTEMD='1',
                        SR_ALLOW_UNPRIVILEGED='1', SR_PREFIX=str(self.base / 'prefix'),
                        SR_ETC=str(self.base / 'etc'), SR_DATA=str(self.base / 'data'),
                        SR_UNIT_DIR=str(self.base / 'units'), FAKE_LOG=str(self.log),
                        FAKE_STATE=str(self.base / 'running'),
                        FAKE_READY=str(self.base / 'ready'))

    def command(self, role, *args):
        return ['sh', str(ROOT / 'scripts' / f'sniroute-{role}.sh'), *args]

    def run_script(self, role, *args, stdin=''):
        return subprocess.run(self.command(role, *args), env=self.env, cwd=self.base,
                              input=stdin, text=True, errors="replace", capture_output=True, timeout=15,
                              start_new_session=True)

    def calls(self):
        return [json.loads(s) for s in self.log.read_text().splitlines()]

    def assert_clean(self):
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_download_urls_for_each_platform_and_custom_source(self):
        tools = self.base / 'download-tools'
        tools.mkdir()
        curl = tools / 'curl'
        curl.write_text('''#!/usr/bin/env python3
import os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
Path(os.environ['DOWNLOAD_LOG']).write_text(args[-1])
shutil.copyfile(os.environ['DOWNLOAD_SOURCE'], args[args.index('-o') + 1])
''')
        curl.chmod(0o700)
        uname = tools / 'uname'
        uname.write_text('''#!/bin/sh
case "$1" in
  -s) printf '%s\\n' "$TEST_OS" ;;
  -m) printf '%s\\n' "$TEST_ARCH" ;;
  *) exit 1 ;;
esac
''')
        uname.chmod(0o700)
        download_log = self.base / 'download-url'
        self.env.pop('SR_BIN', None)
        self.env.pop('SR_SHA256', None)
        self.env.update(PATH=str(tools) + os.pathsep + self.env['PATH'],
                        DOWNLOAD_SOURCE=str(self.binary), DOWNLOAD_LOG=str(download_log),
                        SR_REPO='obrdx/SniRoute')
        sources = [('', 'https://github.com/obrdx/SniRoute/releases/latest/download/sniroute_'),
                   ('https://example.com/sniroute_{os}_{arch}', 'https://example.com/sniroute_')]
        for role, mode in [('server', '--temp'), ('client', '--probe')]:
            for system, target_os in [('Linux', 'linux'), ('Darwin', 'darwin')]:
                for machine, target_arch in [('x86_64', 'amd64'), ('aarch64', 'arm64')]:
                    for source, prefix in sources:
                        with self.subTest(role=role, os=system, arch=machine, source=source):
                            self.env.update(TEST_OS=system, TEST_ARCH=machine, SR_BIN_URL=source)
                            result = self.run_script(role, mode)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertEqual(download_log.read_text(), f'{prefix}{target_os}_{target_arch}')
                            self.assert_clean()
        self.env['SR_BIN_URL'] = 'https://example.com/fixed-binary'
        for role, mode in [('server', '--temp'), ('client', '--probe')]:
            result = self.run_script(role, mode)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(download_log.read_text(), self.env['SR_BIN_URL'])
            self.assert_clean()

    def test_arguments_keep_spaces_and_globs(self):
        result = self.run_script('client', '--probe', '-label', 'a b', '-sni-file', '*.txt')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[-1][-4:], ['-label', 'a b', '-sni-file', '*.txt'])
        self.assert_clean()

    def test_menu_reads_stdin(self):
        result = self.run_script('client', stdin='0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.base / 'input.txt').read_text(), '0\n')
        self.assert_clean()

    def test_failure_propagates_and_cleans(self):
        self.env['FAKE_EXIT'] = '7'
        result = self.run_script('client', '--probe')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assert_clean()
        self.assertTrue((self.base / 'state').exists())

    def test_interruption_waits_for_partial_report(self):
        self.env['FAKE_WAIT'] = '1'
        for sig in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            with self.subTest(signal=sig):
                ready = self.base / 'ready'
                ready.unlink(missing_ok=True)
                proc = subprocess.Popen(self.command('client', '--probe'), env=self.env,
                                        cwd=self.base, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, errors="replace", start_new_session=True)
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(.02)
                    self.assertTrue(ready.exists())
                    os.kill(proc.pid, sig)
                    out, err = proc.communicate(timeout=5)
                    self.assertEqual(proc.returncode, 0, out + err)
                    self.assertTrue((self.base / 'partial-report.md').exists())
                    self.assert_clean()
                    (self.base / 'partial-report.md').unlink()
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate()

    def test_terminal_ctrl_c_is_not_forwarded_twice(self):
        self.env['FAKE_WAIT'] = '1'
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        proc = subprocess.Popen(self.command('client', '--probe'), env=self.env,
                                cwd=self.base, stdin=slave, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.base / 'ready').exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue((self.base / 'ready').exists())
            os.killpg(proc.pid, signal.SIGINT)
            out, err = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, out + err)
            self.assertTrue((self.base / 'partial-report.md').exists())
            self.assert_clean()
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()

    def test_temp_server_stops_before_cleanup(self):
        result = self.run_script('server', '--temp')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.base / 'running').exists())
        self.assertTrue((self.base / 'state/server.yaml').exists())
        self.assert_clean()
        commands = [c[:2] for c in self.calls()]
        self.assertIn(['server', 'start'], commands)
        self.assertEqual(commands[-1], ['server', 'stop'])

    def test_install_launcher_and_uninstall(self):
        result = self.run_script('server', '--install')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        launcher = self.base / 'prefix/bin/sniroute'
        result = subprocess.run([str(launcher)], input='0\n', text=True,
                                env=self.env, cwd=self.base, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.base / 'running').exists())
        result = self.run_script('server', '--uninstall')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(launcher.exists())
        self.assertFalse((self.base / 'running').exists())
        self.assertTrue((self.base / 'etc/server.yaml').exists())
        self.assert_clean()

    def test_systemd_install_and_dry_uninstall(self):
        tools = self.base / 'tools'
        tools.mkdir()
        systemctl = tools / 'systemctl'
        systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SYSTEMCTL_LOG"\n')
        systemctl.chmod(0o700)
        calls = self.base / 'systemctl-calls'
        self.env.update(SR_NO_SYSTEMD='0', SYSTEMCTL_LOG=str(calls),
                        PATH=str(tools) + os.pathsep + self.env['PATH'])
        result = self.run_script('server', '--install')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        unit = self.base / 'units/sniroute.service'
        self.assertIn('Restart=always', unit.read_text())
        self.assertIn('enable sniroute.service', calls.read_text())
        self.assertIn('restart sniroute.service', calls.read_text())
        before = calls.read_text()
        result = self.run_script('server', '--uninstall', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.read_text(), before)
        self.assertTrue(unit.exists())

    def test_openrc_install_and_uninstall(self):
        tools = self.base / 'openrc-tools'
        tools.mkdir()
        calls = self.base / 'openrc-calls'
        for name in ('rc-service', 'rc-update'):
            tool = tools / name
            tool.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$OPENRC_LOG"\n')
            tool.chmod(0o700)
        self.env.update(SR_NO_SYSTEMD='0', OPENRC_LOG=str(calls),
                        SR_INIT_DIR=str(self.base / 'init.d'),
                        PATH=str(tools) + os.pathsep + self.env['PATH'])
        result = self.run_script('server', '--install')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        init = (self.base / 'init.d/sniroute').read_text()
        self.assertIn('supervise-daemon', init)
        self.assertIn('command_args="server run -config', init)
        self.assertIn('add sniroute default', calls.read_text())
        self.assertIn('sniroute restart', calls.read_text())
        launcher = (self.base / 'prefix/bin/sniroute').read_text()
        self.assertIn('USE_OPENRC="1"', launcher)
        self.assertIn('USE_SYSTEMD="0"', launcher)
        result = self.run_script('server', '--uninstall')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.base / 'init.d/sniroute').exists())
        self.assertIn('sniroute stop', calls.read_text())
        self.assertIn('del sniroute default', calls.read_text())

    def test_terminal_colors_and_plain_redirected_output(self):
        for role, mode in [('client', '--probe'), ('server', '--install')]:
            for disabled in (False, True):
                with self.subTest(role=role, no_color=disabled):
                    env = dict(self.env, TERM='xterm-256color')
                    env.pop('NO_COLOR', None)
                    if disabled:
                        env['NO_COLOR'] = ''
                    master, slave = pty.openpty()
                    try:
                        result = subprocess.run(self.command(role, '--dry-run', mode),
                                                stdin=subprocess.DEVNULL,
                                                stdout=slave, stderr=slave, cwd=self.base,
                                                env=env, start_new_session=True, timeout=10)
                        # Drain before closing the last slave descriptor:
                        # macOS may discard queued PTY output on last close.
                        os.set_blocking(master, False)
                        output = b''
                        while True:
                            try:
                                chunk = os.read(master, 4096)
                            except OSError:
                                break
                            if not chunk:
                                break
                            output += chunk
                    finally:
                        os.close(master)
                        if slave is not None:
                            os.close(slave)
                    self.assertEqual(result.returncode, 0, output)
                    self.assertEqual(b'\x1b[' in output, not disabled, output)
            result = self.run_script(role, '--dry-run', mode)
            self.assertNotIn('\x1b[', result.stdout + result.stderr)

    def test_dry_run_has_no_side_effects(self):
        for role, mode in [('server', '--uninstall'), ('server', '--install'),
                           ('server', '--temp'), ('client', '--probe')]:
            result = self.run_script(role, '--dry-run', mode)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.base / 'state').exists())
        self.assertFalse((self.base / 'prefix').exists())
        self.assert_clean()


if __name__ == '__main__':
    unittest.main()
