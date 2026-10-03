"""Real menu/preflight/provenance; isolated tools and apt, no host package changes."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from web_link_fixture import terminal
from test_safety import ROOT

# Independent inventory of the production commands; existing platform is mocked.
TOOLS = ('curl tar openssl jq dig certbot flock ss sha256sum timeout iptables ip6tables '
         'nft conntrack getent useradd userdel groupdel awk grep sed cmp cat chmod chown cp cut '
         'date dirname id install mktemp mv readlink rm sleep stat tr uname '
         'groupadd find iptables-save ip6tables-save nginx systemctl systemd-path journalctl').split()
MANUAL = 'apt-get update && apt-get install -y --no-install-recommends'


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root/'tools'; self.tools.mkdir()
        self.managed = self.root/'managed'; self.managed.mkdir()
        for name in ('binary','toml','manifest','web-link','certificate','nginx'):
            (self.managed/name).write_text('private fixture unchanged '+name)
        self.original = self.hashes()
        self.trace = self.root/'trace'
        for tool in TOOLS:
            real = shutil.which(tool)
            if real and tool in ('dirname','mktemp','rm','stat'):
                (self.tools/tool).symlink_to(real)
            else:
                (self.tools/tool).write_text('#!/bin/bash\nexit 0\n')
                (self.tools/tool).chmod(0o755)
        (self.tools/'python3').symlink_to(sys.executable)
        (self.tools/'systemd-path').write_text('#!/bin/bash\nprintf "%s\\n" "$FIXTURE_RUNTIME_PATH"\n')
        (self.tools/'apt-get').write_text('''#!/bin/bash
set -eu
printf 'apt %s frontend=%s\\n' "$*" "${DEBIAN_FRONTEND:-}" >>"$FIXTURE_TRACE"
if [[ $1 == update ]]; then [[ $FIXTURE_APT != update-fail ]]; exit; fi
[[ $FIXTURE_APT != install-fail ]] || exit 41
[[ $FIXTURE_APT != unresolved ]] || exit 0
for tool in $FIXTURE_MISSING; do
    printf '#!/bin/bash\\nexit 0\\n' >"$FIXTURE_TOOLS/$tool"
    /bin/chmod 0755 "$FIXTURE_TOOLS/$tool"
done
''')
        for tool in ('systemd-path','apt-get'): (self.tools/tool).chmod(0o755)
        self.code = '''source "$1"
platform_preflight() {
    printf 'platform %s\\n' "$BASHPID" >>"$FIXTURE_TRACE"
    [[ $FIXTURE_PLATFORM == supported ]] || die 'Unsupported fixture platform'
}
take_lock() { printf 'lock\\n' >>"$FIXTURE_TRACE"; }
fixture_action() {
    printf 'action %s %s\\n' "$1" "$BASHPID" >>"$FIXTURE_TRACE"
    printf reached >"$FIXTURE_MANAGED/action"
}
install_manager() { fixture_action install; }
update_manager() { fixture_action update; }
check_manager() { fixture_action check; }
repair_manager() { fixture_action repair; }
uninstall_manager() { fixture_action uninstall; }
shift
main "$@"
'''
        self.env = dict(os.environ, PATH=str(self.tools), TERM='xterm',
                        FIXTURE_TOOLS=str(self.tools), FIXTURE_TRACE=str(self.trace),
                        FIXTURE_MANAGED=str(self.managed), FIXTURE_APT='success',
                        FIXTURE_RUNTIME_PATH=str(self.tools), FIXTURE_PLATFORM='supported',
                        FIXTURE_MISSING='conntrack')

    def hashes(self):
        return {p.name:hashlib.sha256(p.read_bytes()).digest() for p in self.managed.iterdir()
                if p.name != 'action'}

    def run_action(self, missing=('conntrack',), answer=b'1\ny\n', args=(), **settings):
        for tool in missing: (self.tools/tool).unlink()
        env = dict(self.env, FIXTURE_MISSING=' '.join(missing), **settings)
        command = ['/bin/bash','-c',self.code,'fixture',str(ROOT/'telemt-web-manager.sh'),*args]
        result, output = terminal(command, answer, env)
        text = output.decode()
        trace = self.trace.read_text() if self.trace.exists() else ''
        self.assertEqual(self.hashes(),self.original)
        self.assertNotIn('tg://',text)
        return result,text,trace

    def refused(self,result,trace):
        self.assertNotEqual(result,0)
        self.assertNotIn('action ',trace)
        self.assertNotIn('lock',trace)
        self.assertFalse((self.managed/'action').exists())

    def test_menu_yes_rechecks_and_continues_same_process(self):
        result,text,trace = self.run_action()
        self.assertEqual(result,0)
        self.assertIn('conntrack -> package: conntrack',text)
        self.assertEqual(text.count('Install missing packages now? [y/N]'),1)
        self.assertLess(text.index('Packages to install:'),text.index('Install missing packages now?'))
        self.assertIn('apt update frontend=noninteractive',trace)
        self.assertIn('apt install -y --no-install-recommends conntrack frontend=noninteractive',trace)
        self.assertIn('Dependencies installed successfully. Continuing...',text)
        self.assertTrue((self.tools/'conntrack').exists())
        self.assertIn('action install ',trace)
        lines=trace.splitlines()
        self.assertEqual(lines[0].split()[-1],lines[-1].split()[-1])

    def test_menu_uppercase_yes(self):
        result,_,trace=self.run_action(answer=b'1\nY\n')
        self.assertEqual(result,0); self.assertIn('action install ',trace)

    def test_decline_default_and_non_yes_never_install(self):
        for answer in (b'N',b'',b'yes'):
            with self.subTest(answer=answer):
                # Each case requires a fresh private tool inventory.
                if not (self.tools/'conntrack').exists():
                    (self.tools/'conntrack').write_text('unused'); (self.tools/'conntrack').chmod(0o755)
                result,text,trace=self.run_action(answer=b'1\n'+answer+b'\n')
                self.refused(result,trace)
                self.assertNotIn('apt ',trace)
                self.assertIn('Dependency installation declined.',text)
                self.assertIn(MANUAL+' conntrack',text)
                self.trace.unlink()

    def test_cli_install_check_update_never_prompt_even_on_tty(self):
        for action in ('--install','--check','--update'):
            with self.subTest(action=action):
                if not (self.tools/'conntrack').exists():
                    (self.tools/'conntrack').write_text('unused'); (self.tools/'conntrack').chmod(0o755)
                result,text,trace=self.run_action(answer=b'',args=(action,))
                self.refused(result,trace)
                self.assertNotIn('apt ',trace)
                self.assertNotIn('Install missing packages now?',text)
                self.assertIn(MANUAL+' conntrack',text)
                self.trace.unlink()

    def test_cli_redirected_never_prompt_or_install(self):
        (self.tools/'conntrack').unlink()
        result=subprocess.run(['/bin/bash','-c',self.code,'fixture',str(ROOT/'telemt-web-manager.sh'),'--install'],
                              env=self.env,capture_output=True,timeout=5)
        text=(result.stdout+result.stderr).decode(); trace=self.trace.read_text()
        self.refused(result.returncode,trace)
        self.assertNotIn('apt ',trace); self.assertNotIn('Install missing packages now?',text)
        self.assertIn(MANUAL+' conntrack',text)

    def test_update_failure_does_not_install_or_continue(self):
        result,text,trace=self.run_action(FIXTURE_APT='update-fail')
        self.refused(result,trace)
        self.assertIn('apt update ',trace); self.assertNotIn('apt install',trace)
        self.assertIn('apt-get update failed',text)

    def test_install_failure_does_not_continue(self):
        result,text,trace=self.run_action(FIXTURE_APT='install-fail')
        self.refused(result,trace)
        self.assertIn('apt install',trace); self.assertIn('apt-get install failed',text)

    def test_successful_apt_without_command_fails_mandatory_recheck(self):
        result,text,trace=self.run_action(FIXTURE_APT='unresolved')
        self.refused(result,trace)
        self.assertIn('Required command still missing after package installation: conntrack',text)
        self.assertNotIn('Dependencies installed successfully',text)

    def test_deduplicate_and_collect_all_fixed_packages(self):
        result,text,trace=self.run_action(missing=('dig','iptables','ip6tables','conntrack'))
        self.assertEqual(result,0)
        for tool,package in [('dig','dnsutils'),('iptables','iptables'),('ip6tables','iptables'),('conntrack','conntrack')]:
            self.assertIn(tool+' -> package: '+package,text)
        self.assertIn('apt install -y --no-install-recommends dnsutils iptables conntrack frontend=noninteractive',trace)
        self.assertEqual(text.count('Install missing packages now? [y/N]'),1)
        self.assertLess(text.index('Packages to install:'),text.index('Install missing packages now?'))

    def test_platform_refuses_before_apt_and_action(self):
        result,text,trace=self.run_action(FIXTURE_PLATFORM='unsupported')
        self.refused(result,trace)
        self.assertNotIn('apt ',trace); self.assertNotIn('Install missing packages now?',text)
        self.assertNotIn('Missing required dependencies:',text)
        self.assertIn('Unsupported fixture platform',text)

    def test_nginx_is_prerequisite_never_auto_provisioned(self):
        result,text,trace=self.run_action(missing=('nginx','conntrack'))
        self.refused(result,trace)
        self.assertNotIn('apt ',trace); self.assertNotIn('Install missing packages now?',text)
        self.assertIn('Nginx is not installed automatically',text)

    def test_systemd_path_still_required_after_install(self):
        result,text,trace=self.run_action(FIXTURE_RUNTIME_PATH='/missing-fixture-runtime-path')
        self.refused(result,trace)
        self.assertIn('apt install',trace)
        self.assertIn('conntrack unavailable on the systemd runtime PATH',text)
        self.assertNotIn('Dependencies installed successfully',text)

    def test_uninstall_extra_tools_are_collected_before_mutation(self):
        result,text,trace=self.run_action(missing=('groupadd','find','iptables-save','ip6tables-save'),answer=b'6\ny\n')
        self.assertEqual(result,0)
        self.assertIn('apt install -y --no-install-recommends passwd findutils iptables frontend=noninteractive',trace)
        self.assertIn('action uninstall ',trace)
        self.assertEqual(text.count('Install missing packages now? [y/N]'),1)
        self.assertLess(text.index('Packages to install:'),text.index('Install missing packages now?'))

    def test_no_missing_tools_never_apt_or_prompt(self):
        result,text,trace=self.run_action(missing=(),answer=b'1\n')
        self.assertEqual(result,0); self.assertIn('action install ',trace)
        self.assertNotIn('apt ',trace); self.assertNotIn('Install missing packages now?',text)

    def test_show_link_dependency_group_requires_no_conntrack_or_nginx(self):
        for tool in ('conntrack','certbot','nginx','ss','nft'): (self.tools/tool).unlink()
        code='source "$1"; check_dependencies show-web-link'
        result=subprocess.run(['/bin/bash','-c',code,'fixture',str(ROOT/'telemt-web-manager.sh')],
                              env=self.env,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout,b''); self.assertEqual(result.stderr,b'')

    def test_missing_apt_get_refuses_without_action(self):
        (self.tools/'apt-get').unlink()
        result,text,trace=self.run_action()
        self.refused(result,trace)
        self.assertNotIn('apt ',trace)
        self.assertIn('apt-get unavailable',text)

    def test_menu_with_redirected_stdout_cannot_install(self):
        (self.tools/'conntrack').unlink()
        result,text=terminal(['/bin/bash','-c',self.code,'fixture',str(ROOT/'telemt-web-manager.sh')],
                             b'1\ny\n',self.env,output_tty=False)
        trace=self.trace.read_text(); self.refused(result,trace)
        self.assertNotIn('apt ',trace)
        self.assertNotIn(b'Install missing packages now?',text)
        self.assertIn((MANUAL+' conntrack').encode(),text)


if __name__ == '__main__':
    unittest.main()
