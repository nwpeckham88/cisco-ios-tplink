"""CLI hardening and replay-safety tests."""

import argparse
import io
from unittest.mock import MagicMock

import pytest

import tplink_tool.cli as cli_module

from tplink_tool.cli import (
    SwitchCLI,
    _resolve_password,
    _save_password_to_keychain,
    _delete_password_from_keychain,
    FIRMWARE_PASSWORD,
)
from tplink_tool.sdk import IPSettings, PortSpeed


def _make_args(**overrides):
    args = {
        'host': '10.1.1.239',
        'user': 'admin',
        'password': None,
        'password_stdin': False,
        'password_file': None,
        'password_env': 'TPLINK_PASSWORD',
        'keychain': True,
        'keychain_service': 'tplink-tool',
        'save_keychain': False,
        'delete_keychain': False,
    }
    args.update(overrides)
    return argparse.Namespace(**args)


@pytest.fixture
def shell():
    sw = MagicMock()
    return SwitchCLI(sw, 'switch')


class TestModeGuards:
    def test_no_ip_requires_config_mode(self, shell, capsys):
        shell.onecmd('no ip address dhcp')
        out = capsys.readouterr().out
        assert 'Command not available in exec mode' in out
        shell.sw.get_ip_settings.assert_not_called()
        shell.sw.set_ip_settings.assert_not_called()

    def test_no_bandwidth_requires_config_if_mode(self, shell, capsys):
        shell.onecmd('no bandwidth ingress')
        out = capsys.readouterr().out
        assert 'Command not available in exec mode' in out
        shell.sw.get_bandwidth_control.assert_not_called()
        shell.sw.set_bandwidth_control.assert_not_called()

    def test_no_channel_group_requires_config_if_mode(self, shell, capsys):
        shell.onecmd('no channel-group 1')
        out = capsys.readouterr().out
        assert 'Command not available in exec mode' in out
        shell.sw.get_port_trunk.assert_not_called()
        shell.sw.set_port_trunk.assert_not_called()


class TestReplayCompatibility:
    def test_speed_enum_token_is_accepted(self, shell):
        shell._enter('config-if', _if_ports=[1])
        shell.onecmd('speed 100M-Full')
        shell.sw.set_ports.assert_called_once_with([1], speed=PortSpeed.M100F)

    def test_ip_default_gateway_command(self, shell):
        shell._enter('config')
        shell.sw.get_ip_settings.return_value = IPSettings(
            dhcp=False,
            ip='10.1.1.239',
            netmask='255.255.255.0',
            gateway='10.1.1.1',
        )

        shell.onecmd('ip default-gateway 10.1.1.254')

        shell.sw.set_ip_settings.assert_called_once_with(
            ip='10.1.1.239',
            netmask='255.255.255.0',
            gateway='10.1.1.254',
            dhcp=False,
        )


class TestPasswordResolution:
    @staticmethod
    def make_args(**overrides):
        return _make_args(**overrides)

    def test_argv_password_is_deprecated_but_supported(self):
        args = self.make_args(password='secret')
        with pytest.warns(DeprecationWarning):
            assert _resolve_password(args) == 'secret'

    def test_env_password_is_used(self, monkeypatch):
        monkeypatch.setenv('TPLINK_PASSWORD', 'env-secret')
        args = self.make_args()
        assert _resolve_password(args) == 'env-secret'

    def test_password_stdin_is_supported(self, monkeypatch):
        args = self.make_args(password_stdin=True)
        monkeypatch.setattr('sys.stdin', io.StringIO('stdin-secret\n'))
        assert _resolve_password(args) == 'stdin-secret'

    def test_password_file_is_supported(self, tmp_path):
        secret_file = tmp_path / 'secret.txt'
        secret_file.write_text('file-secret\n', encoding='utf-8')
        args = self.make_args(password_file=str(secret_file))
        assert _resolve_password(args) == 'file-secret'

    def test_hardcoded_fallback_when_no_other_source(self, monkeypatch):
        monkeypatch.delenv('TPLINK_PASSWORD', raising=False)
        args = self.make_args()
        assert _resolve_password(args) == FIRMWARE_PASSWORD

    def test_keychain_password_is_used_when_available(self, monkeypatch):
        class FakeKeyring:
            @staticmethod
            def get_password(service, account):
                assert service == 'tplink-tool'
                assert account == 'admin@10.1.1.239'
                return 'keychain-secret'

        monkeypatch.delenv('TPLINK_PASSWORD', raising=False)
        monkeypatch.setattr('tplink_tool.cli._load_keyring', lambda: FakeKeyring)
        args = self.make_args()
        assert _resolve_password(args) == 'keychain-secret'

    def test_keychain_can_be_disabled(self, monkeypatch):
        class FakeKeyring:
            @staticmethod
            def get_password(service, account):
                return 'keychain-secret'

        monkeypatch.delenv('TPLINK_PASSWORD', raising=False)
        monkeypatch.setattr('tplink_tool.cli._load_keyring', lambda: FakeKeyring)
        args = self.make_args(keychain=False)
        assert _resolve_password(args) == FIRMWARE_PASSWORD

    def test_save_password_to_keychain(self, monkeypatch):
        calls = []

        class FakeKeyring:
            @staticmethod
            def get_password(service, account):
                return None

            @staticmethod
            def set_password(service, account, password):
                calls.append((service, account, password))

        monkeypatch.setattr('tplink_tool.cli._load_keyring', lambda: FakeKeyring)
        args = self.make_args(password='save-me', save_keychain=True)
        resolved = _resolve_password(args)
        _save_password_to_keychain(args, resolved)
        assert calls == [('tplink-tool', 'admin@10.1.1.239', 'save-me')]

    def test_delete_password_from_keychain(self, monkeypatch):
        calls = []

        class FakeKeyring:
            @staticmethod
            def delete_password(service, account):
                calls.append((service, account))

        monkeypatch.setattr('tplink_tool.cli._load_keyring', lambda: FakeKeyring)
        args = self.make_args(delete_keychain=True)
        _delete_password_from_keychain(args)
        assert calls == [('tplink-tool', 'admin@10.1.1.239')]


class TestMainKeychainFlow:
    def test_save_keychain_runs_after_successful_login(self, monkeypatch):
        args = _make_args(password='save-me', save_keychain=True)
        monkeypatch.setattr(cli_module.argparse.ArgumentParser, 'parse_args', lambda self: args)

        saved_calls = []
        monkeypatch.setattr(cli_module, '_save_password_to_keychain',
                            lambda parsed_args, password: saved_calls.append((parsed_args, password)))

        class FakeSwitch:
            def __init__(self, host, user, password):
                self.host = host
                self.user = user
                self.password = password

            def login(self):
                return None

            def get_system_info(self):
                return type('Info', (), {
                    'description': 'TL-SG108E',
                    'firmware': '1.0.0',
                    'ip': '10.1.1.239',
                })()

            def logout(self):
                return None

        class FakeCLI:
            def __init__(self, sw, hostname):
                self.sw = sw
                self.hostname = hostname
                self._compat_mode = False

            def run_vlan_health_check(self):
                return True

            def cmdloop(self):
                return None

        monkeypatch.setattr(cli_module, 'Switch', FakeSwitch)
        monkeypatch.setattr(cli_module, 'SwitchCLI', FakeCLI)

        cli_module.main()
        assert saved_calls == [(args, 'save-me')]

    def test_save_keychain_is_skipped_when_login_fails(self, monkeypatch):
        args = _make_args(password='bad-password', save_keychain=True)
        monkeypatch.setattr(cli_module.argparse.ArgumentParser, 'parse_args', lambda self: args)

        saved_calls = []
        monkeypatch.setattr(cli_module, '_save_password_to_keychain',
                            lambda parsed_args, password: saved_calls.append((parsed_args, password)))

        class FakeSwitch:
            def __init__(self, host, user, password):
                self.host = host
                self.user = user
                self.password = password

            def login(self):
                raise RuntimeError('Login failed')

            def get_system_info(self):
                raise AssertionError('Should not be called when login fails')

            def logout(self):
                return None

        monkeypatch.setattr(cli_module, 'Switch', FakeSwitch)

        with pytest.raises(SystemExit) as exc:
            cli_module.main()

        assert exc.value.code == 1
        assert saved_calls == []

    def test_save_keychain_failure_still_logs_out(self, monkeypatch):
        args = _make_args(password='save-me', save_keychain=True)
        monkeypatch.setattr(cli_module.argparse.ArgumentParser, 'parse_args', lambda self: args)
        monkeypatch.setattr(cli_module, '_save_password_to_keychain',
                            lambda parsed_args, password: (_ for _ in ()).throw(ValueError('keychain unavailable')))

        class FakeSwitch:
            logout_calls = 0

            def __init__(self, host, user, password):
                self.host = host
                self.user = user
                self.password = password

            def login(self):
                return None

            def get_system_info(self):
                return type('Info', (), {
                    'description': 'TL-SG108E',
                    'firmware': '1.0.0',
                    'ip': '10.1.1.239',
                })()

            def logout(self):
                FakeSwitch.logout_calls += 1

        monkeypatch.setattr(cli_module, 'Switch', FakeSwitch)

        with pytest.raises(SystemExit) as exc:
            cli_module.main()

        assert exc.value.code == 2
        assert FakeSwitch.logout_calls == 1
