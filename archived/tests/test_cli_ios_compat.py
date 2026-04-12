"""IOS compatibility tests for CLI command grammar."""

from unittest.mock import MagicMock

import pytest

from tplink_tool.cli import SwitchCLI
from tplink_tool.sdk import Dot1QVlanEntry, StormType


@pytest.fixture
def shell():
    sw = MagicMock()
    return SwitchCLI(sw, 'switch')


class TestHyphenatedCommands:
    def test_channel_group_hyphenated_syntax(self, shell):
        shell._enter('config-if', _if_ports=[1])
        shell.sw.get_port_trunk.return_value = MagicMock(groups={1: [2]})

        shell.onecmd('channel-group 1')

        shell.sw.set_port_trunk.assert_called_once_with(1, [1, 2])

    def test_no_channel_group_hyphenated_syntax(self, shell):
        shell._enter('config-if', _if_ports=[2])
        shell.sw.get_port_trunk.return_value = MagicMock(groups={1: [1, 2, 3]})

        shell.onecmd('no channel-group 1')

        shell.sw.set_port_trunk.assert_called_once_with(1, [1, 3])

    def test_storm_control_hyphenated_syntax(self, shell):
        shell._enter('config-if', _if_ports=[1, 2])

        shell.onecmd('storm-control broadcast rate 5')

        shell.sw.set_storm_control.assert_called_once_with(
            [1, 2],
            rate_index=5,
            storm_types=[StormType.BROADCAST],
        )

    def test_port_vlan_hyphenated_syntax(self, shell):
        shell._enter('config')

        shell.onecmd('port-vlan mode enable')

        shell.sw.set_port_vlan_enabled.assert_called_once_with(True)


class TestInterfaceRangeGrammar:
    def test_interface_range_comma_and_dash(self, shell):
        shell._enter('config')

        shell.onecmd('interface range gi1,gi2,gi4-5')

        assert shell._mode == 'config-if'
        assert shell._if_ports == [1, 2, 4, 5]

    def test_interface_range_ios_slot_port_form(self, shell):
        shell._enter('config')

        shell.onecmd('interface range gi1/0/1-1/0/3')

        assert shell._mode == 'config-if'
        assert shell._if_ports == [1, 2, 3]


class TestTrunkVlanListGrammar:
    def test_switchport_trunk_add_vlan_list(self, shell):
        shell._enter('config-if', _if_ports=[8])
        shell.sw.get_dot1q_vlans.side_effect = [
            (True, []),
            (True, []),
        ]

        shell.onecmd('switchport trunk allowed vlan add 10,20')

        calls = shell.sw.add_dot1q_vlan.call_args_list
        assert [c.args[0] for c in calls] == [10, 20]
        for call in calls:
            assert call.kwargs['tagged_ports'] == [8]
            assert call.kwargs['untagged_ports'] == []

    def test_switchport_trunk_remove_vlan_range(self, shell):
        shell._enter('config-if', _if_ports=[8])
        vlan_entries = [
            Dot1QVlanEntry(vid=10, name='v10', tagged_members=0x80, untagged_members=0),
            Dot1QVlanEntry(vid=11, name='v11', tagged_members=0x80, untagged_members=0),
            Dot1QVlanEntry(vid=12, name='v12', tagged_members=0x80, untagged_members=0),
        ]
        shell.sw.get_dot1q_vlans.side_effect = [
            (True, vlan_entries),
            (True, vlan_entries),
        ]

        shell.onecmd('switchport trunk allowed vlan remove 10-12')

        calls = shell.sw.add_dot1q_vlan.call_args_list
        assert [c.args[0] for c in calls] == [10, 11, 12]
        for call in calls:
            assert call.kwargs['tagged_ports'] == []
