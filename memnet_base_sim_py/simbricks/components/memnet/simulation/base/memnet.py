# Copyright 2026 Max Planck Institute for Software Systems,
# National University of Singapore, and SimBricks UG (haftungsbeschränkt)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import annotations

import typing_extensions as tpe

from simbricks.orchestration.instantiation import base as inst_base
from simbricks.orchestration.simulation import base as sim_base
from simbricks.orchestration.simulation import net as sim_net
from simbricks.orchestration.system import eth as sys_eth
from simbricks.utils import base as utils_base


class MemSwitchNet(sim_net.NetSim):

    def __init__(
        self,
        simulation: sim_base.Simulation,
        executable: str = "simb_net_memswitch",
        relative_pcap_filepath: str | None = None,
    ) -> None:
        super().__init__(
            simulation=simulation,
            executable=executable,
        )
        self.name = f"MemSwitchNet-{self._id}"
        self._relative_pcap_file_path: str | None = relative_pcap_filepath
        """AS_ID,VADDR_START,VADDR_END,MEMNODE_MAC,PHYS_START."""
        self.mem_map = []

    def add(self, switch_spec: sys_eth.EthSwitch):
        utils_base.has_expected_type(switch_spec, sys_eth.EthSwitch)
        if len(self._components) > 1:
            raise Exception("can only add a single switch component to the SwitchNet")
        super().add(switch_spec)

    def toJSON(self) -> dict:
        json_obj = super().toJSON()
        json_obj["relative_pcap_file_path"] = self._relative_pcap_file_path
        json_obj["mem_map"] = utils_base.list_tuple_to_json(self.mem_map)
        return json_obj

    @classmethod
    def fromJSON(cls, simulation: sim_base.Simulation, json_obj: dict) -> tpe.Self:
        instance = super().fromJSON(simulation, json_obj)
        instance._relative_pcap_file_path = utils_base.get_json_attr_top(
            json_obj, "relative_pcap_file_path"
        )
        instance.mem_map = utils_base.json_array_to_list(
            utils_base.get_json_attr_top(json_obj, "mem_map")
        )
        return instance

    def run_cmd(self, inst: inst_base.Instantiation) -> str:
        channels = self.get_channels()
        eth_latency, sync_period, run_sync = (
            sim_base.Simulator.get_unique_latency_period_sync(channels=channels)
        )

        cmd = inst.env.repo_base(self._executable)
        cmd += f" -S {sync_period} -E {eth_latency}"

        if not run_sync:
            cmd += " -u"

        if self._relative_pcap_file_path is not None:
            pcap_file = inst.env.output_base(
                relative_path=self._relative_pcap_file_path
            )
            cmd += " -p " + pcap_file

        sockets = self._get_socks_by_all_comp(inst=inst)
        listen, connect = sim_base.Simulator.split_sockets_by_type(sockets)

        for sock in connect:
            cmd += " -s " + sock._path

        for sock in listen:
            cmd += " -h " + sock._path

        for m in self.mem_map:
            cmd += " -m " + f" {m[0]},{m[1]},{m[2]},"
            cmd += "".join(reversed(m[3].split(":")))
            cmd += f",{m[4]}"

        return cmd
