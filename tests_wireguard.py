import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).parent


class WireGuardStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = (ROOT / "wireguard_setup.sh").read_text()
        cls.install = (ROOT / "install.sh").read_text()

    def test_shell_syntax(self):
        for name in ("wireguard_setup.sh", "install.sh"):
            result = subprocess.run(["bash", "-n", str(ROOT / name)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_agent_is_split_tunnel_only(self):
        self.assertIn("Address = ${my_ip}/32", self.script)
        self.assertIn("AllowedIPs = ${hub_wg_ip}/32", self.script)
        self.assertNotIn("AllowedIPs = 0.0.0.0/0", self.script)
        self.assertIn("不使用 0.0.0.0/0", self.script)

    def test_hub_peer_is_single_agent_address(self):
        self.assertIn("AllowedIPs = ${peer_ip}/32", self.script)
        self.assertIn("wg set \"$WG_IF\" peer", self.script)

    def test_install_flow_has_explicit_wireguard_prompts(self):
        self.assertIn("是否同时配置 WireGuard 面板端", self.install)
        self.assertIn("是否通过 WireGuard 连接面板", self.install)
        self.assertIn("setup_wireguard_hub", self.install)
        self.assertIn("setup_wireguard_agent", self.install)

    def test_install_agent_binds_to_wg_address(self):
        self.assertIn("AGENT_HOST_VALUE=\"$WG_AGENT_IP\"", self.install)
        self.assertIn("--bind ${AGENT_HOST_VALUE}:${AGENT_PORT}", self.install)


if __name__ == "__main__":
    unittest.main()
