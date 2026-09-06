import unittest
from requestwatch.dockerinfo import DockerInventory


def row(container_id, name, address, mode="bridge", ipv6=""):
    return {"Id": container_id, "Names": ["/" + name], "Image": "example:latest", "State": "running",
            "HostConfig": {"NetworkMode": mode},
            "NetworkSettings": {"Networks": {"default": {"IPAddress": address, "GlobalIPv6Address": ipv6}}}}


class FakeClient:
    def __init__(self, data, error=None):
        self.data, self.error, self.requests = data, error, []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, path, params):
        self.requests.append((path, params))
        if self.error:
            raise self.error
        return self

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


class DockerInventoryTests(unittest.TestCase):
    def test_read_only_refresh_and_both_endpoints(self):
        client = FakeClient([row("a", "api", "172.18.0.2", ipv6="fd00::2"),
                             row("b", "database", "172.18.0.3")])
        inventory = DockerInventory(client_factory=lambda: client)
        inventory.refresh()
        self.assertEqual(client.requests, [("/containers/json", {"all": "0"})])
        identity = inventory.identify("172.18.0.2", "172.18.0.3")
        self.assertEqual(identity["container_id"], "a")
        self.assertEqual(identity["dst_container_id"], "b")
        self.assertEqual(identity["container_ids"], ["a", "b"])
        self.assertEqual(inventory.identify("fd00:0:0:0::2", "1.1.1.1")["container_id"], "a")
        self.assertTrue(inventory.status()["available"])

    def test_host_network_and_shared_ip_are_not_guessed(self):
        client = FakeClient([row("host", "host", "192.168.1.2", "host"),
                             row("a", "a", "172.18.0.2"), row("b", "b", "172.18.0.2")])
        inventory = DockerInventory(client_factory=lambda: client)
        inventory.refresh()
        self.assertEqual(inventory.identify("192.168.1.2", "1.1.1.1")["attribution"], "unknown")
        result = inventory.identify("172.18.0.2", "1.1.1.1")
        self.assertEqual(result["attribution"], "unknown")
        self.assertIn("shared", result["attribution_note"])

    def test_failed_refresh_discards_stale_mapping(self):
        client = FakeClient([row("a", "api", "172.18.0.2")])
        inventory = DockerInventory(client_factory=lambda: client)
        inventory.refresh()
        client.error = OSError("Docker unavailable")
        inventory.refresh()
        self.assertEqual(inventory.list(), [])
        self.assertFalse(inventory.status()["available"])
        self.assertEqual(inventory.identify("172.18.0.2", "1.1.1.1")["attribution"], "unknown")

    def test_published_ports_preserve_binding_and_defensive_copy(self):
        item = row("a", "new-api", "172.18.0.2")
        item["Ports"] = [{"PrivatePort": 3000, "PublicPort": 13000, "IP": "127.0.0.1", "Type": "tcp"},
                         {"PrivatePort": 9090, "Type": "tcp"}]
        inventory = DockerInventory(client_factory=lambda: FakeClient([item]))
        inventory.refresh()
        ports = inventory.list()[0]["ports"]
        self.assertEqual(ports, [{"private_port": 3000, "public_port": 13000, "ip": "127.0.0.1", "type": "tcp"},
                                 {"private_port": 9090, "public_port": None, "ip": "", "type": "tcp"}])
        ports[0]["public_port"] = 1
        self.assertEqual(inventory.list()[0]["ports"][0]["public_port"], 13000)

    def test_list_is_defensive_copy(self):
        inventory = DockerInventory(client_factory=lambda: FakeClient([row("a", "api", "172.18.0.2")]))
        inventory.refresh()
        inventory.list()[0]["ips"].clear()
        self.assertEqual(inventory.list()[0]["ips"], ["172.18.0.2"])


if __name__ == "__main__":
    unittest.main()
