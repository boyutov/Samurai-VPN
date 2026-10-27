"""Test installation and the packaged privileged boundary inside private mount/net/user namespaces."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import uuid

mapping = Path("/proc/self/uid_map").read_text().split()
if len(mapping) != 3 or mapping[2] != "1":
    raise SystemExit("Use test-helper-isolated.sh; refusing non-isolated user namespace")
parent = os.environ.get("SAMURAI_PARENT_MOUNTNS")
if not parent or os.readlink("/proc/self/ns/mnt") == parent:
    raise SystemExit("Use test-helper-isolated.sh; refusing original mount namespace")

def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout

def identity():
    private = run("/usr/bin/wg", "genkey").strip()
    public = run("/usr/bin/wg", "pubkey", input=private + "\n").strip()
    return {"privateKey": private, "publicKey": public}

root = Path.cwd()
run("/usr/bin/mount", "--make-rprivate", "/")
with tempfile.TemporaryDirectory(prefix="samurai-helper-sandbox-") as folder:
    base = Path(folder)
    mounted = []
    try:
        for target in ("opt", "run"):
            (base / target).mkdir(mode=0o755)
            run("/usr/bin/mount", "--bind", str(base / target), "/" + target)
            mounted.append("/" + target)
        run(str(root / "native/linux/install-helper.sh"))
        # Installer must refuse an existing installation.
        second = subprocess.run([str(root / "native/linux/install-helper.sh")], capture_output=True, text=True)
        assert second.returncode != 0
        launcher = "/opt/samurai-vpn-helper/bin/samurai-vpn-helper"
        own, peer = identity(), identity()
        network = str(uuid.uuid4())
        configuration = {
            "address": "10.203.1.1", "listenPort": 30101, "identity": own,
            "peers": [{"peerId": str(uuid.uuid4()), "name": "Test peer", "publicKey": peer["publicKey"],
                       "address": "10.203.1.2", "endpoint": "192.0.2.2:30102"}],
        }
        environment = os.environ.copy()
        environment["PKEXEC_UID"] = "1000"
        # Launcher must discard injected Java options.
        environment["JAVA_TOOL_OPTIONS"] = "-invalid-option-that-must-not-reach-java"
        def request(operation, config=None):
            result = subprocess.run([launcher], input=json.dumps({
                "operation": operation, "networkId": network, "configuration": config,
            }), env=environment, capture_output=True, text=True, timeout=20)
            response = json.loads(result.stdout)
            assert own["privateKey"] not in result.stdout + result.stderr
            return result.returncode, response
        code, response = request("up", configuration)
        assert code == 0 and response["status"]["state"] == "up", response
        interface = response["status"]["interfaceName"]
        assert request("status")[1]["status"]["state"] == "up"
        code, response = request("shell")
        assert code != 0 and response["success"] is False
        assert request("down")[1]["status"]["state"] == "down"
        assert request("down")[1]["status"]["state"] == "down"
        links = json.loads(run("/usr/sbin/ip", "-j", "link", "show"))
        assert all(link["ifname"] != interface for link in links)
        print("Packaged helper passed: isolated installation, refusal to overwrite, clean environment, up/status/down, invalid-operation rejection, no leaked keys.")
    finally:
        for target in reversed(mounted):
            subprocess.run(["/usr/bin/umount", target], check=True)
