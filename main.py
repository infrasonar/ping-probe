from libprobe.probe import Probe
from lib.check.ping import CheckPing
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = (
        CheckPing,
    )

    probe = Probe("ping", version, checks)

    probe.start()
