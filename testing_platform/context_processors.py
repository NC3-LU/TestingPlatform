import os
import subprocess

from testing_platform.settings import BASE_DIR


def get_version(request):
    version_res = (
        os.environ.get("PKGVER")
        or subprocess.run(
            ["git", "-C", BASE_DIR, "describe", "--tags"], stdout=subprocess.PIPE
        )
        .stdout.decode()
        .strip()
    )  # Type: str
    version = version_res.split("-")
    if len(version) == 1:
        app_version = version[0]
        version_url = (
            "https://github.com/NC3-LU/TestingPlatform/releases/tag/{}".format(
                version[0]
            )
        )
    else:
        app_version = f"{version[0]} - {version[2][1:]}"
        version_url = "https://github.com/NC3-LU/TestingPlatform/commits/{}".format(
            version[2][1:]
        )
    return {"app_version": app_version, "version_url": version_url}
