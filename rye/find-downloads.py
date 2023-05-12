import re
from dataclasses import dataclass

import requests


@dataclass
class Download:
    interpreter: str
    version: tuple[int, int, int]
    arch: str
    platform: str
    url: str
    sha256: str | None


class Finder:
    def find(self) -> list[Download]:
        raise NotImplementedError


class CPythonFinder(Finder):
    RELEASE_URL = "https://api.github.com/repos/indygreg/python-build-standalone/releases"
    FLAVOR_PREFERENCES = [
        "shared-pgo",
        "shared-noopt",
        "shared-noopt",
        "static-noopt",
        "gnu-pgo+lto",
        "gnu-lto",
        "gnu-pgo",
        "pgo+lto",
        "lto",
        "pgo",
    ]
    HIDDEN_FLAVORS = [
        "debug",
        "noopt",
        "install_only",
    ]
    SPECIAL_TRIPLES = {
        "macos": "x86_64-apple-darwin",
        "linux64": "x86_64-unknown-linux",
        "windows-amd64": "x86_64-pc-windows",
        "windows-x86": "i686-pc-windows",
        "linux64-musl": "x86_64-unknown-linux",
    }

    # matches these: https://doc.rust-lang.org/std/env/consts/constant.ARCH.html
    ARCH_MAPPING = {
        "x86_64": "x86_64",
        "x86": "x86",
        "i686": "x86",
        "aarch64": "aarch64",
    }

    # matches these: https://doc.rust-lang.org/std/env/consts/constant.OS.html
    PLATFORM_MAPPING = {
        "darwin": "macos",
        "windows": "windows",
        "linux": "linux",
    }

    _filename_re = re.compile(
        r"""(?x)
        ^
            cpython-(?P<ver>\d+\.\d+\.\d+?)
            (?:\+\d+)?
            -(?P<triple>.*?)
            (?:-[\dT]+)?\.tar\.(?:gz|zst)
        $
    """
    )

    _suffix_re = re.compile(
        r"""(?x)^(.*?)-(%s)$"""
        % (
            "|".join(
                map(
                    re.escape,
                    sorted(FLAVOR_PREFERENCES + HIDDEN_FLAVORS, key=len, reverse=True),
                )
            )
        )
    )

    def __init__(self, github_token: str):
        headers = {
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": "Bearer " + github_token,
        }
        self._sess = requests.Session()
        self._sess.headers.update(headers)

    @classmethod
    def parse_filename(cls, filename: str) -> tuple[str, str, str] | None:
        match = cls._filename_re.match(filename)
        if match is None:
            return
        version, triple = match.groups()
        if triple.endswith("-full"):
            triple = triple[:-5]
        match = cls._suffix_re.match(triple)
        if match is not None:
            triple, suffix = match.groups()
        else:
            suffix = None
        return version, triple, suffix

    @classmethod
    def normalize_triple(cls, triple: str) -> str | None:
        triple = cls.SPECIAL_TRIPLES.get(triple, triple)
        pieces = triple.split("-")
        try:
            arch = cls.ARCH_MAPPING.get(pieces[0])
            if arch is None:
                return
            platform = cls.PLATFORM_MAPPING.get(pieces[2])
            if platform is None:
                return
        except IndexError:
            return
        return "%s-%s" % (arch, platform)

    def read_sha256(self, url: str) -> str | None:
        resp = self._sess.get(url + ".sha256")
        if not resp.ok:
            return None
        return resp.text.strip()

    @staticmethod
    def _sort_key(info: tuple[str, str, str]) -> int:
        triple, flavor, url = info
        try:
            pref = CPythonFinder.FLAVOR_PREFERENCES.index(flavor)
        except ValueError:
            pref = -1
        return pref

    def find(self) -> list[Download]:
        results = {}

        for page in range(1, 100):
            resp = self._sess.get("%s?page=%d" % (self.RELEASE_URL, page))
            rows = resp.json()
            if not rows:
                break
            for row in rows:
                for asset in row["assets"]:
                    url = asset["browser_download_url"]
                    base_name = asset["name"]
                    # These are currently broken: https://github.com/indygreg/python-build-standalone/issues/172
                    if "20230507" in base_name:
                        continue
                    if base_name.endswith(".sha256"):
                        continue
                    info = self.parse_filename(base_name)
                    if info is None:
                        continue
                    py_ver, triple, flavor = info
                    if "-static" in triple or "-musl" in triple or (flavor and "noopt" in flavor):
                        continue
                    triple = self.normalize_triple(triple)
                    if triple is None:
                        continue
                    results.setdefault(py_ver, []).append((triple, flavor, url))

        downloads = []
        for py_ver, choices in results.items():
            py_ver = tuple(map(int, py_ver.split(".")))
            choices.sort(key=self._sort_key, reverse=True)
            seen = set()
            for triple, flavor, url in choices:
                triple = tuple(triple.split("-"))
                if triple in seen:
                    continue
                seen.add(triple)
                sha256 = self.read_sha256(url)
                downloads.append(Download(
                    interpreter="cpython",
                    version=py_ver,
                    arch=triple[0],
                    platform=triple[1],
                    url=url,
                    sha256=sha256,
                ))

        return downloads


class PyPyFinder(Finder):
    BASE_DOWNLOAD_URL = "https://downloads.python.org/pypy/"
    RELEASE_PAGE_URL = "https://www.pypy.org/checksums.html"

    _row_re = re.compile(r"(\w{64})\s+(pypy.+(?:.tar.bz2|.zip))", re.I)
    _filename_re = re.compile(
        r"""(?x)
        ^
            pypy(?P<ver>\d+\.\d+)
            -v(?P<pypy_ver>\d+\.\d+\.\d+(?:rc\d+)?)
            -(?P<triple>.*?)
            (?:\.tar\.bz2|\.zip)
        $
        """
    )

    TRIPLE_MAPPING = {
        "linux64": ("x86_64", "linux"),
        "aarch64": ("aarch64", "linux"),
        "macos_arm64": ("aarch64", "macos"),
        "macos_x86_64": ("x86_64", "macos"),
        "win64": ("x86_64", "windows"),
    }

    @classmethod
    def parse_filename(cls, filename: str) -> tuple[str, str] | None:
        match = cls._filename_re.match(filename)
        if match is None:
            return
        version, pypy_ver, triple = match.groups()
        if "rc" in pypy_ver:
            return None
        if triple == "src":
            return None
        if version.startswith("2."):
            return None
        return version + ".0", triple

    def find(self) -> list[Download]:
        resp = requests.get(self.RELEASE_PAGE_URL)
        html = resp.text
        matches = self._row_re.findall(html)
        downloads = []
        for sha256, filename in matches:
            info = self.parse_filename(filename)
            if info is None:
                continue
            py_ver, triple = info
            if triple not in self.TRIPLE_MAPPING:
                continue
            arch, platform = self.TRIPLE_MAPPING[triple]
            url = self.BASE_DOWNLOAD_URL + filename
            py_ver = tuple(map(int, py_ver.split(".")))
            downloads.append(Download(
                interpreter="pypy",
                version=py_ver,
                arch=arch,
                platform=platform,
                url=url,
                sha256=sha256.strip(),
            ))
        return downloads


def main():
    # github_token = open("token.txt").read().strip()
    # cpython_downloads = CPythonFinder(github_token).find()
    cpython_downloads = []
    pypy_downloads = PyPyFinder().find()

    print("// generated code, do not edit")
    print("use std::borrow::Cow;")
    print(
        "pub const PYTHON_VERSIONS: &[(PythonVersion, &str, &str, &str, Option<&str>)] = &["
    )
    for d in sorted(
            cpython_downloads + pypy_downloads,
            key=lambda x: (x.interpreter, x.version),
            reverse=True,
    ):
        sha256 = 'Some("%s")' % d.sha256 if d.sha256 else "None"
        print(
            f'    (PythonVersion {{ kind: Cow::Borrowed("{d.interpreter}"), major: {d.version[0]}, minor: {d.version[1]}, patch: {d.version[2]}, suffix: None }}, "{d.arch}", "{d.platform}", "{d.url}", {sha256}),'
        )
    print("];")


if __name__ == '__main__':
    main()
