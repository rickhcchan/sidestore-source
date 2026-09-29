#!/usr/bin/env python3
"""Generate a Classic-compatible source using only Python's standard library.

Untrusted IPA files are read as ZIP archives, never extracted or executed.
All projects must succeed before any output is published; apps.json is replaced
atomically last. No wall-clock timestamps or download counts enter the output.
"""

import argparse
import hashlib
import json
import os
import plistlib
import re
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_IPA = 2 * 1024**3


class SyncError(ValueError):
    """An upstream or configuration error; leave the existing source intact."""


def require(condition, message):
    if not condition:
        raise SyncError(message)


def string(value, label):
    require(isinstance(value, str) and bool(value.strip()), f"Missing/invalid {label}")
    return value


def https_url(value):
    string(value, "URL")
    u = urllib.parse.urlsplit(value)
    require(u.scheme == "https" and u.hostname and not u.username and not u.password,
            f"Expected a public HTTPS URL: {value}")
    return value


def release_date(value):
    string(value, "release date")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SyncError(f"Invalid release date: {value}") from exc
    require(date.tzinfo is not None, "Release date must include a timezone")
    return value


def open_url(url, *, api=False):
    https_url(url)
    headers = {"User-Agent": "rickhcchan-sidestore-source"}
    if api:
        require(urllib.parse.urlsplit(url).hostname == "api.github.com", "Invalid API host")
        headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        if os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    # IPA requests never carry the token, including redirects to GitHub's CDN.
    for attempt in range(3):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60)
        except urllib.error.HTTPError as exc:
            if attempt == 2 or exc.code not in (429, 500, 502, 503, 504):
                raise SyncError(f"HTTP {exc.code} fetching {url}; check availability/API limits") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == 2:
                raise SyncError(f"Failed to fetch {url}: {exc}") from exc
        time.sleep(2**attempt)


def api_json(path):
    with open_url("https://api.github.com/" + path, api=True) as response:
        return json.load(response)


def latest_release(repository):
    # GitHub's designated latest non-draft, non-prerelease. Do not guess from tags.
    release = api_json(f"repos/{repository}/releases/latest")
    require(release.get("draft") is False and release.get("prerelease") is False,
            f"{repository}: latest release is not stable")
    release_date(release.get("published_at"))
    string(release.get("tag_name"), "release tag")
    # Explicit pagination avoids silently missing ambiguous assets in large releases.
    assets = []
    for page in range(1, 101):
        batch = api_json(f"repos/{repository}/releases/{release['id']}/assets?per_page=100&page={page}")
        require(isinstance(batch, list), "Invalid release assets response")
        assets.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise SyncError("Too many asset pages; refusing incomplete selection")
    release["assets"] = assets
    return release


def select_asset(release, project):
    require(release.get("draft") is False and release.get("prerelease") is False,
            "Refusing a draft/prerelease")
    pattern = re.compile(project["assetPattern"])
    excluded = re.compile(project.get("excludePattern", r"(?!)"))
    matches = [a for a in release["assets"]
               if a["name"].lower().endswith(".ipa")
               and pattern.fullmatch(a["name"]) and not excluded.search(a["name"])]
    names = ", ".join(a["name"] for a in release["assets"])
    require(len(matches) == 1,
            f"{project['repository']} {release['tag_name']}: expected exactly one modern IPA, "
            f"found {len(matches)}. Available assets: {names}. Review config.json selection rules.")
    asset = matches[0]
    require(asset.get("state") == "uploaded", "Selected IPA is not fully uploaded")
    require(type(asset.get("size")) is int and 0 < asset["size"] <= MAX_IPA, "Invalid IPA size")
    url = https_url(asset["browser_download_url"])
    prefix = f"https://github.com/{project['repository']}/releases/download/"
    require(url.startswith(prefix), "IPA URL must point to the original upstream release")
    return asset


def download(asset, destination):
    digest = hashlib.sha256()
    size = 0
    with open_url(asset["browser_download_url"]) as response, destination.open("wb") as out:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            require(size <= asset["size"], "IPA exceeds GitHub's reported file size")
            digest.update(chunk)
            out.write(chunk)
    require(size == asset["size"], f"Truncated IPA: expected {asset['size']} bytes, got {size}")
    checksum = digest.hexdigest()
    if asset.get("digest"):
        require(asset["digest"] == "sha256:" + checksum, "IPA SHA-256 differs from GitHub's digest")
    return checksum


def section(data, offset, size):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
            "Truncated/malformed Mach-O code signature")
    return data[offset:offset + size]


def unpack(fmt, data, offset):
    return struct.unpack(fmt, section(data, offset, struct.calcsize(fmt)))


def entitlements(data):
    """Read embedded XML code-signature entitlements, including fat binaries.

    No signing tools, Apple account, execution, or changes to the IPA are needed.
    Unknown/DER-only signatures fail closed rather than claim no permissions.
    """
    magic = section(data, 0, 4)
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        count, = unpack(">I", data, 4)
        require(0 < count <= 64, "Invalid fat Mach-O architecture count")
        wide = magic[-1] == 0xBF
        result = set()
        for i in range(count):
            pos = 8 + i * (32 if wide else 20)
            offset, size = unpack(">QQ" if wide else ">II", data, pos + 8)
            result.update(entitlements(section(data, offset, size)))
        return result
    formats = {b"\xcf\xfa\xed\xfe": ("<", 32), b"\xce\xfa\xed\xfe": ("<", 28),
               b"\xfe\xed\xfa\xcf": (">", 32), b"\xfe\xed\xfa\xce": (">", 28)}
    require(magic in formats, "Unsupported executable format; cannot inspect entitlements")
    endian, pos = formats[magic]
    count, commands_size = unpack(endian + "II", data, 16)
    commands_end = pos + commands_size
    section(data, pos, commands_size)
    require(count <= commands_size // 8, "Invalid Mach-O command count")
    result = set()
    for _ in range(count):
        command, size = unpack(endian + "II", data, pos)
        require(size >= 8 and pos + size <= commands_end, "Invalid Mach-O load command")
        if command == 0x1D:  # LC_CODE_SIGNATURE
            require(size >= 16, "Truncated code-signature command")
            offset, length = unpack(endian + "II", data, pos + 8)
            signature = section(data, offset, length)
            sig_magic, sig_size, slots = unpack(">III", signature, 0)
            require(sig_magic == 0xFADE0CC0 and 12 <= sig_size <= length,
                    "Unsupported code-signature container")
            signature = section(signature, 0, sig_size)
            require(slots <= (sig_size - 12) // 8, "Invalid signature slot count")
            xml_found = der_found = False
            for j in range(slots):
                kind, start = unpack(">II", signature, 12 + j * 8)
                blob_magic, blob_size = unpack(">II", signature, start)
                require(blob_size >= 8, "Invalid signature blob length")
                payload = section(signature, start + 8, blob_size - 8)
                if kind == 5:
                    require(blob_magic == 0xFADE7171, "Invalid XML entitlements magic")
                    values = plistlib.loads(payload)
                    require(isinstance(values, dict), "Entitlements must be a dictionary")
                    result.update(values)
                    xml_found = True
                elif kind == 7:
                    der_found = True
            require(not der_found or xml_found, "DER-only entitlements unsupported; catalogue unchanged")
        pos += size
    return result


def read_member(archive, name, limit):
    info = archive.getinfo(name)
    require(info.file_size <= limit, f"IPA member too large: {name}")
    return archive.read(info)


def extract_metadata(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "IPA has duplicate ZIP entries")
        mains = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        require(len(mains) == 1, f"Expected one main app Info.plist; found {len(mains)}")
        main = plistlib.loads(read_member(archive, mains[0], 4 * 1024**2))
        keys = {"bundleIdentifier": "CFBundleIdentifier", "version": "CFBundleShortVersionString",
                "buildVersion": "CFBundleVersion", "minOSVersion": "MinimumOSVersion"}
        metadata = {key: string(main.get(plist), plist) for key, plist in keys.items()}
        require(re.fullmatch(r"\d+(?:\.\d+){0,2}", metadata["minOSVersion"]), "Invalid MinimumOSVersion")
        privacy, permissions = {}, set()
        # Include nested app/extension permissions, but never use their versions as the main version.
        bundles = [n for n in names if n.startswith(mains[0].rsplit("/", 1)[0] + "/")
                   and re.search(r"\.(?:app|appex)/Info\.plist$", n)]
        for name in sorted(bundles):
            info = plistlib.loads(read_member(archive, name, 4 * 1024**2))
            for key, value in sorted(info.items()):
                if key.startswith("NS") and key.endswith("UsageDescription"):
                    string(value, key)
                    if key not in privacy:
                        privacy[key] = value
                    elif value != privacy[key] and value not in privacy[key].split("\n"):
                        privacy[key] += "\n" + value
            executable = string(info.get("CFBundleExecutable"), "CFBundleExecutable")
            require("/" not in executable and executable not in (".", ".."), "Invalid executable name")
            binary = read_member(archive, name.rsplit("/", 1)[0] + "/" + executable, MAX_IPA)
            permissions.update(entitlements(binary))
        metadata["appPermissions"] = {"entitlements": sorted(permissions), "privacy": dict(sorted(privacy.items()))}
        # Only use declared primary icons. CgBI/iOS-optimized PNGs need an explicit external iconURL.
        stems = []
        for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
            stems.extend(main.get(key, {}).get("CFBundlePrimaryIcon", {}).get("CFBundleIconFiles", []))
        stems.extend(main.get("CFBundleIconFiles", []))
        candidates = []
        base = mains[0].rsplit("/", 1)[0] + "/"
        for name in names:
            leaf = name.removeprefix(base)
            if not name.startswith(base) or "/" in leaf or not leaf.endswith(".png"):
                continue
            if not any(re.fullmatch(re.escape(s.removesuffix('.png')) + r"(?:@\dx)?(?:~ipad)?\.png", leaf)
                       for s in stems):
                continue
            png = read_member(archive, name, 10 * 1024**2)
            if png[:8] == b"\x89PNG\r\n\x1a\n" and png[12:16] == b"IHDR":
                width, height = unpack(">II", png, 16)
                if 0 < width == height <= 4096:
                    candidates.append((width, name, png))
        metadata["icon"] = max(candidates)[2] if candidates else None
        return metadata


def validate_config(config):
    source = config["source"]
    for key in ("name", "identifier"):
        string(source[key], key)
    https_url(source["sourceURL"])
    require(source["sourceURL"].endswith("/apps.json"), "sourceURL must end in /apps.json")
    require(config["projects"], "Configure at least one project")
    ids, bundles = set(), set()
    for p in config["projects"]:
        require(re.fullmatch(r"[a-z0-9-]+", p["id"]), "Invalid project id")
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", p["repository"]), "Invalid repository")
        require(p["id"] not in ids and p["bundleIdentifier"] not in bundles, "Duplicate project/bundle identity")
        ids.add(p["id"])
        bundles.add(p["bundleIdentifier"])
        for k in ("name", "developerName", "bundleIdentifier", "localizedDescription", "assetPattern"):
            string(p[k], k)
        re.compile(p["assetPattern"])
        re.compile(p.get("excludePattern", r"(?!)"))
        if p.get("iconURL"):
            https_url(p["iconURL"])


def generate_catalogue(config, records):
    source = dict(config["source"], apps=[], news=[])
    icons = {}
    for project, release, asset, metadata, checksum in records:
        require(metadata["bundleIdentifier"] == project["bundleIdentifier"],
                f"{project['id']}: bundle identity changed from {project['bundleIdentifier']} "
                f"to {metadata['bundleIdentifier']}; review upstream before changing config")
        icon_url = project.get("iconURL")
        if not icon_url:
            icon = metadata["icon"]
            require(icon, f"{project['id']}: no web-compatible primary icon; configure iconURL")
            filename = f"icons/{project['id']}-{hashlib.sha256(icon).hexdigest()[:16]}.png"
            icons[filename] = icon
            icon_url = source["sourceURL"].rsplit("/", 1)[0] + "/" + filename
        app = {k: project[k] for k in ("name", "developerName", "localizedDescription")}
        app.update(bundleIdentifier=metadata["bundleIdentifier"], iconURL=icon_url,
                   appPermissions=metadata["appPermissions"])
        if "tintColor" in project:
            app["tintColor"] = project["tintColor"]
        # A latest-only catalogue avoids duplicate (version, build) entries and stale permissions.
        version = {k: metadata[k] for k in ("version", "buildVersion", "minOSVersion")}
        version.update(date=release["published_at"], downloadURL=asset["browser_download_url"],
                       size=asset["size"], sha256=checksum,
                       localizedDescription=f"{project['name']} {release['tag_name']}\n\n"
                       f"{release.get('body') or 'No upstream release notes supplied.'}\n\n"
                       f"Upstream release: {release['html_url']}")
        app["versions"] = [version]
        source["apps"].append(app)
        source["news"].append({
            "identifier": f"{project['id']}-release-{release['id']}-asset-{asset['id']}",
            "title": f"{project['name']} {release['tag_name']}",
            "caption": f"Upstream release available. App {metadata['version']} "
                       f"(build {metadata['buildVersion']}). If already installed with this version, "
                       "a tweak-only update may require manual installation; see release notes.",
            "date": release["published_at"], "url": release["html_url"],
            "appID": metadata["bundleIdentifier"], "notify": True,
        })
    source["news"].sort(key=lambda n: (n["date"], n["identifier"]), reverse=True)
    validate_catalogue(source, config)
    return source, icons


def validate_catalogue(source, config):
    """Validate the emitted common-format subset plus project identity invariants."""
    for key in ("name", "identifier", "sourceURL"):
        require(source.get(key) == config["source"][key], f"Source {key} changed")
    https_url(source["sourceURL"])
    projects = {p["bundleIdentifier"]: p for p in config["projects"]}
    require(isinstance(source.get("apps"), list) and len(source["apps"]) == len(projects), "Incorrect app count")
    seen = set()
    for app in source["apps"]:
        bundle = app.get("bundleIdentifier")
        require(bundle in projects and bundle not in seen, "Unknown/duplicate app identity")
        seen.add(bundle)
        for key in ("name", "developerName", "localizedDescription"):
            string(app.get(key), key)
        https_url(app.get("iconURL"))
        permissions = app["appPermissions"]
        require(isinstance(permissions["entitlements"], list) and
                all(isinstance(p, str) for p in permissions["entitlements"]), "Invalid entitlements")
        require(isinstance(permissions["privacy"], dict) and
                all(isinstance(k, str) and isinstance(v, str) for k, v in permissions["privacy"].items()),
                "Invalid privacy permissions")
        require(len(app["versions"]) == 1, "Expected exactly one current version")
        for v in app["versions"]:
            for key in ("version", "buildVersion", "minOSVersion", "localizedDescription"):
                string(v.get(key), key)
            require(re.fullmatch(r"\d+(?:\.\d+){0,2}", v["minOSVersion"]), "Invalid minimum iOS")
            release_date(v["date"])
            https_url(v["downloadURL"])
            require(v["downloadURL"].startswith(f"https://github.com/{projects[bundle]['repository']}/releases/download/"),
                    "Download must use original upstream GitHub asset")
            require(type(v["size"]) is int and 0 < v["size"] <= MAX_IPA, "Invalid file size")
            require(re.fullmatch(r"[a-f0-9]{64}", v["sha256"]), "Invalid SHA-256")
    news_ids = set()
    require(isinstance(source["news"], list) and len(source["news"]) == len(projects), "Incorrect news count")
    for news in source["news"]:
        for key in ("identifier", "title", "caption"):
            string(news.get(key), key)
        require(news["identifier"] not in news_ids and news["appID"] in projects, "Invalid news identity")
        news_ids.add(news["identifier"])
        release_date(news["date"])
        https_url(news["url"])
        require(type(news["notify"]) is bool, "Invalid news notification flag")


def atomic_write(path, content):
    if path.exists() and path.read_bytes() == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
            tmp = Path(out.name)
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        tmp.chmod(0o644)
        os.replace(tmp, path)
    finally:
        if tmp and tmp.exists():
            tmp.unlink()
    return True


def sync(config, output):
    validate_config(config)
    previous = json.loads(output.read_text()) if output.exists() else None
    if previous:
        for key in ("identifier", "sourceURL"):
            require(previous.get(key) == config["source"][key], f"Refusing to change source {key}")
    records = []
    with tempfile.TemporaryDirectory(prefix="sidestore-source-") as temporary:
        for project in config["projects"]:
            release = latest_release(project["repository"])
            asset = select_asset(release, project)
            print(f"{project['id']}: {release['tag_name']} / {asset['name']}", flush=True)
            ipa = Path(temporary) / (project["id"] + ".ipa")
            checksum = download(asset, ipa)
            metadata = extract_metadata(ipa)
            ipa.unlink()
            print(f"  {metadata['bundleIdentifier']} {metadata['version']} "
                  f"({metadata['buildVersion']}), iOS {metadata['minOSVersion']}+, "
                  f"{asset['size']} bytes; SHA-256 {checksum}", flush=True)
            records.append((project, release, asset, metadata, checksum))
        catalogue, icons = generate_catalogue(config, records)
    if previous:
        old = {a["bundleIdentifier"]: a for a in previous.get("apps", [])}
        for app in catalogue["apps"]:
            earlier = old.get(app["bundleIdentifier"], {}).get("versions", [])
            v = app["versions"][0]
            if earlier and earlier[0].get("sha256") != v["sha256"] and all(
                    earlier[0].get(k) == v[k] for k in ("version", "buildVersion")):
                print(f"NOTICE: {app['name']} IPA changed with identical version/build; "
                      "news and download updated, but an app-update badge cannot be guaranteed.")
    # Validation and all fetching finish before writes. Content-addressed icons cannot
    # break the old catalogue if an interrupted write leaves an unused icon behind.
    for name, content in icons.items():
        atomic_write(output.parent / name, content)
    changed = atomic_write(output, (json.dumps(catalogue, indent=2, ensure_ascii=False) + "\n").encode())
    print("Catalogue updated." if changed else "Catalogue unchanged.")
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    parser.add_argument("--output", type=Path, default=ROOT / "apps.json")
    parser.add_argument("--validate", action="store_true", help="Validate existing catalogue without network access")
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text())
        validate_config(config)
        if args.validate:
            validate_catalogue(json.loads(args.output.read_text()), config)
            print("Catalogue valid.")
        else:
            sync(config, args.output)
    except (SyncError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, struct.error) as exc:
        print(f"ERROR: {exc}. Existing catalogue was not replaced.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
