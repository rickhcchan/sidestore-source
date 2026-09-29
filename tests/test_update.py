import copy
import io
import json
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import update as u


CONFIG = json.loads((u.ROOT / "config.json").read_text())
# These synthetic releases and IPA fixtures describe YTKACE only.
CONFIG["projects"] = [p for p in CONFIG["projects"] if p["id"] == "ytkace"]
PROJECT = CONFIG["projects"][0]
# Names observed in the actual v1.1.1 release on 2026-09-29.
NAMES = ["com.itzzace.ytkace_1.1.1_roothide.deb", "com.itzzace.ytkace_1.1.1_rootless.deb",
         "YTKACE_1.1.1_YouTube_21.39.4.ipa", "YTKACE_1.1.1_YouTube_iOS16_21.33.6.ipa"]


def release():
    return {"id": 100, "tag_name": "v1.1.1", "draft": False, "prerelease": False,
            "published_at": "2026-09-28T19:47:40Z", "body": "Actual release notes ☀",
            "html_url": "https://github.com/itzzace/ytkace/releases/tag/v1.1.1",
            "assets": [{"id": i, "name": n, "size": 123, "state": "uploaded",
                        "browser_download_url": "https://github.com/itzzace/ytkace/releases/download/v1.1.1/" + n}
                       for i, n in enumerate(NAMES)]}


def macho(values=None, der_only=False):
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
    if values is None and not der_only:
        return header
    payload = b"fake DER" if der_only else plistlib.dumps(values)
    blob = struct.pack(">II", 0xFADE7172 if der_only else 0xFADE7171, len(payload) + 8) + payload
    sig = struct.pack(">IIIII", 0xFADE0CC0, len(blob) + 20, 1, 7 if der_only else 5, 20) + blob
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
    return header + struct.pack("<4I", 0x1D, 16, 48, len(sig)) + sig


def metadata():
    return {"bundleIdentifier": "com.google.ios.youtube", "version": "21.39.4",
            "buildVersion": "21.39.4", "minOSVersion": "17.0", "icon": b"test icon bytes",
            "appPermissions": {"entitlements": ["aps-environment"],
                               "privacy": {"NSCameraUsageDescription": "Camera purpose"}}}


def make_ipa(path, fmt=plistlib.FMT_BINARY, change=None, extra_main=False, duplicate=False):
    main = {"CFBundleIdentifier": "com.google.ios.youtube", "CFBundleShortVersionString": "21.39.4",
            "CFBundleVersion": "12345", "MinimumOSVersion": "17.0", "CFBundleExecutable": "YouTube",
            "NSCameraUsageDescription": "Camera purpose"}
    if change:
        change(main)
    with zipfile.ZipFile(path, "w") as z:
        # Put an extension FIRST with different versions: it must never be mistaken for the main app.
        extension = dict(main, CFBundleIdentifier="com.google.ios.youtube.extension",
                         CFBundleShortVersionString="99.0", CFBundleVersion="999",
                         CFBundleExecutable="Extension", NSMicrophoneUsageDescription="Microphone purpose")
        z.writestr("Payload/YouTube.app/PlugIns/Extension.appex/Info.plist", plistlib.dumps(extension, fmt=fmt))
        z.writestr("Payload/YouTube.app/PlugIns/Extension.appex/Extension", macho({"extension-entitlement": True}))
        z.writestr("Payload/YouTube.app/Info.plist", plistlib.dumps(main, fmt=fmt))
        z.writestr("Payload/YouTube.app/YouTube", macho({"aps-environment": "production"}))
        if extra_main:
            z.writestr("Payload/Other.app/Info.plist", plistlib.dumps(main))
        if duplicate:
            z.writestr("Payload/YouTube.app/Info.plist", plistlib.dumps(main))


class AssetSelectionTests(unittest.TestCase):
    def test_actual_asset_names_choose_modern(self):
        r = release()
        r["assets"].append(dict(r["assets"][0], name="source.zip"))
        self.assertEqual(u.select_asset(r, PROJECT)["name"], NAMES[2])

    def test_never_falls_back_to_legacy_or_tweaks(self):
        r = release()
        del r["assets"][2]
        with self.assertRaisesRegex(u.SyncError, "found 0.*iOS16"):
            u.select_asset(r, PROJECT)

    def test_ambiguity_fails_with_asset_names(self):
        r = release()
        r["assets"].append(dict(r["assets"][2], name="YTKACE_1.1.1_YouTube_21.40.1.ipa"))
        with self.assertRaisesRegex(u.SyncError, "found 2.*21.40.1"):
            u.select_asset(r, PROJECT)

    def test_prereleases_and_drafts_rejected(self):
        for flag in ("prerelease", "draft"):
            r = release()
            r[flag] = True
            with self.subTest(flag=flag), self.assertRaises(u.SyncError):
                u.select_asset(r, PROJECT)

    def test_incomplete_asset_and_foreign_url_rejected(self):
        for changes in ({"state": "open"}, {"browser_download_url": "https://example.com/app.ipa"}, {"size": 0}):
            r = release()
            r["assets"][2].update(changes)
            with self.subTest(changes=changes), self.assertRaises(u.SyncError):
                u.select_asset(r, PROJECT)

    def test_all_asset_pages_are_considered(self):
        r = release()
        with patch.object(u, "api_json", side_effect=[r, [r["assets"][0]] * 100, [r["assets"][2]]]) as api:
            fetched = u.latest_release("itzzace/ytkace")
        self.assertEqual(len(fetched["assets"]), 101)
        self.assertIn("page=2", api.call_args[0][0])
        self.assertEqual(u.select_asset(fetched, PROJECT)["name"], NAMES[2])


class IPAExtractionTests(unittest.TestCase):
    def test_binary_and_xml_main_app_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.ipa"
            for fmt in (plistlib.FMT_BINARY, plistlib.FMT_XML):
                with self.subTest(format=fmt):
                    make_ipa(p, fmt)
                    m = u.extract_metadata(p)
                    self.assertEqual(m["bundleIdentifier"], "com.google.ios.youtube")
                    self.assertEqual(m["version"], "21.39.4")
                    self.assertEqual(m["buildVersion"], "12345")
                    self.assertEqual(m["minOSVersion"], "17.0")
                    self.assertEqual(m["appPermissions"]["entitlements"], ["aps-environment", "extension-entitlement"])
                    self.assertEqual(m["appPermissions"]["privacy"]["NSMicrophoneUsageDescription"], "Microphone purpose")

    def test_missing_metadata_rejected_not_guessed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.ipa"
            for field in ("CFBundleVersion", "CFBundleShortVersionString", "MinimumOSVersion", "CFBundleIdentifier"):
                make_ipa(p, change=lambda m: m.pop(field))
                with self.subTest(field=field), self.assertRaisesRegex(u.SyncError, field):
                    u.extract_metadata(p)

    def test_multiple_main_apps_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.ipa"
            make_ipa(p, extra_main=True)
            with self.assertRaisesRegex(u.SyncError, "found 2"):
                u.extract_metadata(p)

    def test_no_main_app_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.ipa"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("Payload/Example.app/PlugIns/Other.appex/Info.plist", plistlib.dumps({}))
            with self.assertRaisesRegex(u.SyncError, "found 0"):
                u.extract_metadata(p)

    def test_duplicate_members_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.ipa"
            with self.assertWarns(UserWarning):
                make_ipa(p, duplicate=True)
            with self.assertRaisesRegex(u.SyncError, "duplicate"):
                u.extract_metadata(p)

    def test_unsigned_and_fat_executable_permissions(self):
        self.assertEqual(u.entitlements(macho()), set())
        a, b = macho({"one": True}), macho({"two": True})
        fat = struct.pack(">II", 0xCAFEBABE, 2)
        fat += struct.pack(">5I", 0, 0, 48, len(a), 0)
        fat += struct.pack(">5I", 0, 0, 48 + len(a), len(b), 0)
        self.assertEqual(u.entitlements(fat + a + b), {"one", "two"})

    def test_malformed_and_der_only_signatures_fail_closed(self):
        for binary in (b"not executable", macho({"one": True})[:-10], macho(der_only=True)):
            with self.subTest(binary=binary[:4]), self.assertRaises(u.SyncError):
                u.entitlements(binary)


class CatalogueTests(unittest.TestCase):
    def catalogue(self, r=None, m=None):
        r, m = r or release(), m or metadata()
        return u.generate_catalogue(CONFIG, [(PROJECT, r, u.select_asset(r, PROJECT), m, "a" * 64)])

    def test_exact_ipa_values_not_release_tag_and_direct_url(self):
        source, icons = self.catalogue()
        app = source["apps"][0]
        v = app["versions"][0]
        self.assertEqual(v["version"], "21.39.4")
        self.assertEqual(v["buildVersion"], "21.39.4")
        self.assertEqual(v["size"], 123)
        self.assertEqual(v["minOSVersion"], "17.0")
        self.assertEqual(v["date"], release()["published_at"])
        self.assertEqual(v["downloadURL"], release()["assets"][2]["browser_download_url"])
        self.assertIn("Actual release notes ☀", v["localizedDescription"])
        self.assertEqual(source["identifier"], CONFIG["source"]["identifier"])
        self.assertTrue(app["iconURL"].endswith(next(iter(icons))))
        u.validate_catalogue(json.loads(json.dumps(source)), CONFIG)

    def test_tweak_only_release_keeps_version_changes_download_and_news(self):
        before, _ = self.catalogue()
        r = release()
        r.update(id=101, tag_name="v1.1.2", published_at="2026-09-29T12:00:00Z")
        r["assets"][2].update(id=20, name="YTKACE_1.1.2_YouTube_21.39.4.ipa",
                              browser_download_url="https://github.com/itzzace/ytkace/releases/download/v1.1.2/YTKACE_1.1.2_YouTube_21.39.4.ipa")
        after, _ = self.catalogue(r)
        old, new = before["apps"][0]["versions"][0], after["apps"][0]["versions"][0]
        self.assertEqual((old["version"], old["buildVersion"]), (new["version"], new["buildVersion"]))
        self.assertNotEqual(old["downloadURL"], new["downloadURL"])
        self.assertNotEqual(before["news"][0]["identifier"], after["news"][0]["identifier"])
        self.assertEqual(len(after["apps"][0]["versions"]), 1)

    def test_repeated_generation_is_identical(self):
        self.assertEqual(self.catalogue(), self.catalogue())

    def test_changed_bundle_id_fails(self):
        m = metadata()
        m["bundleIdentifier"] = "com.example.changed"
        with self.assertRaisesRegex(u.SyncError, "bundle identity changed"):
            self.catalogue(m=m)

    def test_validation_rejects_invalid_catalogue(self):
        source, _ = self.catalogue()
        for field, value in (("size", -1), ("version", 42), ("date", "not-a-date"),
                             ("downloadURL", "https://example.com/copy.ipa"), ("sha256", "wrong")):
            broken = copy.deepcopy(source)
            broken["apps"][0]["versions"][0][field] = value
            with self.subTest(field=field), self.assertRaises(u.SyncError):
                u.validate_catalogue(broken, CONFIG)

    def test_additional_project_without_code_changes(self):
        config = copy.deepcopy(CONFIG)
        p = dict(PROJECT, id="other", repository="example/other", bundleIdentifier="com.example.other")
        config["projects"].append(p)
        r = release()
        asset = dict(r["assets"][2], browser_download_url="https://github.com/example/other/releases/download/v1/app.ipa")
        m = dict(metadata(), bundleIdentifier=p["bundleIdentifier"])
        result, _ = u.generate_catalogue(config, [(PROJECT, r, r["assets"][2], metadata(), "a" * 64),
                                                  (p, r, asset, m, "b" * 64)])
        self.assertEqual(len(result["apps"]), 2)


class SyncTests(unittest.TestCase):
    def test_truncated_and_wrong_digest_downloads_fail(self):
        with tempfile.TemporaryDirectory() as d:
            for asset in ({"size": 4}, {"size": 3, "digest": "sha256:" + "0" * 64}):
                asset["browser_download_url"] = "https://github.com/example/repo/releases/download/v1/app.ipa"
                with patch.object(u, "open_url", return_value=io.BytesIO(b"123")), self.assertRaises(u.SyncError):
                    u.download(asset, Path(d) / "test.ipa")

    def test_success_then_noop_does_not_touch_file(self):
        def fake_download(asset, path):
            path.write_bytes(b"fixture")
            return "a" * 64
        with tempfile.TemporaryDirectory() as d, patch.object(u, "latest_release", return_value=release()), \
                patch.object(u, "download", side_effect=fake_download), \
                patch.object(u, "extract_metadata", return_value=metadata()):
            out = Path(d) / "apps.json"
            self.assertTrue(u.sync(CONFIG, out))
            before = out.stat().st_mtime_ns
            self.assertFalse(u.sync(CONFIG, out))
            self.assertEqual(out.stat().st_mtime_ns, before)

    def test_failure_in_second_project_preserves_catalogue_and_icons(self):
        config = copy.deepcopy(CONFIG)
        config["projects"].append(dict(PROJECT, id="other", bundleIdentifier="com.example.other"))
        source, _ = CatalogueTests().catalogue()
        def fake_download(asset, path):
            path.write_bytes(b"fixture")
            return "a" * 64
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "apps.json"
            original = json.dumps(source).encode()
            out.write_bytes(original)
            with patch.object(u, "latest_release", side_effect=[release(), u.SyncError("upstream unavailable")]), \
                    patch.object(u, "download", side_effect=fake_download), \
                    patch.object(u, "extract_metadata", return_value=metadata()), self.assertRaises(u.SyncError):
                u.sync(config, out)
            self.assertEqual(out.read_bytes(), original)
            self.assertEqual(list(Path(d).iterdir()), [out])

    def test_invalid_metadata_preserves_existing_catalogue(self):
        source, _ = CatalogueTests().catalogue()
        def fake_download(asset, path):
            path.write_bytes(b"fixture")
            return "a" * 64
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "apps.json"
            out.write_text(json.dumps(source))
            original = out.read_bytes()
            with patch.object(u, "latest_release", return_value=release()), \
                    patch.object(u, "download", side_effect=fake_download), \
                    patch.object(u, "extract_metadata", return_value=dict(metadata(), bundleIdentifier="wrong")), \
                    self.assertRaises(u.SyncError):
                u.sync(CONFIG, out)
            self.assertEqual(out.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
