#!/usr/bin/env python3

import argparse
import contextlib
import io
import tarfile
import tempfile
import unittest
from unittest import mock

import adblock_to_mitmania as converter


def parse(text: str) -> converter.ParsedFilters:
    return converter.parse_sources([("fixture", text.splitlines())])


class ParseFiltersTest(unittest.TestCase):
    def test_common_ublock_adblock_and_hosts_forms(self) -> None:
        parsed = parse(
            """
            ! title
            ||ads.example^
            tracker.example
            0.0.0.0 metrics.example another.example # sink entries
            @@||allowed.ads.example^
            """
        )
        self.assertEqual(
            parsed.blocked,
            {"ads.example", "tracker.example", "metrics.example", "another.example"},
        )
        self.assertEqual(parsed.exceptions, {"allowed.ads.example"})

    def test_adguard_dns_forms_and_scoped_rules(self) -> None:
        parsed = parse(
            """
            ||no-caret.example
            inline-comment.example # AdGuard domains-only comment
            ||doubleclick.net^
            ||googlesyndication.com^
            ||adservice.google.com^
            ||important.example^$important
            @@||important.example^
            ||allowed-important.example^$important
            @@||allowed-important.example^$important
            ||rewrite.example^$dnsrewrite=REFUSED
            ||client.example^$client=127.0.0.1
            ||aaaa-only.example^$dnstype=AAAA
            ||third-party.example^$third-party
            """
        )
        self.assertEqual(
            parsed.blocked,
            {
                "no-caret.example",
                "inline-comment.example",
                "doubleclick.net",
                "googlesyndication.com",
                "adservice.google.com",
            },
        )
        self.assertEqual(parsed.important, {"important.example"})
        self.assertEqual(parsed.important_exceptions, {"allowed-important.example"})
        self.assertEqual(parsed.exceptions, set())
        self.assertEqual(parsed.stats["unsupported"], 4)

    def test_badfilter_disables_only_same_priority_and_disposition(self) -> None:
        parsed = parse(
            """
            ||normal.example^
            ||normal.example^$badfilter
            ||important.example^$important
            ||important.example^$important,badfilter
            @@||exception.example^
            @@||exception.example^$badfilter
            @@||important-exception.example^$important
            @@||important-exception.example^$important,badfilter
            """
        )
        self.assertFalse(parsed.blocked)
        self.assertFalse(parsed.important)
        self.assertFalse(parsed.exceptions)
        self.assertFalse(parsed.important_exceptions)

    def test_cosmetic_path_and_invalid_hosts_are_not_widened(self) -> None:
        parsed = parse(
            """
            example.org##.advert
            ||example.org/ads/*
            ||*.wildcard.example^
            localhost
            one-label
            """
        )
        self.assertFalse(parsed.blocked)
        self.assertEqual(parsed.stats["unsupported"], 5)

    def test_ghostery_archive_imports_only_selected_categories(self) -> None:
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
            for name, content in {
                "trackerdb-main/db/patterns/ad.eno": """
                    name: Ad network
                    category: advertising
                    --- domains
                    ads.ghostery.example
                    --- domains
                """,
                "trackerdb-main/db/patterns/utility.eno": """
                    name: Useful CDN
                    category: utilities
                    --- domains
                    useful.ghostery.example
                    --- domains
                """,
            }.items():
                raw = content.encode()
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))

        provider = converter.GhosteryProvider("trackerdb.tar.gz")
        lines = provider.decode(
            archive_buffer.getvalue(),
            "trackerdb.tar.gz",
            1024 * 1024,
            converter.DEFAULT_GHOSTERY_CATEGORIES,
        )
        parsed = converter.parse_sources([("ghostery", lines)])
        self.assertEqual(parsed.blocked, {"ads.ghostery.example"})

    def test_effective_domains_are_sorted_and_exclude_exceptions(self) -> None:
        parsed = parse(
            """
            ||z.example^
            ||a.example^$important
            ||allowed.example^
            @@||allowed.example^
            """
        )
        self.assertEqual(
            converter.effective_blocked_domains(parsed),
            ["a.example", "z.example"],
        )

    def test_mined_rule_counts_are_recorded_per_provider(self) -> None:
        parsed = converter.parse_sources(
            [
                (
                    "adblock=https://example.test/list.txt",
                    ["||ads.example^", "@@||allowed.example^", "not a rule /"],
                )
            ]
        )

        provider, stats = parsed.source_stats[0]
        self.assertEqual(provider, "adblock")
        self.assertEqual(stats["mined"], 2)
        self.assertEqual(stats["lines"], 3)
        self.assertEqual(stats["unsupported"], 1)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            converter.print_stats(parsed, [])
        self.assertIn("mined provider=adblock rules=2 lines=3 unsupported=1", stderr.getvalue())
        self.assertIn("mined=2 effective_domains=1", stderr.getvalue())


class OutputTest(unittest.TestCase):
    def test_rule_priority_and_catch_all(self) -> None:
        parsed = parse(
            """
            ||block.example^
            @@||allow.example^
            ||important.example^$important
            @@||important-allow.example^$important
            """
        )
        args = argparse.Namespace(
            max_regex_chars=12_000,
            action="block",
            status=403,
            body="blocked",
            no_catch_all=False,
        )
        rules = converter.build_http_rules(parsed, args)
        self.assertIn("important-allow\\.example", rules[0]["match"]["host"])
        self.assertFalse(rules[0]["mitm"])
        self.assertIn("important\\.example", rules[1]["match"]["host"])
        self.assertEqual(rules[1]["connection"], {"accept": False})
        self.assertNotIn("request", rules[1])
        self.assertIn("allow\\.example", rules[2]["match"]["host"])
        self.assertIn("block\\.example", rules[3]["match"]["host"])
        self.assertEqual(rules[3]["connection"], {"accept": False})
        self.assertEqual(rules[4], {"match": {}, "mitm": False})

    def test_action_raise_still_uses_interception(self) -> None:
        parsed = parse("||block.example^\n")
        args = argparse.Namespace(
            max_regex_chars=12_000,
            action="raise",
            status=403,
            body="blocked",
            no_catch_all=False,
        )
        rules = converter.build_http_rules(parsed, args)
        blocked = next(r for r in rules if "block\\.example" in r["match"]["host"])
        self.assertNotIn("deny", blocked)
        self.assertEqual(
            blocked["request"],
            [{"action": "raise", "params": {"http": 403, "body": "blocked"}}],
        )

    def test_base_ruleset_preserves_bucket_values_and_appends_existing_http(self) -> None:
        base = {
            "0.0.0.0/0": {
                "uuid": "v4-id",
                "http": [{"match": {}, "mitm": False}],
                "egress": [{"cidr": "0.0.0.0/0", "action": "allow"}],
            },
            "::/0": {
                "uuid": "v6-id",
                "http": [{"match": {"host": "existing.example"}, "mitm": False}],
                "egress": [{"cidr": "::/0", "action": "allow"}],
            },
        }
        generated = [
            {"match": {"host": "re:(?:^|\\.)ads\\.example$"}, "request": [{"action": "block"}]}
        ]
        merged = converter.merge_base_ruleset(base, generated)

        self.assertEqual(merged["0.0.0.0/0"]["uuid"], "v4-id")
        self.assertEqual(
            merged["0.0.0.0/0"]["egress"],
            [{"cidr": "0.0.0.0/0", "action": "allow"}],
        )
        self.assertEqual(
            merged["0.0.0.0/0"]["http"],
            [*generated, converter.GENERATION_BOUNDARY, *base["0.0.0.0/0"]["http"]],
        )
        self.assertEqual(
            merged["::/0"]["http"],
            [*generated, converter.GENERATION_BOUNDARY, *base["::/0"]["http"]],
        )

    def test_repeated_merge_does_not_accumulate_prior_generations(self) -> None:
        base = {
            "0.0.0.0/0": {
                "uuid": "v4-id",
                "http": [{"match": {}, "mitm": False}],
                "egress": [{"cidr": "0.0.0.0/0", "action": "allow"}],
            },
        }
        first_run = [{"match": {"host": "re:(?:^|\\.)old-ads\\.example$"}, "connection": {"accept": False}}]
        second_run = [{"match": {"host": "re:(?:^|\\.)new-ads\\.example$"}, "connection": {"accept": False}}]

        after_first = converter.merge_base_ruleset(base, first_run)
        after_second = converter.merge_base_ruleset(after_first, second_run)

        # The second run's own base is the first run's OUTPUT (exactly what
        # --control fetches and re-merges against on every invocation) -
        # the stale first-run rule must not survive into the second run's
        # result, or every re-run grows the table by one more generation.
        self.assertEqual(
            after_second["0.0.0.0/0"]["http"],
            [*second_run, converter.GENERATION_BOUNDARY, *base["0.0.0.0/0"]["http"]],
        )
        self.assertNotIn(first_run[0], after_second["0.0.0.0/0"]["http"])
        self.assertEqual(base["0.0.0.0/0"]["http"], [{"match": {}, "mitm": False}])

    def test_cli_refuses_empty_allow_only_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = f"{directory}/empty.txt"
            output = f"{directory}/output.json"
            with open(source, "w", encoding="utf-8") as handle:
                handle.write("! comments only\nexample.org##.advert\n")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = converter.main([f"adblock={source}", "-o", output])
            self.assertEqual(result, 1)
            self.assertIn("no effective blocking hostnames", stderr.getvalue())


class SourceDefaultsTest(unittest.TestCase):
    def test_rules_provider_is_an_interface(self) -> None:
        with self.assertRaises(TypeError):
            converter.RulesProvider()
        for provider_type in converter.PROVIDER_TYPES.values():
            with self.subTest(provider=provider_type.name):
                self.assertTrue(issubclass(provider_type, converter.RulesProvider))
        for provider_type in (
            converter.EasyPrivacyProvider,
            converter.AdGuardProvider,
            converter.UBlockProvider,
            converter.UBlockPrivacyProvider,
            converter.PeterLoweProvider,
            converter.HageziLightProvider,
            converter.HageziTIFMiniProvider,
        ):
            with self.subTest(text_provider=provider_type.name):
                self.assertTrue(issubclass(provider_type, converter.AdBlockProvider))
        self.assertTrue(issubclass(converter.GhosteryProvider, converter.RulesProvider))

    def test_no_sources_uses_compatibility_focused_defaults(self) -> None:
        args = converter.parse_args([])

        self.assertEqual(
            args.sources,
            [
                converter.HageziLightProvider(
                    converter.HageziLightProvider.default_url
                ),
                converter.HageziTIFMiniProvider(
                    converter.HageziTIFMiniProvider.default_url
                ),
            ],
        )

    def test_peterlowe_is_an_explicit_preset(self) -> None:
        args = converter.parse_args(["--preset", "peterlowe"])

        self.assertEqual(
            args.sources,
            [converter.PeterLoweProvider(converter.PeterLoweProvider.default_url)],
        )

    def test_provider_default_urls_are_real(self) -> None:
        self.assertEqual(
            converter.AdBlockProvider.default_url,
            "https://easylist-downloads.adblockplus.org/easylist.txt",
        )
        self.assertEqual(
            converter.EasyPrivacyProvider.default_url,
            "https://easylist.to/easylist/easyprivacy.txt",
        )
        self.assertEqual(
            converter.AdGuardProvider.default_url,
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        )
        self.assertEqual(
            converter.UBlockProvider.default_url,
            "https://ublockorigin.github.io/uAssets/filters/filters.txt",
        )
        self.assertEqual(
            converter.UBlockPrivacyProvider.default_url,
            "https://ublockorigin.github.io/uAssets/filters/privacy.txt",
        )
        self.assertEqual(
            converter.PeterLoweProvider.default_url,
            "https://pgl.yoyo.org/adservers/serverlist.php?"
            "hostformat=plain&mimetype=plaintext&showintro=0",
        )
        self.assertEqual(
            converter.HageziLightProvider.default_url,
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/"
            "light.txt",
        )
        self.assertEqual(
            converter.HageziTIFMiniProvider.default_url,
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/"
            "tif.mini.txt",
        )
        self.assertEqual(
            converter.GhosteryProvider.default_url,
            "https://github.com/ghostery/trackerdb/archive/refs/heads/main.tar.gz",
        )

    def test_named_provider_presets_add_only_that_provider(self) -> None:
        expected = {
            "adblock": converter.AdBlockProvider,
            "easyprivacy": converter.EasyPrivacyProvider,
            "adguard": converter.AdGuardProvider,
            "ublock": converter.UBlockProvider,
            "ublock-privacy": converter.UBlockPrivacyProvider,
            "peterlowe": converter.PeterLoweProvider,
            "hagezi-light": converter.HageziLightProvider,
            "hagezi-tif-mini": converter.HageziTIFMiniProvider,
            "ghostery": converter.GhosteryProvider,
        }
        for preset, provider_type in expected.items():
            with self.subTest(preset=preset):
                args = converter.parse_args(["--preset", preset])
                self.assertEqual(
                    args.sources,
                    [provider_type(provider_type.default_url)],
                )

    def test_all_preset_uses_every_provider_default(self) -> None:
        args = converter.parse_args(["--preset", "all"])

        self.assertEqual(
            args.sources,
            [
                provider_type(provider_type.default_url)
                for provider_type in converter.PROVIDER_TYPES.values()
            ],
        )

    def test_multiple_presets_are_ordered_and_deduplicated(self) -> None:
        args = converter.parse_args(
            [
                "--preset",
                "adguard",
                "ublock",
                "peterlowe",
                "adguard",
            ]
        )
        self.assertEqual(
            args.sources,
            [
                converter.AdGuardProvider(converter.AdGuardProvider.default_url),
                converter.UBlockProvider(converter.UBlockProvider.default_url),
                converter.PeterLoweProvider(converter.PeterLoweProvider.default_url),
            ],
        )

    def test_explicit_source_does_not_add_defaults(self) -> None:
        args = converter.parse_args(["adblock=custom-filter.txt"])
        self.assertEqual(args.sources, [converter.AdBlockProvider("custom-filter.txt")])

    def test_explicit_stdin_does_not_add_defaults(self) -> None:
        args = converter.parse_args(["adguard=-"])
        self.assertEqual(args.sources, [converter.AdGuardProvider("-")])

    def test_source_spec_preserves_equals_in_url(self) -> None:
        args = converter.parse_args(["adblock=https://example.test/list?format=a=b"])
        self.assertEqual(
            args.sources,
            [converter.AdBlockProvider("https://example.test/list?format=a=b")],
        )

    def test_source_requires_known_provider_prefix(self) -> None:
        for source in ("filter.txt", "unknown=https://example.test/list"):
            with self.subTest(source=source), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    converter.parse_args([source])


class ControlTest(unittest.TestCase):
    def test_control_connection_accepts_unix_and_tcp_urls(self) -> None:
        unix_connection = converter.control_connection("unix:///run/mitmania.sock", 5)
        self.assertIsInstance(unix_connection, converter.UnixHTTPConnection)
        self.assertEqual(unix_connection.socket_path, "/run/mitmania.sock")

        tcp_connection = converter.control_connection("tcp://127.0.0.1:5555", 5)
        self.assertIsInstance(tcp_connection, converter.http.client.HTTPConnection)
        self.assertEqual(tcp_connection.host, "127.0.0.1")
        self.assertEqual(tcp_connection.port, 5555)

    def test_control_connection_rejects_endpoint_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "TCP control URL"):
            converter.control_connection("tcp://127.0.0.1:5555/rules/default", 5)

    def test_control_connection_rejects_ignored_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not contain credentials"):
            converter.control_connection("http://user:secret@127.0.0.1:5555", 5)

    def test_control_request_reports_remote_endpoint(self) -> None:
        connection = mock.Mock()
        connection.request.side_effect = OSError(65, "No route to host")
        with mock.patch.object(converter, "control_connection", return_value=connection):
            with self.assertRaisesRegex(
                ValueError,
                r"GET http://192\.168\.16\.1:9077/rules/default: TCP connect failed: \[Errno 65\] No route to host",
            ):
                converter.control_request(
                    "http://192.168.16.1:9077", "GET", None, 5
                )
        connection.close.assert_called_once_with()

    def test_control_failure_happens_before_provider_download(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(
                converter,
                "fetch_control_ruleset",
                side_effect=ValueError("remote unavailable"),
            ),
            mock.patch.object(converter.AdBlockProvider, "load") as load,
            contextlib.redirect_stderr(stderr),
        ):
            result = converter.main(
                [
                    "--quiet",
                    "--control",
                    "http://192.168.16.1:9077",
                    "--preset",
                    "adblock",
                ]
            )
        self.assertEqual(result, 1)
        self.assertIn("remote unavailable", stderr.getvalue())
        load.assert_not_called()

    def test_mined_counts_are_logged_before_control_put(self) -> None:
        base = {
            "0.0.0.0/0": {"http": []},
            "::/0": {"http": []},
        }
        with tempfile.TemporaryDirectory() as directory:
            source = f"{directory}/filters.txt"
            with open(source, "w", encoding="utf-8") as handle:
                handle.write("||ads.example^\n")
            stderr = io.StringIO()
            with (
                mock.patch.object(converter, "fetch_control_ruleset", return_value=base),
                mock.patch.object(converter, "push_control_ruleset") as push,
                contextlib.redirect_stderr(stderr),
            ):
                result = converter.main(
                    [
                        f"adblock={source}",
                        "--control",
                        "http://127.0.0.1:5555",
                    ]
                )

        self.assertEqual(result, 0)
        push.assert_called_once()
        output = stderr.getvalue()
        self.assertLess(output.index("mined provider=adblock"), output.index("pushing "))

    def test_fetch_control_ruleset_uses_get(self) -> None:
        body = b'{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}'
        with mock.patch.object(converter, "control_request", return_value=(200, body)) as request:
            document = converter.fetch_control_ruleset("unix:///tmp/control.sock", 7)
        request.assert_called_once_with("unix:///tmp/control.sock", "GET", None, 7)
        self.assertEqual(set(document), {"0.0.0.0/0", "::/0"})

    def test_push_control_ruleset_uses_put(self) -> None:
        body = b'{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}'
        with mock.patch.object(converter, "control_request", return_value=(204, b"")) as request:
            converter.push_control_ruleset("unix:///tmp/control.sock", body, 9)
        request.assert_called_once_with("unix:///tmp/control.sock", "PUT", body, 9)

    def test_push_rejects_oversize_before_request(self) -> None:
        oversized = b"x" * (converter.CONTROL_MAX_RULESET_BYTES + 1)
        with mock.patch.object(converter, "control_request") as request:
            with self.assertRaisesRegex(ValueError, "refusing to send"):
                converter.push_control_ruleset("unix:///tmp/control.sock", oversized, 9)
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
