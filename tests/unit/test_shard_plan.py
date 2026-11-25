# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The duration-aware shard plan: tests/utils/shard_plan.py and its use in sharding.py.

What these hold
---------------
The plan moves a module or a test from the shard its path hashes to onto a shard chosen
by measured seconds. The one property that must survive is the one the hash gave for
free: across the shards of a run, every test runs exactly once. The tests below hold it
from three sides: the packing alone (every atom placed once, the same answer every
time, a stale or partial file leaving the unlisted to the hash), the hooks with a plan
(a split module is collected everywhere and filtered per test), and a real pytest run per
shard over a planted tree whose collected ids are compared across the shards.

The committed ``tests/utils/shard_timings.json`` is checked for shape only. Whether it is
fresh is a maintainer's call (scripts/update_shard_timings.py), never a failure here:
a module added or removed since the file was cut costs balance and nothing else.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from tests.utils import shard_plan, sharding
from tests.utils.helpers import checkout_env

REPO_ROOT = Path(__file__).resolve().parents[2]
UPDATE_SCRIPT = REPO_ROOT / "scripts" / "update_shard_timings.py"


def _timings(platform: str, tier: str, **data: Any) -> Dict[str, Any]:
    return {"schema": 1, "platforms": {platform: {tier: data}}}


#: Three modules of 50, 30 and 20 seconds over two shards: 50 | 30 + 20.
THREE = _timings("linux", "unit", modules={"a.py": 50, "b.py": 30, "c.py": 20})


class TestPacking:
    @pytest.mark.unit
    def test_the_heaviest_module_gets_a_shard_to_itself_when_that_is_the_balance(self):
        plan = shard_plan.build_plan(THREE, "linux", "unit", 2)
        assert plan is not None
        assert plan.module_owner("b.py") == plan.module_owner("c.py")
        assert plan.module_owner("a.py") != plan.module_owner("b.py")

    @pytest.mark.unit
    def test_the_plan_is_the_same_every_time_whatever_order_the_file_lists_modules(
        self,
    ):
        shuffled = _timings(
            "linux", "unit", modules={"c.py": 20, "a.py": 50, "b.py": 30}
        )
        first = shard_plan.build_plan(THREE, "linux", "unit", 2)
        second = shard_plan.build_plan(shuffled, "linux", "unit", 2)
        assert first == second

    @pytest.mark.unit
    def test_equal_weights_are_placed_in_path_order_on_the_lowest_shard_first(self):
        timings = _timings(
            "linux", "unit", modules={"b.py": 10, "a.py": 10, "c.py": 10}
        )
        plan = shard_plan.build_plan(timings, "linux", "unit", 3)
        assert [plan.module_owner(m) for m in ("a.py", "b.py", "c.py")] == [1, 2, 3]

    @pytest.mark.unit
    def test_a_module_the_file_does_not_list_keeps_its_crc32_shard(self):
        plan = shard_plan.build_plan(THREE, "linux", "unit", 4)
        assert plan.module_owner("new/test_new.py") == sharding.owner(
            "new/test_new.py", 4
        )

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "platform, tier, count",
        [
            ("windows", "unit", 2),  # no data for this platform
            ("linux", "integration", 2),  # no data for this tier
            ("linux", "e2e", 2),  # a tier with no plan at all
            ("linux", "unit", 0),  # not a shard count
        ],
    )
    def test_no_data_for_the_run_means_no_plan(self, platform, tier, count):
        assert shard_plan.build_plan(THREE, platform, tier, count) is None

    @pytest.mark.unit
    def test_a_module_over_half_a_shards_share_with_per_test_seconds_is_split(self):
        timings = _timings(
            "linux",
            "integration",
            modules={"big.py": 80, "small.py": 20},
            items={"big.py": {"t1": 30, "t2": 30, "t3": 20}},
        )
        plan = shard_plan.build_plan(timings, "linux", "integration", 2)
        assert plan.is_split("big.py") and not plan.is_split("small.py")
        owners = {plan.item_owner("big.py", t) for t in ("t1", "t2", "t3")}
        assert owners == {1, 2}

    @pytest.mark.unit
    def test_a_big_module_without_per_test_seconds_stays_whole(self):
        timings = _timings("linux", "integration", modules={"big.py": 80, "s.py": 20})
        plan = shard_plan.build_plan(timings, "linux", "integration", 2)
        assert not plan.is_split("big.py")

    @pytest.mark.unit
    def test_a_test_the_file_does_not_list_keeps_its_crc32_shard(self):
        timings = _timings(
            "linux",
            "integration",
            modules={"big.py": 100},
            items={"big.py": {"t1": 50, "t2": 50}},
        )
        plan = shard_plan.build_plan(timings, "linux", "integration", 2)
        assert plan.item_owner("big.py", "t_new") == shard_plan.crc32_owner(
            "big.py::t_new", 2
        )

    @pytest.mark.unit
    @pytest.mark.parametrize("count", [2, 3, 5, 8])
    def test_every_atom_lands_on_exactly_one_shard_of_the_count(self, count):
        modules = {f"m{i:02d}.py": float(100 - i) for i in range(40)}
        modules["m00.py"] = 2000.0
        items = {"m00.py": {f"t{j}": 5.0 for j in range(20)}}
        plan = shard_plan.build_plan(
            _timings("linux", "integration", modules=modules, items=items),
            "linux",
            "integration",
            count,
        )
        owners = list(plan.modules.values()) + [
            o for tests in plan.split.values() for o in tests.values()
        ]
        assert all(1 <= o <= count for o in owners)
        assert len(plan.modules) + len(plan.split["m00.py"]) == 39 + 20

    @pytest.mark.unit
    def test_packing_beats_the_hash_on_a_skewed_tier(self):
        weights = [400, 90, 80, 70, 60, 50, 40, 30]
        modules = {f"m{i}.py": float(w) for i, w in enumerate(weights)}
        plan = shard_plan.build_plan(
            _timings("linux", "unit", modules=modules), "linux", "unit", 4
        )
        loads = [0.0] * 4
        for module, seconds in modules.items():
            loads[plan.module_owner(module) - 1] += seconds
        assert max(loads) == 400  # the heavy module alone; the rest fit under it


class TestFileShape:
    @pytest.mark.unit
    def test_the_committed_file_is_valid_and_plans_every_sharded_pool(self):
        timings = shard_plan.load_timings()
        assert timings is not None, "tests/utils/shard_timings.json is missing"
        for platform, count in (("windows", 8), ("macos", 8), ("linux", 6)):
            for tier in shard_plan.TIERS:
                plan = shard_plan.build_plan(timings, platform, tier, count)
                assert plan is not None, (platform, tier)
                assert plan.modules, (platform, tier)

    @pytest.mark.unit
    def test_a_missing_file_is_not_an_error(self, tmp_path):
        assert shard_plan.load_timings(tmp_path / "absent.json") is None

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "content",
        [
            "not json",
            "[]",
            '{"schema": 2, "platforms": {}}',
            '{"schema": 1, "platforms": {"plan9": {}}}',
            '{"schema": 1, "platforms": {"linux": {"e2e": {}}}}',
            '{"schema": 1, "platforms": {"linux": {"unit": {"modules": {"a.py": -1}}}}}',
            '{"schema": 1, "platforms": {"linux": {"unit": {"modules": {"a.py": "3"}}}}}',
            (
                '{"schema": 1, "platforms": {"linux": {"unit": {"modules": {}, '
                '"items": {"b.py": {"t": 1}}}}}}'
            ),
        ],
    )
    def test_a_malformed_file_is_refused_by_name(self, tmp_path, content):
        path = tmp_path / "t.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError):
            shard_plan.load_timings(path)

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "name, expected",
        [
            ("win32", "windows"),
            ("cygwin", "windows"),
            ("darwin", "macos"),
            ("linux", "linux"),
            ("freebsd14", "linux"),
        ],
    )
    def test_platform_keys(self, name, expected):
        assert shard_plan.platform_key(name) == expected

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "nodeid, key",
        [
            ("tests/a.py::test_x", "test_x"),
            ("tests/a.py::TestA::test_x[p-q]", "TestA::test_x[p-q]"),
            ("tests/a.py::test_x[a::b]", "test_x[a::b]"),
            ("tests/a.py", None),
        ],
    )
    def test_a_tests_key_is_its_id_inside_the_module(self, nodeid, key):
        assert shard_plan.item_key(nodeid) == key


class TestHooks:
    @staticmethod
    def _plan() -> shard_plan.Plan:
        return shard_plan.Plan(
            count=2,
            modules={"whole.py": 2},
            split={"big.py": {"t1": 1, "t2": 2}},
        )

    @pytest.mark.unit
    def test_a_split_module_is_never_ignored_and_a_planned_one_goes_where_the_plan_says(
        self, tmp_path
    ):
        for name in ("big.py", "whole.py", "other.py"):
            (tmp_path / name).write_text("", encoding="utf-8")
        patterns = ["*.py"]
        plan = self._plan()

        def ignored(name: str, index: int) -> bool:
            return sharding.ignored_by_shard(
                tmp_path / name, tmp_path, patterns, (index, 2), plan
            )

        assert [ignored("big.py", i) for i in (1, 2)] == [False, False]
        assert [ignored("whole.py", i) for i in (1, 2)] == [True, False]
        # Not in the plan: the hash decides, as with no plan at all.
        hashed = sharding.owner("other.py", 2)
        assert [ignored("other.py", i) for i in (1, 2)] == [i != hashed for i in (1, 2)]

    @pytest.mark.unit
    def test_a_plan_cut_for_another_count_is_not_used(self, tmp_path):
        (tmp_path / "whole.py").write_text("", encoding="utf-8")
        plan = self._plan()  # count 2
        for index in (1, 2, 3):
            assert sharding.ignored_by_shard(
                tmp_path / "whole.py", tmp_path, ["*.py"], (index, 3), plan
            ) == (sharding.owner("whole.py", 3) != index)

    @staticmethod
    def _items(*nodeids: str) -> List[SimpleNamespace]:
        return [SimpleNamespace(nodeid=n) for n in nodeids]

    @pytest.mark.unit
    def test_a_shard_keeps_the_tests_of_a_split_module_the_plan_gives_it(self):
        deselected: List[Any] = []
        config = SimpleNamespace(
            hook=SimpleNamespace(
                pytest_deselected=lambda items: deselected.extend(items)
            )
        )
        items = self._items(
            "big.py::t1", "big.py::t2", "whole.py::t9", "big.py::TestC::t1"
        )
        sharding._SplitModuleItems(self._plan(), 1).pytest_collection_modifyitems(
            config, items
        )
        kept = {i.nodeid for i in items}
        dropped = {i.nodeid for i in deselected}
        assert kept | dropped == {
            "big.py::t1",
            "big.py::t2",
            "whole.py::t9",
            "big.py::TestC::t1",
        }
        assert kept & dropped == set()
        assert "big.py::t1" in kept and "big.py::t2" in dropped
        assert "whole.py::t9" in kept  # not a split module: left to the module owner
        # An unlisted test of the split module is kept by exactly one of the two shards.
        unlisted = self._items("big.py::TestC::t1")
        again = SimpleNamespace(hook=config.hook)
        sharding._SplitModuleItems(self._plan(), 2).pytest_collection_modifyitems(
            again, unlisted
        )
        assert (len(unlisted) == 1) != ("big.py::TestC::t1" in kept)


class TestConfigure:
    @staticmethod
    def _config(markexpr: str) -> SimpleNamespace:
        registered: Dict[str, Any] = {}
        return SimpleNamespace(
            stash=pytest.Stash(),
            getoption=lambda name, default="": markexpr,
            pluginmanager=SimpleNamespace(
                register=lambda plugin, name: registered.__setitem__(name, plugin)
            ),
            registered=registered,
        )

    @pytest.fixture
    def timing_file(self, tmp_path, monkeypatch):
        path = tmp_path / "timings.json"
        monkeypatch.setattr(shard_plan, "TIMINGS_PATH", path)
        monkeypatch.setattr(
            shard_plan, "platform_key", lambda sys_platform=None: "linux"
        )
        return path

    @pytest.mark.unit
    def test_a_sharded_tier_run_builds_the_plan_and_registers_the_item_filter(
        self, timing_file, monkeypatch
    ):
        timing_file.write_text(
            json.dumps(
                _timings(
                    "linux",
                    "integration",
                    modules={"big.py": 90, "s.py": 10},
                    items={"big.py": {"t1": 45, "t2": 45}},
                )
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv(sharding.ENV_VAR, "1of2")
        config = self._config("integration")
        sharding.configure(config)
        plan = config.stash[sharding._PLAN_KEY]
        assert plan is not None and plan.is_split("big.py")
        assert sharding._SPLIT_ITEMS_PLUGIN in config.registered

    @pytest.mark.unit
    @pytest.mark.parametrize("markexpr", ["", "e2e", "unit and not slow", "not unit"])
    def test_only_an_exact_planned_tier_gets_a_plan(
        self, timing_file, monkeypatch, markexpr
    ):
        timing_file.write_text(json.dumps(THREE), encoding="utf-8")
        monkeypatch.setenv(sharding.ENV_VAR, "1of2")
        config = self._config(markexpr)
        sharding.configure(config)
        assert config.stash[sharding._PLAN_KEY] is None

    @pytest.mark.unit
    def test_an_unsharded_run_has_no_plan_and_reads_no_file(
        self, timing_file, monkeypatch
    ):
        timing_file.write_text("not json", encoding="utf-8")
        monkeypatch.delenv(sharding.ENV_VAR, raising=False)
        config = self._config("unit")
        sharding.configure(config)
        assert config.stash[sharding._PLAN_KEY] is None

    @pytest.mark.unit
    def test_a_missing_timing_file_leaves_the_hash_in_charge(
        self, timing_file, monkeypatch
    ):
        monkeypatch.setenv(sharding.ENV_VAR, "1of2")
        config = self._config("unit")
        sharding.configure(config)
        assert config.stash[sharding._PLAN_KEY] is None

    @pytest.mark.unit
    def test_a_malformed_timing_file_is_a_usage_error_not_a_silent_fallback(
        self, timing_file, monkeypatch
    ):
        timing_file.write_text("{", encoding="utf-8")
        monkeypatch.setenv(sharding.ENV_VAR, "1of2")
        with pytest.raises(pytest.UsageError, match="shard_timings.json"):
            sharding.configure(self._config("unit"))


#: The driver a child pytest runs: it points the plan at the planted timing file and
#: then is pytest, so the child collects exactly as a CI shard does.
DRIVER = (
    "import sys\n"
    "from pathlib import Path\n"
    "import pytest\n"
    "from tests.utils import shard_plan\n"
    "shard_plan.TIMINGS_PATH = Path(sys.argv[1])\n"
    "sys.exit(pytest.main(sys.argv[2:]))\n"
)


class TestRealCollection:
    COUNT = 3

    @staticmethod
    def _plant(root: Path) -> Dict[str, Any]:
        """A tree whose one big module the plan splits, plus modules and tests it never saw."""
        (root / "pytest.ini").write_text(
            "[pytest]\ntestpaths = suite\npython_files = test_*.py\n"
            "markers =\n    unit\n    integration\n    e2e\n",
            encoding="utf-8",
        )
        suite = root / "suite"
        suite.mkdir()
        body = "import pytest\n\npytestmark = pytest.mark.unit\n\n\n"
        (suite / "test_big.py").write_text(
            body
            + "".join(f"def test_case_{i}():\n    pass\n\n\n" for i in range(6))
            + "def test_added_after_the_timings():\n    pass\n",
            encoding="utf-8",
        )
        for name in ("test_a.py", "test_b.py", "test_c.py", "test_unseen.py"):
            (suite / name).write_text(
                body + "def test_one():\n    pass\n", encoding="utf-8"
            )
        timings = _timings(
            shard_plan.platform_key(),
            "unit",
            modules={
                "suite/test_big.py": 100,
                "suite/test_a.py": 10,
                "suite/test_b.py": 10,
                "suite/test_c.py": 10,
            },
            items={"suite/test_big.py": {f"test_case_{i}": 16 for i in range(6)}},
        )
        path = root / "timings.json"
        path.write_text(json.dumps(timings), encoding="utf-8")
        (root / "driver.py").write_text(DRIVER, encoding="utf-8")
        return timings

    def _collected(self, root: Path, index: int) -> List[str]:
        done = subprocess.run(
            [
                sys.executable,
                str(root / "driver.py"),
                str(root / "timings.json"),
                "-c",
                str(root / "pytest.ini"),
                "--rootdir",
                str(root),
                "--confcutdir",
                str(root),
                "-p",
                "tests.utils.sharding",
                "-p",
                "no:cacheprovider",
                "-p",
                "no:randomly",
                "-n",
                "0",
                "-m",
                "unit",
                "--collect-only",
                "-q",
            ],
            cwd=root,
            env=checkout_env(
                {
                    **{
                        k: v
                        for k, v in os.environ.items()
                        if not k.startswith(("PYTEST_", "COV_CORE_", "COVERAGE_"))
                        and k not in (sharding.ENV_VAR, sharding.FLOOR_ENV_VAR)
                    },
                    sharding.ENV_VAR: f"{index}of{self.COUNT}",
                }
            ),
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert done.returncode in (0, 5), done.stdout + done.stderr
        return [line for line in done.stdout.splitlines() if "::" in line]

    @pytest.mark.integration
    def test_every_test_runs_in_exactly_one_shard_and_the_big_module_is_split(
        self, tmp_path
    ):
        timings = self._plant(tmp_path)
        per_shard = {i: self._collected(tmp_path, i) for i in range(1, self.COUNT + 1)}
        everything = sorted(t for tests in per_shard.values() for t in tests)
        expected = sorted(
            [f"suite/test_big.py::test_case_{i}" for i in range(6)]
            + ["suite/test_big.py::test_added_after_the_timings"]
            + [
                f"suite/{name}::test_one"
                for name in ("test_a.py", "test_b.py", "test_c.py", "test_unseen.py")
            ]
        )
        assert everything == expected, per_shard
        big_shards = {
            i
            for i, tests in per_shard.items()
            if any("test_big.py" in t for t in tests)
        }
        assert len(big_shards) > 1, "the big module should be split across shards"
        plan = shard_plan.build_plan(
            timings, shard_plan.platform_key(), "unit", self.COUNT
        )
        for i, tests in per_shard.items():
            for case in range(6):
                node = f"suite/test_big.py::test_case_{case}"
                assert (node in tests) == (
                    plan.item_owner("suite/test_big.py", f"test_case_{case}") == i
                )
        # A module the file never listed is where the hash put it, as before.
        for i, tests in per_shard.items():
            assert ("suite/test_unseen.py::test_one" in tests) == (
                sharding.owner("suite/test_unseen.py", self.COUNT) == i
            )


class TestUpdateScript:
    JUNIT = (
        '<?xml version="1.0"?><testsuites><testsuite name="pytest">'
        '<testcase classname="tests.unit.a" name="test_x" time="3.0"/>'
        '<testcase classname="tests.unit.a.TestC" name="test_y[1]" time="1.5"/>'
        '<testcase classname="" name="tests.unit.b" time="0.0"><skipped/></testcase>'
        '<testcase classname="tests.gone.x" name="test_z" time="9.0"/>'
        "</testsuite></testsuites>"
    )

    def _artifact(self, root: Path, name: str, junit: str) -> None:
        directory = root / name
        directory.mkdir(parents=True)
        (directory / "pytest.junit.xml").write_text(junit, encoding="utf-8")

    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        for module in ("tests/unit/a.py", "tests/unit/b.py"):
            (repo / module).parent.mkdir(parents=True, exist_ok=True)
            (repo / module).write_text("", encoding="utf-8")
        return repo

    def _run(
        self, repo: Path, artifacts: Path, out: Path
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(UPDATE_SCRIPT),
                str(artifacts),
                "--repo-root",
                str(repo),
                "--out",
                str(out),
                "--source",
                "a test",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env=checkout_env(),
        )

    @pytest.mark.integration
    def test_a_complete_group_becomes_module_and_per_test_seconds(self, tmp_path):
        repo = self._repo(tmp_path)
        artifacts = tmp_path / "artifacts"
        for index in (1, 2):
            self._artifact(
                artifacts,
                f"test-results-windows-latest-x86_64-py3.12-unit-shard{index}of2",
                self.JUNIT,
            )
        out = tmp_path / "out.json"
        done = self._run(repo, artifacts, out)
        assert done.returncode == 0, done.stderr
        timings = json.loads(out.read_text(encoding="utf-8"))
        shard_plan.validate(timings)
        data = timings["platforms"]["windows"]["unit"]
        # Two shards of the same group add up; the module that no longer exists is left out.
        assert data["modules"] == {"tests/unit/a.py": 9.0}
        assert "tests/gone/x.py" not in data["modules"]
        assert "testcase(s) matched no file" in done.stderr

    @pytest.mark.integration
    def test_the_file_is_written_the_way_the_pretty_format_json_hook_writes_it(
        self, tmp_path
    ):
        # The repository's pre-commit pretty-format-json hook sorts keys and indents by
        # two. A refresh written any other way is rewritten, whole, by the first commit
        # that touches it, so the maintainer's diff is not the script's output.
        repo = self._repo(tmp_path)
        artifacts = tmp_path / "artifacts"
        for platform in ("windows-latest", "ubuntu-24.04-arm"):
            self._artifact(
                artifacts,
                f"test-results-{platform}-x86_64-py3.12-unit-shard1of1",
                self.JUNIT,
            )
        out = tmp_path / "out.json"
        done = self._run(repo, artifacts, out)
        assert done.returncode == 0, done.stderr
        written = out.read_text(encoding="utf-8")
        assert (
            written == json.dumps(json.loads(written), indent=2, sort_keys=True) + "\n"
        )

    @pytest.mark.integration
    def test_a_group_with_a_shard_missing_is_skipped_and_the_old_data_kept(
        self, tmp_path
    ):
        repo = self._repo(tmp_path)
        artifacts = tmp_path / "artifacts"
        self._artifact(
            artifacts,
            "test-results-macos-15-arm64-py3.12-unit-shard1of2",
            self.JUNIT,
        )
        self._artifact(
            artifacts,
            "test-results-ubuntu-24.04-arm-arm64-py3.12-unit-shard1of1",
            self.JUNIT,
        )
        out = tmp_path / "out.json"
        out.write_text(
            json.dumps(_timings("macos", "unit", modules={"old.py": 7})),
            encoding="utf-8",
        )
        done = self._run(repo, artifacts, out)
        assert done.returncode == 0, done.stderr
        assert "shards [2] of 2 are missing" in done.stderr
        platforms = json.loads(out.read_text(encoding="utf-8"))["platforms"]
        assert platforms["macos"]["unit"]["modules"] == {"old.py": 7}
        assert "tests/unit/a.py" in platforms["linux"]["unit"]["modules"]

    @pytest.mark.integration
    def test_nothing_to_read_is_a_failure_that_writes_nothing(self, tmp_path):
        out = tmp_path / "out.json"
        done = self._run(self._repo(tmp_path), tmp_path, out)
        assert done.returncode == 2
        assert not out.exists()
