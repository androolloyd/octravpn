#!/usr/bin/env python3
"""Freshness/aggregation regressions; no Docker, public RPC, VHS or media tools."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("ci_recordings", Path(__file__).with_name("ci_recordings.py"))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class RecordingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "demo/tapes").mkdir(parents=True)
        (self.root / "demo/recordings").mkdir()
        self.tape = "demo/tapes/01-fixture.tape"
        (self.root / self.tape).write_text(
            "Output demo/recordings/01-fixture.gif\nOutput demo/recordings/01-fixture.mp4\n")
        self.stage = self.root / "artifacts/demo-recordings-h1"
        ci.initialize(self.stage, "h1", [self.tape], "commit", "run")

    def fresh(self, command, *, cwd, check):
        self.assertEqual(cwd, self.root)
        self.assertTrue(check)
        if command[0] == "vhs":
            for path in ci.outputs(self.root, self.tape):
                path.write_bytes(b"fresh fixture output")

    def render(self):
        with patch.object(ci.subprocess, "run", side_effect=self.fresh):
            self.assertTrue(ci.render(self.root, self.stage, self.tape, False))
        self.assertTrue(ci.finalize(self.stage))

    def test_zero_exit_without_outputs_cannot_reuse_tracked_media(self):
        for path in ci.outputs(self.root, self.tape):
            path.write_bytes(b"old tracked output")
        with patch.object(ci.subprocess, "run"):
            self.assertFalse(ci.render(self.root, self.stage, self.tape, False))
        self.assertFalse(ci.finalize(self.stage))
        self.assertEqual(list(self.stage.iterdir()), [self.stage / ci.MANIFEST])

    def test_failed_preflight_never_invokes_renderer(self):
        with patch.object(ci.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "preflight")) as run:
            self.assertFalse(ci.render(self.root, self.stage, self.tape, False))
        self.assertEqual(run.call_count, 1)
        self.assertFalse(ci.finalize(self.stage))

    def test_only_fresh_assigned_outputs_and_caption_source_are_staged(self):
        recordings = self.root / "demo/recordings"
        (recordings / "01-fixture.vtt").write_text("WEBVTT\n")
        (recordings / "01-fixture-captioned.mp4").write_bytes(b"old derivative")
        (recordings / "02-other.gif").write_bytes(b"other group's old video")
        self.render()
        state = ci.verified(self.stage, "commit", "run")
        self.assertEqual(set(state["files"]), {"01-fixture.gif", "01-fixture.mp4", "01-fixture.vtt"})
        self.assertEqual((self.stage / "01-fixture.mp4").read_bytes(), b"fresh fixture output")

    def test_tampered_or_wrong_run_artifact_is_rejected_before_publication(self):
        self.render()
        with self.assertRaisesRegex(ValueError, "run/commit"):
            ci.publish(self.root, self.stage, "commit", "another run")
        (self.stage / "01-fixture.mp4").write_bytes(b"stale replacement")
        with self.assertRaisesRegex(ValueError, "hash differs"):
            ci.publish(self.root, self.stage, "commit", "run")

    def test_postprocessing_failure_cannot_be_published(self):
        self.render()
        self.assertFalse(ci.finalize(self.stage, True))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            ci.publish(self.root, self.stage, "commit", "run")

    def test_duplicate_groups_cannot_overwrite_fresh_recordings(self):
        self.render()
        other = self.stage.parent / "demo-recordings-h2"
        ci.initialize(other, "h2", [self.tape], "commit", "run")
        with patch.object(ci.subprocess, "run", side_effect=self.fresh):
            self.assertTrue(ci.render(self.root, other, self.tape, False))
        self.assertTrue(ci.finalize(other))
        with self.assertRaisesRegex(ValueError, "overlapping"):
            ci.merge(self.stage.parent, self.root / "merged", ["h1", "h2"], "commit", "run")
        self.assertFalse((self.root / "merged").exists())

    def test_missing_group_or_unlisted_file_is_not_accepted(self):
        self.render()
        with self.assertRaisesRegex(ValueError, "manifest is missing"):
            ci.merge(self.stage.parent, self.root / "merged", ["h1", "h2"], "commit", "run")
        (self.stage / "02-other.gif").write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "files differ"):
            ci.verified(self.stage, "commit", "run")

    def test_escaping_output_is_refused_without_deleting_anything(self):
        sentinel = self.root / "do-not-delete.mp4"
        sentinel.write_bytes(b"keep")
        (self.root / self.tape).write_text("Output ../../do-not-delete.mp4\n")
        with self.assertRaisesRegex(ValueError, "own GIF and MP4"):
            ci.render(self.root, self.stage, self.tape, False)
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_merge_preserves_disjoint_group_hashes(self):
        self.render()
        second = "demo/tapes/02-second.tape"
        (self.root / second).write_text(
            "Output demo/recordings/02-second.gif\nOutput demo/recordings/02-second.mp4\n")
        stage = self.stage.parent / "demo-recordings-h2"
        ci.initialize(stage, "h2", [second], "commit", "run")
        def render_second(command, *, cwd, check):
            if command[0] == "vhs":
                for path in ci.outputs(self.root, second):
                    path.write_bytes(b"second fresh output")
        with patch.object(ci.subprocess, "run", side_effect=render_second):
            self.assertTrue(ci.render(self.root, stage, second, False))
        self.assertTrue(ci.finalize(stage))
        merged = self.root / "merged"
        ci.merge(self.stage.parent, merged, ["h1", "h2"], "commit", "run")
        state = ci.verified(merged, "commit", "run")
        self.assertEqual(len(state["files"]), 4)
        self.assertEqual(len(state["completed"]), 2)
        self.assertEqual(json.loads((merged / ci.MANIFEST).read_text())["group"], "heavy")


if __name__ == "__main__":
    unittest.main()
