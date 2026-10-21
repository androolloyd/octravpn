import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('checkpoint', pathlib.Path(__file__).with_name('qualification-checkpoint.py'))
checkpoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checkpoint)


class TestSummaries(unittest.TestCase):
    def test_binary_worker_output_preserves_passing_and_failing_summaries(self):
        raw = (b'\x00\x88worker output\xff\n'
               b'test result: ok. 7 passed; 0 failed; 1 ignored;\n'
               b'\xfe\ntest result: FAILED. 1 passed; 2 failed; 0 ignored;\n')
        self.assertEqual(checkpoint.test_summaries(raw), [(7, 0, 1), (1, 2, 0)])
        self.assertEqual(checkpoint.test_summaries(b'\x00\xffno test summary'), [])


if __name__ == '__main__':
    unittest.main()
