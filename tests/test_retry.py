import unittest

from url_reputation.retry import RetryPolicy, retry_call


class TestRetry(unittest.TestCase):
    def test_retries_then_succeeds(self):
        state = {"n": 0}

        def fn():
            state["n"] += 1
            if state["n"] < 3:
                raise RuntimeError("timeout")
            return 42

        out = retry_call(
            fn,
            policy=RetryPolicy(retries=3, base_delay_seconds=0.0, max_delay_seconds=0.0, jitter=0.0),
            should_retry=lambda e: True,
        )
        self.assertEqual(out, 42)
        self.assertEqual(state["n"], 3)

    def test_does_not_retry_when_predicate_false(self):
        state = {"n": 0}

        def fn():
            state["n"] += 1
            raise RuntimeError("nope")

        with self.assertRaises(RuntimeError):
            retry_call(
                fn,
                policy=RetryPolicy(retries=3, base_delay_seconds=0.0, max_delay_seconds=0.0, jitter=0.0),
                should_retry=lambda e: False,
            )

        self.assertEqual(state["n"], 1)


if __name__ == "__main__":
    unittest.main()
