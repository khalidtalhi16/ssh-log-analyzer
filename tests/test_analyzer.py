import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from log_analyzer import parse_log, analyze

def fail(sec, ip="203.0.113.9", user="root"):
    return f"Nov 20 03:00:{sec:02d} host sshd[1]: Failed password for {user} from {ip} port 5000 ssh2"

class TestAnalyzer(unittest.TestCase):
    def test_parses_failed_and_accepted(self):
        lines = [fail(1), "Nov 20 03:01:00 host sshd[2]: Accepted password for bob from 192.0.2.1 port 22 ssh2"]
        ev = parse_log(lines, 2026)
        self.assertEqual([e.kind for e in ev], ["failed", "accepted"])

    def test_ignores_garbage(self):
        self.assertEqual(parse_log(["hello world", ""], 2026), [])

    def test_detects_brute_force(self):
        ev = parse_log([fail(s) for s in range(1, 8)], 2026)
        self.assertEqual(analyze(ev)[0].type, "BRUTE_FORCE")

    def test_slow_attempts_not_flagged(self):
        lines = [f"Nov 20 0{h}:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2" for h in range(1, 8)]
        self.assertEqual(analyze(parse_log(lines, 2026)), [])

    def test_detects_compromise(self):
        lines = [fail(s) for s in range(1, 8)]
        lines.append("Nov 20 03:00:20 host sshd[2]: Accepted password for root from 203.0.113.9 port 22 ssh2")
        types = [f.type for f in analyze(parse_log(lines, 2026))]
        self.assertIn("POSSIBLE_COMPROMISE", types)

    def test_detects_spraying(self):
        lines = [fail(i, user=f"user{i}") for i in range(1, 7)]
        types = [f.type for f in analyze(parse_log(lines, 2026), threshold=100)]
        self.assertIn("USERNAME_SPRAYING", types)

if __name__ == "__main__":
    unittest.main()
