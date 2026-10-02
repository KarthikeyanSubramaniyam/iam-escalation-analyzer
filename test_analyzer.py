import unittest
from analyzer import analyze

class Cases(unittest.TestCase):
    def test_security_behavior(self):
        self.assertEqual(analyze({"Statement":[{"Effect":"Allow","Action":["iam:PassRole"]}]}), [])
        self.assertEqual(analyze({"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"]}]} )[0]["check"], "PASSROLE_EC2")

if __name__ == "__main__":
    unittest.main()

