import unittest
import tempfile
from pathlib import Path

from analyzer import add_suspicious_ips, analyze_logs

class TestingAddSuspiciousIps(unittest.TestCase):
    def test_ip_at_threshold_is_suspicious(self):
        #Arrange stage
        login_attempts = {
           "10.0.0.5": {
               "failed_login": 5,
               "successful_login": 1
           },
           "10.0.0.8": {
               "failed_login": 4,
               "successful_login": 2
           } 
        }

        threshold = 5
        expected_results = {"10.0.0.5": 5}

        #Act stage
        actual_results = add_suspicious_ips(login_attempts, threshold)

        #Assert stage
        self.assertEqual(actual_results, expected_results)

    def test_ip_below_threshold_not_susicious(self):
        #Arrange stage
        login_attempts = {
            "10.0.0.5": {
                "failed_login": 4,
                "successful_login": 1
            }
        }

        threshold = 5
        expected_results = {}

        #Act stage
        actual_results = add_suspicious_ips(login_attempts, threshold)

        #Assert stage
        self.assertEqual(actual_results, expected_results)

    def test_multiple_suspicious_ips(self):
        #Arrange stage
        login_attempts = {
            "10.0.0.5" : {
                "failed_login": 8,
                "successful_login": 3
            },

            "10.0.0.8" : {
                "failed_login": 6,
                "successful_login": 4
            },

            "10.0.0.10" : {
                "failed_login": 3,
                "successful_login": 5
            }
        }

        threshold = 5
        expected_results = {
            "10.0.0.5": 8,
            "10.0.0.8": 6
        }

        #Act stage
        actual_results = add_suspicious_ips(login_attempts, threshold)

        #Assert stage
        self.assertEqual(actual_results, expected_results)

class TestAnalyzeLogs(unittest.TestCase):
    #Arrange stage
    def test_failed_and_suuccessful_login_counts(self):
        sample_logs = (
            "10.0.0.5 LOGIN_FAILED\n"
            "10.0.0.5 LOGIN_FAILED\n"
            "10.0.0.5 LOGIN_SUCCESS\n"
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            test_log_path = Path(temporary_directory) / "sample_logs.txt"

            test_log_path.write_text(
                sample_logs,
                encoding="utf-8"
            )

            expected_results = {
                "10.0.0.5":{
                    "failed_login": 2,
                    "successful_login": 1
                }
            }

            #Act stage
            actual_results = analyze_logs(test_log_path)

            #Asset stage
            self.assertEqual(actual_results, expected_results)

    def test_empty_log_file(self):
            #Arrange stage
            sample_logs = ""

            with tempfile.TemporaryDirectory() as temporary_directory:
                test_log_path = Path(temporary_directory) / "empty_logs.txt"
    
                test_log_path.write_text(
                    sample_logs,
                    encoding="utf-8"
                )

                expected_results = {}

                #Act stage    
                actual_results = analyze_logs(test_log_path)

                #Assert stage
                self.assertEqual(actual_results, expected_results)

    def test_separated_login_ounts_with_multiple_ips(self):
                #Arrange stage
                sample_logs = (
                    "10.0.0.5 LOGIN_FAILED\n"
                    "10.0.0.8 LOGIN_FAILED\n"
                    "10.0.0.5 LOGIN_SUCCESS\n"
                    "10.0.0.8 LOGIN_SUCCESS\n"
                )
        
                with tempfile.TemporaryDirectory() as temporary_directory:
                    test_log_path = Path(temporary_directory) / "multiple_counts_ips.txt"
        
                    test_log_path.write_text(
                        sample_logs,
                        encoding="utf-8"
                    )
        
                    expected_results = {
                        "10.0.0.5":{
                            "failed_login": 1,
                            "successful_login": 1
                        },
                        "10.0.0.8":{
                            "failed_login": 1,
                            "successful_login": 1
                        }
                    }

                    #Act stage
                    actual_results = analyze_logs(test_log_path)

                    #Assert stage
                    self.assertEqual(actual_results, expected_results)

    def test_invalid_entries_skipped(self):
            #Arrange stage
            sample_logs = (
                "10.0.0.5 LOGIN_FAILED\n"
                "INVALID_LINE\n"
                "\n"
                "10.0.0.5 LOGIN_SUCCESS\n"
                "10.0.0.8 PASSWORD_CHANGED"
            )
    
            with tempfile.TemporaryDirectory() as temporary_directory:
                test_log_path = Path(temporary_directory) / "invalid_entries.txt"
    
                test_log_path.write_text(
                    sample_logs,
                    encoding="utf-8"
                )
    
                expected_results = {
                    "10.0.0.5":{
                        "failed_login": 1,
                        "successful_login": 1
                    }
                }

                #Act stage
                actual_results = analyze_logs(test_log_path)

                #Assert stage
                self.assertEqual(actual_results, expected_results)

if __name__ == "__main__":
    unittest.main()