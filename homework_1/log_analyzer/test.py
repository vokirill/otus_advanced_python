import unittest
import utils
import os
import sys


class TestUtils(unittest.TestCase):
    def test_local_path(self):
        path_to_localfolder = utils.get_full_path("./log")
        true_path_to_localfolder = '/Users/kvokhmintsev/Documents/python_professional/python_advance_solutions/homework_1/log_analyzer/log'
        self.assertEqual(path_to_localfolder, true_path_to_localfolder)

    def test_remote_path(self):
        path_to_remotefolder = utils.get_full_path("/Users/kvokhmintsev/log")
        true_path_to_remotefolder = "/Users/kvokhmintsev/log"
        self.assertEqual(path_to_remotefolder, true_path_to_remotefolder)

    def test_date_from_file(self):
        filename = 'nginx-access-ui.log-20170630'
        self.assertEqual(utils.get_log_date(filename), '20170630')
        filename = 'nginx-access-ui.log-20170630.gz'
        self.assertEqual(utils.get_log_date(filename), '20170630')


if __name__ == '__main__':
    unittest.main()
