#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import buslogic
import argparse
import json
import logging


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "WORK_LOG_DIR": None,
    "ERROR_MAX_PERCENT": 100
}


def main(config):
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--config", nargs='?', const='config.txt', help="store path to config file")
        args = parser.parse_args()
        config_path = args.config
        
        if config_path:
            config = buslogic.parse_config(config_path)
            
        if config["WORK_LOG_DIR"]:
            work_log_dir = buslogic.get_full_path(config["WORK_LOG_DIR"])
        else:
            work_log_dir = None
        buslogic.set_logging(work_log_dir)

        logdir_path = buslogic.get_full_path(config['LOG_DIR'])
        reportdir_path = buslogic.get_full_path(config['REPORT_DIR'])
        log_file, report_date = buslogic.select_file(logdir_path)

        if log_file:
            report_filename = 'report-{}.{}.{}.html'.format(
                report_date[0:4], report_date[4:6], report_date[6:])
            if report_filename in os.listdir(reportdir_path):
                logging.info('report already formed')
                pass
            else:
                statistics = buslogic.count_statistics(logdir_path, log_file, config)
                formated_statistics = buslogic.statistics_formatting(statistics)
                _ = buslogic.html_rendering(
                    'report.html', formated_statistics, report_date, reportdir_path)
                logging.info('parsed succesfully.')
        else:
            loggin.info('no suitable file')
    except Exception as ex:
        msg = "{0}: {1}".format(type(ex).__name__, ex)
        logging.exception(msg, exc_info=True)
        raise


if __name__ == "__main__":
    main(config)
