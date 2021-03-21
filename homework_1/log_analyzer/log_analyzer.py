#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import json
import logging
import re
import gzip
from datetime import datetime
import statistics as stat
from string import Template
import datetime


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

FILE_PATTERN = re.compile(r'nginx-access-ui.log-(\d{8})\d*')
LOG_LINE_PATTERN = re.compile(r"\"[A-Z]+ ([^\s]+) .* (\d+\.\d+)\n")

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "WORK_LOG_DIR": None,
    "ERROR_MAX_PERCENT": 100
}

def get_full_path(location: str) -> str:
    if location.startswith('./'):
        return os.path.join(os.path.abspath(os.getcwd()), location[2:])
    else:
        return location

def parse_config(config_path:str):
    config = {}
    with open(config_path, 'r') as f:
        data = json.load(f)
    if type(data) == dict:
        for key in data.keys():
            config[key] = data[key]
    return config  


def select_file(location: str, pattern=FILE_PATTERN):
    file_list = os.listdir(location)
    mathcing_result = [(elem, pattern.match(elem)) for elem in file_list if pattern.match(elem)]
    if not mathcing_result:
        return None
    max_date = ''
    last_log_file = ''
    for elem in mathcing_result:
        current_date = elem[1][1]
        if current_date > max_date:
            max_date = current_date
            last_log_file = elem[0]
    return last_log_file, max_date


def parse_log_line(line: str, log_pattern=LOG_LINE_PATTERN) -> dict:

    log_info = {'url': '', 'is_error': True, 'request_time': 0}

    parsed_line = re.findall(log_pattern, line)

    if not parsed_line:
        return log_info

    log_info['url'] = parsed_line[0][0]
    log_info['request_time'] = float(parsed_line[0][1])

    if log_info['url'] and log_info['request_time']:
        log_info['is_error'] = False

    return log_info


def count_statistics(logdir_path: str, log_file: str, config: dict) -> dict:
    if log_file.endswith(".gz"):
        log_file = gzip.open(os.path.join(logdir_path, log_file))
    else:
        log_file = open(os.path.join(logdir_path, log_file), encoding='UTF-8')
        pass
    statistics = {}
    median_data = {}
    error_lines = 0
    for i, line in enumerate(log_file.readlines()):
        line = line.decode('utf-8')
        parse_info = parse_log_line(line)
        if parse_info['is_error']:
            error_lines += 1
        else:
            if parse_info['url'] not in statistics.keys():
                statistics[parse_info['url']] = [
                    1, parse_info['request_time'], parse_info['request_time']]
                median_data[parse_info['url']] = [parse_info['request_time']]
            else:
                statistics[parse_info['url']][0] += 1
                statistics[parse_info['url']][1] += parse_info['request_time']
                if statistics[parse_info['url']][2] < parse_info['request_time']:
                    statistics[parse_info['url']
                               ][2] = parse_info['request_time']
                median_data[parse_info['url']].append(
                    parse_info['request_time'])

    if 100.0*error_lines/(i+1) > config["ERROR_MAX_PERCENT"]:
        log_msg = "share of bad lines exceeded"
        logging.info(log_msg)
        raise Exception(log_msg)

    statistics_values = list(statistics.values())
    count = sum([elem[0] for elem in statistics_values])
    time = sum([elem[1] for elem in statistics_values])
    for key in statistics.keys():
        statistics[key].append(100.0*statistics[key][0]/count)
        statistics[key].append(100.0*statistics[key][1]/time)
        statistics[key].append(statistics[key][1]/statistics[key][0])
        statistics[key].append(stat.median(median_data[key]))
    most_common = dict(sorted(list(statistics.items()), reverse=True,
                              key=lambda x: x[1][1])[0:config["REPORT_SIZE"]])
    return most_common


def format_statistics(statistics: dict) -> list:
    formated_statistics = []
    for key in statistics.keys():
        elem = {"url": key,
                "count": statistics[key][0],
                "count_perc": statistics[key][3],
                "time_avg": statistics[key][5],
                "time_max": statistics[key][2],
                "time_med": statistics[key][6],
                "time_perc": statistics[key][4],
                "time_sum": statistics[key][1]}
        formated_statistics.append(elem)
    return formated_statistics


def render_html(path_to_report_template: str, statistics: list, date: str, reportdir_path: str):
    with open(path_to_report_template, 'r') as report_template:
        data = report_template.read()
    template = Template(data)
    res = template.safe_substitute(table_json=str(statistics))
    filename = 'report-{}.{}.{}.html'.format(date[0:4], date[4:6], date[6:])
    path = os.path.join(reportdir_path, filename)
    with open(path, 'w') as f:
        f.write(res)


def set_logging(log_dir):

    log_file = None

    if log_dir and os.access(log_dir, os.W_OK):
        log_file_name = datetime.now().strftime(
            "log_analyzer.log"
        )
        log_file = os.path.join(log_dir, log_file_name)

    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='[%(asctime)s] %(levelname).1s %(message)s',
        datefmt='%Y.%m.%d %H:%M:%S',
    )


def main(config):
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--config", nargs='?', default='config.txt', help="store path to config file")
        args = parser.parse_args()
        config_path = args.config
        
        if config_path:
            config = parse_config(config_path)
            
        if config["WORK_LOG_DIR"]:
            work_log_dir = get_full_path(config["WORK_LOG_DIR"])
        else:
            work_log_dir = None
        set_logging(work_log_dir)

        logdir_path = get_full_path(config['LOG_DIR'])
        reportdir_path = get_full_path(config['REPORT_DIR'])
        log_file, report_date = select_file(logdir_path)

        if not log_file:
            loggin.info('no suitable file')
            return None

        report_date = datetime.date(int(report_date[0:4]),int(report_date[4:6]), int(report_date[6:]))
        report_date = datetime.datetime.strftime(report_date, "%Y-%m-%d")
        report_filename = 'report-{}.html'.format(report_date)

        if os.path.exists(os.path.join(reportdir_path, report_filename )):
            logging.info('report already formed')
            return None
            
        statistics = count_statistics(logdir_path, log_file, config)
        formated_statistics = format_statistics(statistics)
        _ = render_html(
        'report.html', formated_statistics, report_date, reportdir_path)
        logging.info('parsed succesfully.')
        
    except Exception as ex:
        raise


if __name__ == "__main__":
    main(config)
