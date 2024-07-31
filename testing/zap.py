import json
import time
from pprint import pprint

import zapv2
from zapv2 import ZAPv2


def zap_spider(zap, target):
    print(f"Spider Test on: {target}")
    scan_id = zap.spider.scan(target)

    while int(zap.spider.status(scan_id)) < 100:
        print(f'Spider progress: {zap.spider.status(scan_id)} %')
        time.sleep(1)

    print('Spider completed')
    print('\n'.join(map(str, zap.spider.results(scan_id))))
    results = zap.spider.full_results(scan_id)


def zap_ajax_spider(zap, target):
    print(f'Ajax Spider target {target}')
    scan_id = zap.ajaxSpider.scan(target)

    timeout = time.time() + 60 * 2  # 2 minutes from now

    while zap.ajaxSpider.status == 'running':
        if time.time() > timeout:
            break
        print('Ajax Spider status: ' + zap.ajaxSpider.status)
        time.sleep(2)

    print('Ajax Spider completed')
    ajax_results = zap.ajaxSpider.results(start=0, count=10)


def zap_alerts(zap, target):
    print(f"Fetching alerts on: {target}")
    st = 0
    pg = 5000
    alert_dict = {}
    alert_count = 0
    alerts = zap.alert.alerts(baseurl=target, start=st, count=pg)
    while len(alerts) > 0:
        print('Reading ' + str(pg) + ' alerts from ' + str(st))
        alert_count += len(alerts)
        for alert in alerts:
            plugin_id = alert.get('pluginId')
            if alert.get('risk') == 'High':
                print(f'[HIGH] {alert.get("description")}')
                continue
            if alert.get('risk') == 'Informational':
                print(f'[INFO] {alert.get("description")}')
                continue
        st += pg
        alerts = zap.alert.alerts(start=st, count=pg)
    print('Total number of alerts: ' + str(alert_count))


def zap_scan(target, api_key):
    local_proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    session_name = target
    zap = ZAPv2(proxies=local_proxy, apikey=api_key)
    core = zap.core
    core.new_session(name=session_name, overwrite=True)
    if 'https://' not in target:
        if "http://" not in target:
            target = "https://" + target
    core.access_url(target)
    time.sleep(2)
    spider = zap.spider
    scan_id = 0
    scan_id = spider.scan(url=target, maxchildren=None, recurse=True,
                          contextname=None, subtreeonly=None)
    time.sleep(2)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(1)

    json_report = core.jsonreport()
    json_report = json.loads(json_report.replace('<p>', '').replace('</p>', ''))
    html_report = core.htmlreport()
    xml_report = core.xmlreport()

    alerts = core.alerts(baseurl=target, start=None, count=None)
    to_pop = ['alertRef', 'attack', 'cweid', 'evidence', 'id', 'inputVector',
              'messageId', 'method', 'name', 'other', 'param', 'pluginId', 'reference',
              'sourceid', 'tags', 'url', 'wascid']
    for alert in alerts:
        for key in to_pop:
            alert.pop(key)
    seen = []
    for alert in alerts:
        if alert not in seen:
            seen.append(alert)
    alerts = seen

    return alerts
    # return json_report, html_report, xml_report
