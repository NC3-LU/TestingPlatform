import json
import time

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
    zap = ZAPv2(apikey=api_key)
    if 'https://' not in target:
        if "http://" not in target:
            target = "https://" + target
    zap.core.new_session(name=target, overwrite=True)
    zap.core.load_session(name=target)
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(1)
    json_report = zap.core.jsonreport()
    json_report = json.loads(json_report.replace('<p>', '').replace('</p>', ''))
    with open("./zap.json", "w") as f:
        json.dump(json_report, f, indent=4)
    html_report = zap.core.htmlreport()
    return json_report, html_report
