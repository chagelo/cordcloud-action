import base64
import hashlib
import json
import re
from typing import Tuple

import requests
import urllib3

urllib3.disable_warnings()


class Action:
    def __init__(self, email: str, passwd: str, code: str = '', host: str = 'cordcloud.us'):
        self.email = email
        self.passwd = passwd
        self.code = code
        self.host = host.replace('https://', '').replace('http://', '').strip()
        self.session = requests.session()
        self.timeout = 6

    def format_url(self, path) -> str:
        return f'https://{self.host}/{path}'

    def _parse_login_page(self, url: str) -> dict:
        html = self.session.get(url, timeout=self.timeout, verify=False).text
        result = {'csrf_token': '', 'altcha': ''}

        # 提取 csrf_token
        match = re.search(r'<input[^>]+name="csrf_token"[^>]+value="([^"]*)"', html)
        if not match:
            match = re.search(r'<input[^>]+value="([^"]*)"[^>]+name="csrf_token"', html)
        if match:
            result['csrf_token'] = match.group(1)

        # 提取 altcha challengeurl 并求解
        match = re.search(r'challengeurl="([^"]*)"', html)
        if match:
            challenge_url = match.group(1)
            if not challenge_url.startswith('http'):
                challenge_url = self.format_url(challenge_url.lstrip('/'))
            result['altcha'] = self._solve_altcha(challenge_url)

        return result

    def _solve_altcha(self, challenge_url: str) -> str:
        resp = self.session.get(challenge_url, timeout=self.timeout, verify=False)
        challenge_data = resp.json()

        algorithm = challenge_data.get('algorithm', 'SHA-256')
        challenge = challenge_data['challenge']
        salt = challenge_data['salt']
        max_number = challenge_data.get('maxnumber', 1000000)
        signature = challenge_data.get('signature', '')

        for number in range(max_number + 1):
            hash_input = f'{salt}{number}'
            if algorithm == 'SHA-256':
                hash_result = hashlib.sha256(hash_input.encode()).hexdigest()
            elif algorithm == 'SHA-384':
                hash_result = hashlib.sha384(hash_input.encode()).hexdigest()
            elif algorithm == 'SHA-512':
                hash_result = hashlib.sha512(hash_input.encode()).hexdigest()
            else:
                hash_result = hashlib.sha256(hash_input.encode()).hexdigest()

            if hash_result == challenge:
                solution = {
                    'algorithm': algorithm,
                    'challenge': challenge,
                    'number': number,
                    'salt': salt,
                    'signature': signature
                }
                return base64.b64encode(json.dumps(solution).encode()).decode()

        return ''

    def login(self) -> dict:
        login_url = self.format_url('auth/login')
        page_data = self._parse_login_page(login_url)
        form_data = {
            'email': self.email,
            'passwd': self.passwd,
            'code': self.code,
            'csrf_token': page_data['csrf_token'],
            'altcha': page_data['altcha']
        }
        return self.session.post(login_url, data=form_data,
                                 timeout=self.timeout, verify=False).json()

    def check_in(self) -> dict:
        check_in_url = self.format_url('user/checkin')
        return self.session.post(check_in_url, timeout=self.timeout, verify=False).json()

    def info(self) -> Tuple:
        user_url = self.format_url('user')
        html = self.session.get(user_url, verify=False).text
        today_used = re.search('<span class="traffic-info">今日已用</span>(.*?)<code class="card-tag tag-red">(.*?)</code>',
                               html,
                               re.S)
        total_used = re.search(
            '<span class="traffic-info">过去已用</span>(.*?)<code class="card-tag tag-orange">(.*?)</code>',
            html, re.S)
        rest = re.search(
            '<span class="traffic-info">剩余流量</span>(.*?)<code class="card-tag tag-green" id="remain">(.*?)</code>',
            html, re.S)
        if today_used and total_used and rest:
            return today_used.group(2), total_used.group(2), rest.group(2)
        return ()

    def run(self):
        self.login()
        self.check_in()
        self.info()
