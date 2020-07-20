# -*- coding: utf-8 -*-

"""
RaTS: Ransomware Traces Scanner
Copyright (C) 2015 -> 2020 Roberto Battistoni (r.battistoni@gmail.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

import smtplib
from email.mime.text import MIMEText
from config import config


class MailSender(object):
    def __init__(self):
        self.smtp_host = config.CFG_SMTP_HOST
        self.smtp_port = config.CFG_SMTP_PORT
        self.smtp_user = config.CFG_SMTP_USER
        self.smtp_passwd = config.CFG_SMTP_PWD
        self.smtp_ssl = config.CFG_SMTP_SSL

    def send_email(self, from_part, to_part, subject, content):
        msg = MIMEText(content, _charset='utf-8')

        msg['Subject'] = subject
        msg['From'] = from_part
        msg['To'] = to_part

        if self.smtp_ssl:
            s = smtplib.SMTP_SSL(host=self.smtp_host, port=self.smtp_port)
        else:
            s = smtplib.SMTP(host=self.smtp_host, port=self.smtp_port)

        # s.set_debuglevel(2)
        s.login(user=self.smtp_user, password=self.smtp_passwd)
        s.send_message(msg)
        s.quit()
