# -*- coding: utf-8 -*-

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
