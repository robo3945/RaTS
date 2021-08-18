# -*- coding: utf-8 -*-

import smtplib
import ssl
from distutils.util import strtobool
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import config


class MailSender(object):
    def __init__(self):
        self.smtp_host = config.CFG_SMTP_HOST
        self.smtp_port = config.CFG_SMTP_PORT
        self.smtp_user = config.CFG_SMTP_USER
        self.smtp_passwd = config.CFG_SMTP_PWD
        self.smtp_ssl = strtobool(config.CFG_SMTP_SSL)

    def send_email(self, from_part, to_part, subject, content, filename: str):
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = from_part
        msg['To'] = to_part

        context = ssl.create_default_context()

        if self.smtp_ssl:
            s = smtplib.SMTP_SSL(host=self.smtp_host, port=self.smtp_port, context = context)
        else:
            s = smtplib.SMTP(host=self.smtp_host, port=self.smtp_port)

        # s.set_debuglevel(2)
        s.login(user=self.smtp_user, password=self.smtp_passwd)
        attachment = MIMEText(content, _charset='utf-8')
        attachment.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(attachment)
        s.send_message(msg)
        s.quit()
