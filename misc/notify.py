# -*- coding: utf-8 -*-

"""
RaTS: Ransomware Traces Scanner
Copyright (C) 2015, 2016, 2017 Roberto Battistoni (r.battistoni@gmail.com)

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

# Import smtplib for the actual sending function
import smtplib

# Import the email modules we'll need
from email.mime.text import MIMEText

from config import config


class MailSender(object):
    def __init__(self):
        self.smtp_host = config.CFG_SMTP_HOST
        self.smtp_port = config.CFG_SMTP_PORT
        self.smtp_user = config.CFG_SMTP_USER
        self.smtp_passwd = config.CFG_SMTP_PWD

    def send_email(self, from_part, to_part, subject, content):
        """
        Send utils from the Python docs...
        :param from_part:
        :param to_part:
        :param subject:
        :param content:
        :return:
        """
        # Open a plain text file for reading.  For this example, assume that
        # the text file contains only ASCII characters.
        msg = MIMEText(content)

        # me == the sender's email address
        # you == the recipient's email address
        msg['Subject'] = subject
        msg['From'] = from_part
        msg['To'] = to_part

        # Send the message via our own SMTP server.
        s = smtplib.SMTP_SSL(host=self.smtp_host, port=self.smtp_port)
        s.login(user=self.smtp_user, password=self.smtp_passwd)
        s.send_message(msg)
        s.quit()
