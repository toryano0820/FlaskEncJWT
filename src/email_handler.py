import smtplib


class Email:
    def __init__(self, send_from):
        self.send_from = send_from

    def send(self, send_to, subject, message):
        smtp_obj = smtplib.SMTP("email")
        smtp_obj.sendmail(self.send_from, [send_to], f"From: {self.send_from}\nTo: {send_to}\nSubject: {subject}\n\n{message}")
        smtp_obj.quit()


email = Email("N.Era AI Code Validator<noreply@neraai.com>")


def send_member_confirm(email_address, display_name, code):
    email.send(
        email_address,
        "Member Registration: Code Validation Step",
        f"Hi {display_name},\n\nWe have received your member registration request to our OAuth 2.0 server.\n" +
        "Please go to address below to continue.\n" +
        f"http://10.24.120.223:8080/member/code/confirm?code={code}\n\n" +
        "Thanks.\n\n\n" +
        "Regards,\nN.Era AI Team\n\n\n" +
        "(System generated email, do not reply)"
    )


def send_client_confirm(email_address, display_name, code):
    email.send(
        email_address,
        "Client Registration: Code Validation Step",
        f"Hi {display_name},\n\nWe have received your client registration request to our OAuth 2.0 server.\n" +
        "Please go to address below to continue.\n" +
        f"http://10.24.120.223:8080/client/code/confirm?code={code}\n\n" +
        "Thanks.\n\n\n" +
        "Regards,\nN.Era AI Team\n\n\n" +
        "(System generated email, do not reply)"
    )
