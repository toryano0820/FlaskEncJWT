import smtplib


class Email:
    def __init__(self, send_from):
        self.send_from = send_from

    def send(self, send_to, subject, message):
        smtp_obj = smtplib.SMTP("email")
        smtp_obj.sendmail(self.send_from, [send_to], f"Subject: {subject}\n\n{message}")
        smtp_obj.quit()


email = Email("noreply@neraai.com")


def send_register_confirm(email_address, display_name, code):
    # email.send(
    #     email_address,
    #     "Code Validation Step",
    #     f"Hi {display_name},\n\nhttp://10.24.120.223:8080/member/confirm?code={code}"
    # )
    email.send(
        email_address,
        "Code Validation Step",
        f"Hi {display_name},\n\nWe have received your registration request to our OAuth 2.0 server.\n" +
        "Please go to address below to continue.\n\n" +
        f"http://10.24.120.223:8080/member/confirm?code={code}\n\n" +
        "Thanks.\n\n" +
        "Regards,\n N.Era AI Team\n\n" +
        "(System generated email, do not reply)"
    )
