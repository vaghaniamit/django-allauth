from typing import Optional

from django.http import HttpRequest, HttpResponse

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.internal.flows import password_reset
from allauth.account.internal.flows.code_verification import (
    AbstractCodeVerificationProcess,
)
from allauth.account.internal.flows.email_verification import verify_email_indirectly
from allauth.account.internal.flows.signup import send_unknown_account_mail


PASSWORD_RESET_VERIFICATION_SESSION_KEY = (
    "account_password_reset_verification"  # nosec: B105
)
PHONE_PASSWORD_RESET_VERIFICATION_SESSION_KEY = (
    "account_phone_password_reset_verification"  # nosec: B105
)

class PasswordResetVerificationProcess(AbstractCodeVerificationProcess):
    def __init__(self, request, state, user=None):
        self.request = request
        super().__init__(
            state=state,
            timeout=app_settings.PASSWORD_RESET_BY_CODE_TIMEOUT,
            max_attempts=app_settings.PASSWORD_RESET_BY_CODE_MAX_ATTEMPTS,
            user=user,
        )

    def abort(self):
        self.request.session.pop(PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)

    def confirm_code(self):
        if self.state.get("code_confirmed"):
            return
        self.state["code_confirmed"] = True
        self.persist()
        verify_email_indirectly(self.request, self.user, self.state["email"])

    def finish(self) -> HttpResponse | None:
        self.request.session.pop(PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)
        return password_reset.finalize_password_reset(
            self.request, self.user, email=self.state["email"]
        )

    def persist(self):
        self.request.session[PASSWORD_RESET_VERIFICATION_SESSION_KEY] = self.state

    def send(self):
        adapter = get_adapter()
        email = self.state["email"]
        if not self.user:
            send_unknown_account_mail(self.request, email)
            return
        code = adapter.generate_password_reset_code()
        self.state["code"] = code
        context = {
            "request": self.request,
            "code": self.code,
        }
        adapter.send_mail("account/email/password_reset_code", email, context)

    @classmethod
    def initiate(cls, *, request, user, email: str):
        state = cls.initial_state(user, email)
        process = PasswordResetVerificationProcess(request, state=state, user=user)
        process.send()
        process.persist()
        return process

    @classmethod
    def resume(
        cls, request: HttpRequest
    ) -> Optional["PasswordResetVerificationProcess"]:
        state = request.session.get(PASSWORD_RESET_VERIFICATION_SESSION_KEY)
        if not state:
            return None
        process = PasswordResetVerificationProcess(request, state=state)
        return process.abort_if_invalid()

class PhonePasswordResetVerificationProcess(AbstractCodeVerificationProcess):
    def __init__(self, request, state, user=None):
        self.request = request
        super().__init__(
            state=state,
            timeout=app_settings.PASSWORD_RESET_BY_CODE_TIMEOUT,
            max_attempts=app_settings.PASSWORD_RESET_BY_CODE_MAX_ATTEMPTS,
            user=user,
        )

    def abort(self):
        self.request.session.pop(PHONE_PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)

    def confirm_code(self):
        if self.state.get("code_confirmed"):
            return
        self.state["code_confirmed"] = True
        self.persist()

    def finish(self) -> HttpResponse | None:
        self.request.session.pop(PHONE_PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)
        return password_reset.finalize_password_reset(self.request, self.user)

    def persist(self):
        self.request.session[PHONE_PASSWORD_RESET_VERIFICATION_SESSION_KEY] = self.state

    def send(self):
        adapter = get_adapter()
        phone = self.state["phone"]

        if not self.user:
            # Optional:
            # adapter.send_unknown_account_sms(phone)
            return

        code = adapter.generate_password_reset_code()
        self.state["code"] = code

        # You add this method in your adapter
        adapter.send_password_reset_code_sms(self.user, phone, code)

    @classmethod
    def initiate(cls, *, request, user, phone: str):
        state = cls.initial_state(user, phone)
        state["phone"] = phone
        process = PhonePasswordResetVerificationProcess(
            request,
            state=state,
            user=user,
        )
        process.send()
        process.persist()
        return process

    @classmethod
    def resume(
        cls, request: HttpRequest
    ) -> Optional["PhonePasswordResetVerificationProcess"]:
        state = request.session.get(PHONE_PASSWORD_RESET_VERIFICATION_SESSION_KEY)
        if not state:
            return None
        process = PhonePasswordResetVerificationProcess(request, state=state)
        return process.abort_if_invalid()
