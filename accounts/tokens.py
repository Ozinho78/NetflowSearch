from django.contrib.auth.tokens import PasswordResetTokenGenerator


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    """Token für die Kontoaktivierung.

    Erbt Signatur (HMAC mit SECRET_KEY) und Ablaufprüfung vom
    Passwort-Reset, hasht aber einen anderen Zustand.
    """

    # Eigenes Salt: ein Passwort-Reset-Token ist hier NICHT gültig und umgekehrt
    key_salt = "accounts.tokens.AccountActivationTokenGenerator"

    def _make_hash_value(self, user, timestamp):
        # Ändert sich einer dieser Werte, wird der Token ungültig.
        # is_active False -> True  => Link nach erfolgreicher Aktivierung tot
        return f"{user.pk}{user.is_active}{user.email}{timestamp}"


account_activation_token = AccountActivationTokenGenerator()
