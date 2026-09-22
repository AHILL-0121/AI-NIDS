import pytest

from nids.api import auth
from nids.api.routes import notifications


@pytest.fixture(autouse=True)
def reset_rate_limits() -> None:
    auth.login_limiter._events.clear()
    notifications.test_limiter._events.clear()
