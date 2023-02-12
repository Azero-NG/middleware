import pytest

from middlewared.test.integration.assets.account import user, group
from middlewared.test.integration.utils import ssh


@pytest.mark.parametrize("ssh_password_enabled", [True, False])
def test_user_ssh_password_enabled(ssh_password_enabled):
    with user({
        "username": "test",
        "full_name": "Test",
        "group_create": True,
        "home": f"/nonexistent",
        "password": "test1234",
        "ssh_password_enabled": ssh_password_enabled,
    }):
        result = ssh("whoami", check=False, complete_response=True, user="test",
                     password="test1234")
        if ssh_password_enabled:
            assert "test" in result["output"]
        else:
            assert "Permission denied" in result["stderr"]


@pytest.mark.parametrize("ssh_password_enabled", [True, False])
def test_group_ssh_password_enabled(ssh_password_enabled):
    with group({"name": "group1", "ssh_password_enabled": ssh_password_enabled}) as g1:
        with user({
            "username": "test",
            "full_name": "Test",
            "group_create": True,
            "groups": [g1["id"]],
            "home": f"/nonexistent",
            "password": "test1234",
        }):
            result = ssh("whoami", check=False, complete_response=True, user="test",
                         password="test1234")
            if ssh_password_enabled:
                assert "test" in result["output"]
            else:
                assert "Permission denied" in result["stderr"]
