"""Tạo / cập nhật 2 user Wazuh API với quyền TỐI THIỂU cho SIEM/XDR (idempotent).

    python3 siem_api_user.py /run/secrets/wazuh_api_password /run/secrets/wazuh_rules_api_password

`siem-soar` (SOAR): chạy active response trên agent (`active-response:command`) và đọc danh sách agent (`agent:read`).
`siem-rules` (console, nạp rule): `manager:read` + `manager:restart` (để PUT /manager/analysisd/reload; quyền này cũng
mở restart manager, Wazuh không có quyền hẹp hơn), `rules:read`, `logtest:run`. Không sửa được cấu hình hay user.
Không user nào có quyền sửa rule, decoder, cấu hình, user... Script tạo user mặc định của image (create_user.py) cấp
role administrator nên không dùng. Hai user mặc định `wazuh` / `wazuh-wui` (mật khẩu mặc định công khai) bị đổi
sang mật khẩu ngẫu nhiên không ai biết = vô hiệu hóa.
Chạy bằng python của Wazuh, TRƯỚC khi API khởi động -> dùng thẳng lớp ORM của RBAC (các hàm trong wazuh.security
có decorator kiểm tra quyền của request API, gọi ngoài API bị lỗi).
"""
import json
import secrets
import string
import sys

sys.path.append("/var/ossec/framework")

from wazuh.rbac.orm import (AuthenticationManager, PoliciesManager, RolesManager,  # noqa: E402
                            RolesPoliciesManager, UserRolesManager, check_database_integrity)

# user -> (role, {policy: nội dung})
ACCOUNTS = {
    "siem-soar": ("siem_soar", {
        "siem_soar_active_response": {"actions": ["active-response:command"], "resources": ["agent:id:*"],
                                      "effect": "allow"},
        "siem_soar_agents_read": {"actions": ["agent:read"], "resources": ["agent:id:*"], "effect": "allow"},
    }),
    "siem-rules": ("siem_rules", {
        "siem_rules_manager": {"actions": ["manager:read", "manager:restart"], "resources": ["*:*:*"],
                               "effect": "allow"},
        "siem_rules_read": {"actions": ["rules:read"], "resources": ["rule:file:*"], "effect": "allow"},
        "siem_rules_logtest": {"actions": ["logtest:run"], "resources": ["*:*:*"], "effect": "allow"},
    }),
}
DEFAULT_USERS = ("wazuh", "wazuh-wui")


def random_password() -> str:
    chars = [secrets.choice(string.ascii_letters + string.digits) for _ in range(28)]
    chars += [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase),
              secrets.choice(string.digits), secrets.choice("-._!")]
    return "".join(chars)


def setup(user: str, role: str, policies: dict, password: str) -> None:
    with PoliciesManager() as pm:
        policy_ids = []
        for name, body in policies.items():
            if not isinstance(pm.get_policy(name), dict):
                pm.add_policy(name=name, policy=body)
            found = pm.get_policy(name)
            if isinstance(found, dict):
                policy_ids.append(found["id"])
                continue
            # Wazuh không cho 2 policy trùng nội dung: dùng lại policy mặc định có đúng nội dung này
            same = [p.id for p in pm.get_policies() if json.loads(p.policy) == body]
            if not same:
                sys.exit(f"[siem-setup] không tạo được policy {name}")
            policy_ids.append(same[0])

    with RolesManager() as rm:
        if not isinstance(rm.get_role(role), dict):
            rm.add_role(name=role)
        role_id = rm.get_role(role)["id"]

    with RolesPoliciesManager() as rpm:
        for pid in policy_ids:
            if rpm.exist_role_policy(role_id, pid) is not True:
                rpm.add_policy_to_role(role_id=role_id, policy_id=pid)

    with AuthenticationManager() as auth:
        found = auth.get_user(user)
        if not found:
            if auth.add_user(user, password) is not True:
                sys.exit(f"[siem-setup] không tạo được user API {user}")
            found = auth.get_user(user)
        else:
            auth.update_user(found["id"], password)
        user_id = found["id"]

    with UserRolesManager() as urm:
        if urm.exist_user_role(user_id, role_id) is not True:
            urm.add_role_to_user(user_id=user_id, role_id=role_id)
    print(f"[siem-setup] user API {user} (role {role}: {', '.join(policies)})")


def main() -> None:
    check_database_integrity()
    for (user, (role, policies)), pw_file in zip(ACCOUNTS.items(), sys.argv[1:]):
        setup(user, role, policies, open(pw_file, encoding="utf-8").read().strip())
    with AuthenticationManager() as auth:
        for name in DEFAULT_USERS:
            if (default := auth.get_user(name)):
                auth.update_user(default["id"], random_password())
    print(f"[siem-setup] đã vô hiệu hóa {', '.join(DEFAULT_USERS)}")


if __name__ == "__main__":
    main()
