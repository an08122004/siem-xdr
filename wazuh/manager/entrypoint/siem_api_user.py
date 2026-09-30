"""Tạo / cập nhật user Wazuh API `siem-soar` với quyền TỐI THIỂU cho SOAR của siem-xdr (idempotent).

    python3 siem_api_user.py /run/secrets/wazuh_api_password

Quyền: chạy active response trên agent (`active-response:command`) và đọc danh sách agent (`agent:read`).
Không có quyền đọc/sửa rule, decoder, cấu hình, user... Script tạo user mặc định của image (create_user.py) cấp
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

USER, ROLE = "siem-soar", "siem_soar"
POLICIES = {
    "siem_soar_active_response": {"actions": ["active-response:command"], "resources": ["agent:id:*"],
                                  "effect": "allow"},
    "siem_soar_agents_read": {"actions": ["agent:read"], "resources": ["agent:id:*"], "effect": "allow"},
}
DEFAULT_USERS = ("wazuh", "wazuh-wui")


def random_password() -> str:
    chars = [secrets.choice(string.ascii_letters + string.digits) for _ in range(28)]
    chars += [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase),
              secrets.choice(string.digits), secrets.choice("-._!")]
    return "".join(chars)


def main() -> None:
    password = open(sys.argv[1], encoding="utf-8").read().strip()
    check_database_integrity()

    with PoliciesManager() as pm:
        policy_ids = []
        for name, body in POLICIES.items():
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
        if not isinstance(rm.get_role(ROLE), dict):
            rm.add_role(name=ROLE)
        role_id = rm.get_role(ROLE)["id"]

    with RolesPoliciesManager() as rpm:
        for pid in policy_ids:
            if rpm.exist_role_policy(role_id, pid) is not True:
                rpm.add_policy_to_role(role_id=role_id, policy_id=pid)

    with AuthenticationManager() as auth:
        user = auth.get_user(USER)
        if not user:
            if auth.add_user(USER, password) is not True:
                sys.exit(f"[siem-setup] không tạo được user API {USER}")
            user = auth.get_user(USER)
        else:
            auth.update_user(user["id"], password)
        user_id = user["id"]
        for name in DEFAULT_USERS:
            if (default := auth.get_user(name)):
                auth.update_user(default["id"], random_password())

    with UserRolesManager() as urm:
        if urm.exist_user_role(user_id, role_id) is not True:
            urm.add_role_to_user(user_id=user_id, role_id=role_id)

    print(f"[siem-setup] user API {USER} (role {ROLE}: active response + đọc agent); "
          f"đã vô hiệu hóa {', '.join(DEFAULT_USERS)}")


if __name__ == "__main__":
    main()
