import os
import sys
import django

# Set up Django environment
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.contrib.auth.models import User
from monitoring.models import UserProfile, SystemSetting, IOCRule

def seed():
    print("Seeding Sentinel EDR Database...")

    # 1. Create Default Users
    users_data = [
        {"username": "admin", "password": "admin_password_123", "email": "admin@sentinel.local", "role": "admin"},
        {"username": "analyst", "password": "analyst_password_123", "email": "analyst@sentinel.local", "role": "soc_analyst"},
        {"username": "viewer", "password": "viewer_password_123", "email": "viewer@sentinel.local", "role": "viewer"},
        {"username": "agent_user", "password": "agent_password_123", "email": "agent@sentinel.local", "role": "viewer"},
    ]

    for ud in users_data:
        user, created = User.objects.get_or_create(
            username=ud["username"],
            defaults={"email": ud["email"]}
        )
        if created or user.check_password(ud["password"]) is False:
            user.set_password(ud["password"])
            user.save()
        
        # Ensure user profile role matches
        profile = getattr(user, 'profile', None)
        if not profile:
            profile = UserProfile.objects.create(user=user)
        profile.role = ud["role"]
        profile.save()
        print(f"  User '{ud['username']}' configured with role '{ud['role']}'.")

    # 2. Seed Default Settings
    settings_data = [
        {"key": "process_interval", "value": "5", "description": "Polling interval for running processes in seconds."},
        {"key": "service_interval", "value": "10", "description": "Polling interval for Windows services in seconds."},
        {"key": "log_interval", "value": "15", "description": "Polling interval for Windows Event Logs in seconds."},
        {"key": "health_interval", "value": "30", "description": "Polling interval for system health in seconds."},
        {"key": "slack_enable", "value": "false", "description": "Enable or disable Slack alerts integration."},
        {"key": "slack_webhook", "value": "", "description": "Slack Incoming Webhook URL."},
        {"key": "telegram_enable", "value": "false", "description": "Enable or disable Telegram alerts integration."},
        {"key": "telegram_bot_token", "value": "", "description": "Telegram Bot API Token."},
        {"key": "telegram_chat_id", "value": "", "description": "Telegram Chat or Channel ID."},
        {"key": "retention_days", "value": "30", "description": "Log telemetry retention period in days."}
    ]

    for sd in settings_data:
        setting, created = SystemSetting.objects.get_or_create(
            key=sd["key"],
            defaults={"value": sd["value"], "description": sd["description"]}
        )
        if not created and setting.value == "":
            setting.value = sd["value"]
            setting.save()
        print(f"  Setting '{sd['key']}' initialized.")

    # 3. Seed Default IOC rules for demonstration
    iocs = [
        {
            "name": "Mimikatz HackTool Execution",
            "type": "file_name",
            "value": "mimikatz.exe",
            "mitre_technique": "T1003.001",
            "description": "LSASS memory dumping tool used to extract passwords/hashes."
        },
        {
            "name": "Mimikatz SHA256 Signature",
            "type": "hash",
            "value": "a5e8c187bc97df571e2be425e40e698889982425e40e698889982425e40e6988",
            "mitre_technique": "T1003.001",
            "description": "Known signature of mimikatz credential dumping tool."
        },
        {
            "name": "Command Shell execution via Temporary Dir",
            "type": "command_line",
            "value": "AppData\\Local\\Temp",
            "mitre_technique": "T1204.002",
            "description": "Suspicious execution path pointing to system temp directory."
        },
        {
            "name": "Malicious Registry Key RunOnce Persistence",
            "type": "registry_key",
            "value": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\BackdoorSvc",
            "mitre_technique": "T1547.001",
            "description": "Common registry run keys modification for malware persistence."
        }
    ]

    for ioc in iocs:
        rule, created = IOCRule.objects.get_or_create(
            value=ioc["value"],
            type=ioc["type"],
            defaults={
                "name": ioc["name"],
                "mitre_technique": ioc["mitre_technique"],
                "description": ioc["description"]
            }
        )
        print(f"  IOC Rule '{ioc['name']}' ({ioc['type']}) registered.")

    print("Database seeding completed successfully.")

if __name__ == '__main__':
    seed()
