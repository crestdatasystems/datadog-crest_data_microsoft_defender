# Copyright (C) 2025 Crest Data.
# All rights reserved
import os
import platform
import subprocess
import sys
import time
import webbrowser


def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


try:
    import requests
except ImportError:
    install("requests")
    import requests

try:
    from azure.identity import AuthenticationRequiredError, InteractiveBrowserCredential
except ImportError:
    install("azure-identity")
    from azure.identity import AuthenticationRequiredError, InteractiveBrowserCredential

# ANSI escape codes for text formatting
GREEN = "\033[92m"
BOLD_GREEN = "\033[1;92m"
RED = "\033[91m"
YELLOW = "\033[33m"
BRIGHT_YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
ENDC = "\033[0m"

GRAPH_API = "https://graph.microsoft.com/v1.0"


# API Permissions to Assign
PERMISSIONS = {
    # Microsoft Graph Permissions
    "00000003-0000-0000-c000-000000000000": [
        {
            "id": "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5",
            "type": "Role",
        },  # SecurityAlert.Read.All
        {
            "id": "45cc0394-e837-488b-a098-1918f48d186c",
            "type": "Role",
        },  # SecurityIncident.Read.All
        {
            "id": "bf394140-e372-4bf9-a898-299cfc7564e5",
            "type": "Role",
        },  # SecurityEvents.Read.All
        {
            "id": "dd98c7f5-2d42-42d3-a0e4-633161547251",
            "type": "Role",
        },  # ThreatHunting.Read.All
        {
            "id": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
            "type": "Role",
        },  # Directory.Read.All
        {"id": "df021288-bdef-4463-88db-98f22de89214", "type": "Role"},  # User.Read.All
    ],
    # WindowsDefenderATP Permissions
    "fc780465-2017-40d4-a0c5-307022471b92": [
        {
            "id": "41269fc5-d04d-4bfd-bce7-43a51cea049a",
            "type": "Role",
        },  # Vulnerability.Read.All
        {
            "id": "02b005dd-f804-43b4-8fc7-078460413f74",
            "type": "Role",
        },  # Score.Read.All
        {
            "id": "37f71c98-d198-41ae-964d-2c49aab74926",
            "type": "Role",
        },  # Software.Read.All
        {
            "id": "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79",
            "type": "Role",
        },  # Machine.Read.All
        {
            "id": "71fe6b80-7034-4028-9ed8-0f316df9c3ff",
            "type": "Role",
        },  # Alert.Read.All
    ],
}


def get_access_token(tenant_id):
    """Authenticate and return the access token"""
    credential = InteractiveBrowserCredential(tenant_id=tenant_id)
    token = credential.get_token("https://graph.microsoft.com/.default").token
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def create_application(headers):
    """Create a new application and return app_id and object_id"""
    app_name = "datadog-ms-defender-365"
    print(f"Creating application: '{app_name}'...")
    app_data = {
        "displayName": app_name,
        "signInAudience": "AzureADandPersonalMicrosoftAccount",
    }
    response = requests.post(
        f"{GRAPH_API}/applications", headers=headers, json=app_data
    )

    if response.status_code == 201:
        app_info = response.json()
        return app_info["appId"], app_info["id"], app_info["displayName"]
    else:
        print(
            f"{RED}Error creating application: {response.status_code}, {response.text}{ENDC}"
        )
        exit(1)


def grant_permissions(headers, object_id):
    """Assign required permissions to the application"""
    print("Assigning permissions...")
    required_access = [
        {"resourceAppId": app_id, "resourceAccess": permissions}
        for app_id, permissions in PERMISSIONS.items()
    ]

    permission_data = {"requiredResourceAccess": required_access}

    url = f"{GRAPH_API}/applications/{object_id}"
    response = requests.patch(url, headers=headers, json=permission_data)

    if response.status_code == 204:
        print(f"{GREEN}Permissions assigned successfully.{ENDC}")
    else:
        print(
            f"{RED}Error assigning permissions: {response.status_code}, {response.text}{ENDC}"
        )
        exit(1)


def grant_admin_consent_uri(app_id, tenant_id):
    """Print the URL to grant admin consent for the application."""
    print("Granting admin consent...")
    consent_request_url = (
        f"https://login.microsoftonline.com/{tenant_id}/adminconsent?client_id={app_id}"
    )

    print("Redirecting to browser for admin consent...")
    time.sleep(2)
    webbrowser.open(consent_request_url)

    # Wait for user confirmation
    input(f"{BLUE}Press Enter after confirming admin consent has been granted...{ENDC}")


def generate_client_secret(headers, object_id):
    url = f"{GRAPH_API}/applications/{object_id}/addPassword"
    password_description = "defender365"

    print("Generating client secret...")

    # Prepare the JSON payload
    payload = {"passwordCredential": {"displayName": password_description}}

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        client_secret = response.json()["secretText"]
        print(
            f"{MAGENTA}Note this client secret for future use, it will not be shown again.{ENDC}"
        )
        print(f"{MAGENTA}Client Secret: {client_secret}{ENDC}")
        return client_secret
    else:
        print(
            f"{RED}Error generating client secret: {response.status_code}, {response.text}{ENDC}"
        )
        exit(1)


def install_datadog_api_client():
    os_name = platform.system()
    base_command = f'"{sys.executable}" -m pip install "datadog-api-client>=2.16.0"'
    if os_name == "Darwin":
        command = f"sudo {base_command}"
    elif os_name == "Linux":
        command = f"sudo -Hu dd-agent {base_command}"
    else:
        command = base_command

    try:
        print("Installing datadog-api-client library...")
        command = f'"{sys.executable}" -m pip install "datadog-api-client>=2.16.0"'
        subprocess.run(command, check=True, shell=True)
        print(f"{GREEN}datadog-api-client installed successfully!{ENDC}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing datadog-api-client: {e}")


def main():
    # Enable ANSI escape codes on Windows
    if platform.system() == "Windows":
        os.system("")

    # Get user input for tenant_id and app_name
    TENANT_ID = input(f"{CYAN}Enter your Azure Tenant ID: {ENDC}").strip()

    print("Redirecting to browser for authentication...")
    time.sleep(2)
    try:
        headers = get_access_token(TENANT_ID)
    except AuthenticationRequiredError:
        print(
            "Authentication failed. Please ensure the account belongs to the specified tenant."
        )
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    # Create Application
    app_id, object_id, app_name = create_application(headers)
    print(
        f'{GREEN}Application "{app_name}" created successfully.{ENDC}'
        f"\n{CYAN}Application (client) ID:{ENDC} {app_id}"
        f"\n{CYAN}Object ID:{ENDC} {object_id}"
    )

    # Wait for application to propagate
    print("Waiting for application to propagate...")
    time.sleep(5)

    # Assign Permissions
    grant_permissions(headers, object_id)

    # Wait for permissions to propagate
    print("Waiting for permissions to propagate, this may take some time...")
    time.sleep(20)

    # Assign consent
    grant_admin_consent_uri(app_id, TENANT_ID)

    # Wait for admin consent
    print("Waiting for admin consent to propagate...")
    time.sleep(5)

    # Generate client secret
    client_secret = generate_client_secret(headers, object_id)

    print("Waiting for client secret to propagate...")
    time.sleep(5)

    # Install datadog-api-client
    install_datadog_api_client()

    print(f"{BOLD_GREEN}Application setup completed successfully.{ENDC}")
    print("-" * 50)
    print(
        f"{MAGENTA}Tenant ID: {TENANT_ID}{ENDC}"
        f"\n{MAGENTA}Client ID: {app_id}{ENDC}"
        f"\n{MAGENTA}Client Secret: {client_secret}{ENDC}"
    )
    print("-" * 50)
    print(
        f"{CYAN}Use this tenant_id, client_id and client_secret in conf.yaml file for microsoft defender integration.{ENDC}"
    )


if __name__ == "__main__":
    main()
