import argparse
import random
from ldap3 import Server, Connection, ALL, NTLM
import pandas as pd
import sys
from rich.console import Console
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TimeElapsedColumn
from rich.text import Text
from jinja2 import Template

console = Console()

# Banner
BANNER_TEXT = r"""
__        ___             _    ____  
\ \      / / |__   ___   / \  |  _ \ 
 \ \ /\ / /| '_ \ / _ \ / _ \ | | | |
  \ V  V / | | | | (_) / ___ \| |_| |
   \_/\_/  |_| |_|\___/_/   \_\____/ 

@by ShkudW
https://github.com/ShkudW/WhoAD
"""

# Function to generate random colorized banner
def print_colored_banner():
    banner_lines = BANNER_TEXT.split('\n')
    banner_text = Text()
    for line in banner_lines:
        color = random.choice(['cyan', 'magenta', 'yellow', 'green', 'red', 'blue', 'bright_cyan', 'bright_magenta'])
        banner_text.append(line + "\n", style=color)
    console.print(banner_text)

# Function to connect to AD
def connect_to_ad(domain_controller, domain, username, password=None, hash_value=None):
    server = Server(domain_controller, get_info=ALL)
    
    if password:
        conn = Connection(server, user=f'{domain}\\{username}', password=password, authentication=NTLM)
    elif hash_value:
        conn = Connection(server, user=f'{domain}\\{username}', password=hash_value, authentication=NTLM)
    else:
        raise ValueError("You must provide either a password or a hash.")
    
    if not conn.bind():
        console.print(f"[bold red]Failed to bind: {conn.result}[/bold red]")
    else:
        console.print(f"[bold green]Connected to {domain_controller} as {username}[/bold green]")
    
    return conn

# Function to read credentials from file
def get_next_credentials(userfile, used_users):
    with open(userfile, 'r') as f:
        lines = f.readlines()

    available_users = [line.strip() for line in lines]

    # If all users are used, start over from the first user
    if len(used_users) == len(available_users):
        used_users.clear()  # Reset the used users list

    # Select the next user not yet used in the current cycle
    for user in available_users:
        user_name = user.split(':')[0]
        if user_name not in used_users:
            used_users.add(user_name)
            return user.split(':')

    # This should not be reached but in case, return the first user
    first_user = available_users[0].split(':')
    used_users.add(first_user[0])
    return first_user

# Functions for AD enumeration (delegation, full control, etc.)
def find_no_preauth_users(conn, base_dn):
    search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
    conn.search(base_dn, search_filter, attributes=['cn', 'userAccountControl'])
    return [{'User': entry['cn'], 'Object': None} for entry in conn.entries]

def find_sid_history_users(conn, base_dn):
    search_filter = '(sIDHistory=*)'
    conn.search(base_dn, search_filter, attributes=['cn', 'sIDHistory'])
    return [{'User': entry['cn'], 'Object': None} for entry in conn.entries]

def find_delegation_users(conn, base_dn):
    search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
    conn.search(base_dn, search_filter, attributes=['cn', 'memberOf'])
    return [{'User': entry['cn'], 'Object': entry['memberOf']} for entry in conn.entries]

def find_dc_sync_users(conn, base_dn):
    search_filter = '(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
    conn.search(base_dn, search_filter, attributes=['cn', 'msDS-AllowedToDelegateTo'])
    return [{'User': entry['cn'], 'Object': entry['msDS-AllowedToDelegateTo']} for entry in conn.entries]

def find_full_control_users(conn, base_dn):
    """
    Find users with Full Control permissions on critical objects in the domain,
    excluding standard administrative groups like Domain Admins.
    """
    critical_objects = [
        'CN=Domain Admins',
        'CN=Enterprise Admins',
        'CN=Administrators',
        'CN=Schema Admins',
        'CN=Server Operators',
        'CN=Account Operators',
        'CN=Backup Operators'
    ]
    
    search_filter = '(|(objectClass=computer)(objectClass=group)(objectClass=user))'
    conn.search(base_dn, search_filter, attributes=['cn', 'ntSecurityDescriptor', 'memberOf'])
    
    full_control_users = []
    
    for entry in conn.entries:
        # Check if the user is part of any critical objects or groups
        if hasattr(entry, 'memberOf'):
            groups = entry.memberOf.values
            if not any(critical_object in groups for critical_object in critical_objects):
                # If not part of a critical group, check for full control permissions
                if entry.ntSecurityDescriptor:
                    full_control_users.append({
                        'User': entry.cn,
                        'Object': entry.memberOf
                    })

    return full_control_users

def find_service_users(conn, base_dn):
    search_filter = '(servicePrincipalName=*)'
    conn.search(base_dn, search_filter, attributes=['cn', 'servicePrincipalName'])
    return [{'User': entry['cn'], 'Object': entry['servicePrincipalName']} for entry in conn.entries]

# Save the report and display a final message
def save_report(df, filename):
    df.to_excel(filename, index=False)
    console.print(f"[bold green]Report saved to {filename}[/bold green]")

# Generate HTML report
def generate_html_report(df, filename, domain_name, domain_controller):
    template_html = """
    <html>
    <head>
        <title>WhoAD Report</title>
        <style>
            body {
                font-family: 'Arial', sans-serif;
                background-color: #e6f2ff;
                margin: 0;
                padding: 20px;
            }
            h1 {
                color: #4CAF50;
                font-size: 36px;
                font-weight: bold;
                text-align: center;
                margin-bottom: 20px;
                text-shadow: 2px 2px 5px #aaa;
            }
            h2 {
                color: #333;
                margin-top: 40px;
            }
            p {
                color: #666;
                font-size: 18px;
            }
            .domain-info {
                background-color: #e0f7fa;
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }
            th, td {
                padding: 10px;
                border: 1px solid black;
                text-align: left;
            }
            th {
                color: white;
                cursor: pointer;
            }
            .Delegation th {
                background-color: #4CAF50;
            }
            .DC-Sync th {
                background-color: #ff9800;
            }
            .FullControl th {
                background-color: #009688;
            }
            .Service th {
                background-color: #3f51b5;
            }
            tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            .hidden {
                display: none;
            }
            .show {
                display: table-row;
            }
            .table-section {
                margin-bottom: 40px;
            }
            .table-section:hover th {
                background-color: #81c784;
            }
        </style>
        <script>
            function toggleVisibility(id) {
                var rows = document.querySelectorAll('tr.' + id);
                for (var i = 0; i < rows.length; i++) {
                    if (rows[i].classList.contains('hidden')) {
                        rows[i].classList.remove('hidden');
                        rows[i].classList.add('show');
                    } else {
                        rows[i].classList.remove('show');
                        rows[i].classList.add('hidden');
                    }
                }
            }
        </script>
    </head>
    <body>
        <h1>WhoAD Report</h1>
        <div class="domain-info">
            <h2>Domain Information:</h2>
            <p><strong>Domain Name:</strong> {{ domain_name }}</p>
            <p><strong>Domain Controller:</strong> {{ domain_controller }}</p>
        </div>
        <p>This report summarizes the AD permissions found during the scan. Click on the table headers to expand/collapse the details.</p>
        
        <!-- Delegation Users Table -->
        <div class="table-section Delegation">
            <table>
                <thead>
                    <tr onclick="toggleVisibility('Delegation')">
                        <th>Delegation Users (Click to Expand)</th>
                        <th>Object</th>
                    </tr>
                </thead>
                <tbody>
                {% for row in data if row['Category'] == 'Delegation Users' %}
                    <tr class="Delegation hidden">
                        <td>{{ row['User'] }}</td>
                        <td>{{ row['Object'] }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- DC-Sync Users Table -->
        <div class="table-section DC-Sync">
            <table>
                <thead>
                    <tr onclick="toggleVisibility('DC-Sync')">
                        <th>DC-Sync Users (Click to Expand)</th>
                        <th>Object</th>
                    </tr>
                </thead>
                <tbody>
                {% for row in data if row['Category'] == 'DC-Sync Users' %}
                    <tr class="DC-Sync hidden">
                        <td>{{ row['User'] }}</td>
                        <td>{{ row['Object'] }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Full Control Users Table -->
        <div class="table-section FullControl">
            <table>
                <thead>
                    <tr onclick="toggleVisibility('FullControl')">
                        <th>Full Control Users (Click to Expand)</th>
                        <th>Object</th>
                    </tr>
                </thead>
                <tbody>
                {% for row in data if row['Category'] == 'Full Control Users' %}
                    <tr class="FullControl hidden">
                        <td>{{ row['User'] }}</td>
                        <td>{{ row['Object'] }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Service Users Table -->
        <div class="table-section Service">
            <table>
                <thead>
                    <tr onclick="toggleVisibility('Service')">
                        <th>Service Users (Click to Expand)</th>
                        <th>Object</th>
                    </tr>
                </thead>
                <tbody>
                {% for row in data if row['Category'] == 'Service Users' %}
                    <tr class="Service hidden">
                        <td>{{ row['User'] }}</td>
                        <td>{{ row['Object'] }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>

    </body>
    </html>
    """
    
    template = Template(template_html)
    html_content = template.render(data=df.to_dict(orient='records'), domain_name=domain_name, domain_controller=domain_controller)
    
    with open(filename, 'w') as f:
        f.write(html_content)
    
    console.print(f"[bold green]HTML Report saved to {filename}[/bold green]")

# Main function
def main():
    print_colored_banner()  # Show the colored banner at the start

    parser = argparse.ArgumentParser(description="AD Permissions Explorer")
    
    # The flags are set conditionally based on userfile or username/password usage
    if '--userfile' in sys.argv:
        # If --userfile is used, we display only userfile and random options
        parser.add_argument("--userfile", required=True, help="Path to userfile for random user selection")
        parser.add_argument("--random", action='store_true', help="Use random credentials from userfile for each scan")
        parser.add_argument("--domain", required=True, help="Domain name")
        parser.add_argument("--domaincontroller", required=True, help="Domain controller address")
        parser.add_argument("--filename", required=True, help="Filename to save the report")
    else:
        # If --userfile is not used, we display username and password options
        parser.add_argument("--username", help="Username for AD login")
        parser.add_argument("--password", help="Password for AD login")
        parser.add_argument("--hash", help="NTLM or AES256 hash for AD login")
        parser.add_argument("--domain", required=True, help="Domain name")
        parser.add_argument("--domaincontroller", required=True, help="Domain controller address")
        parser.add_argument("--filename", required=True, help="Filename to save the report")

    args = parser.parse_args()

    # Ensure --random can only be used with --userfile
    if hasattr(args, 'random') and args.random and not hasattr(args, 'userfile'):
        console.print("[bold red]You must use --random together with --userfile![/bold red]")
        sys.exit(1)

    base_dn = f"DC={args.domain.replace('.', ',DC=')}"

    if hasattr(args, 'userfile') and hasattr(args, 'random') and args.userfile and args.random:
        used_users = set()  # Keep track of used users to avoid repetition
        with Progress("[bold yellow]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeElapsedColumn(), TimeRemainingColumn()) as progress:
            task = progress.add_task("[cyan]Scanning AD...", total=6)

            # Assign different credentials for each scan, loop through users if needed
            user, password = get_next_credentials(args.userfile, used_users)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            delegation_users = find_delegation_users(conn, base_dn)
            console.print(f"Delegation Users found: {len(delegation_users)}")
            progress.update(task, advance=1)

            user, password = get_next_credentials(args.userfile, used_users)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            sid_history_users = find_sid_history_users(conn, base_dn)
            console.print(f"SID History Users found: {len(sid_history_users)}")
            progress.update(task, advance=1)

            user, password = get_next_credentials(args.userfile, used_users)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            dc_sync_users = find_dc_sync_users(conn, base_dn)
            console.print(f"DC Sync Users found: {len(dc_sync_users)}")
            progress.update(task, advance=1)

            user, password = get_next_credentials(args.userfile, used_users)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            full_control_users = find_full_control_users(conn, base_dn)
            console.print(f"Full Control Users found: {len(full_control_users)}")
            progress.update(task, advance=1)

            user, password = get_next_credentials(args.userfile, used_users)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            service_users = find_service_users(conn, base_dn)
            console.print(f"Service Users found: {len(service_users)}")
            progress.update(task, advance=1)

            user, password = get_next_credentials(args.userfile, used_users)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            no_preauth_users = find_no_preauth_users(conn, base_dn)
            console.print(f"No Pre-auth Users found: {len(no_preauth_users)}")
            progress.update(task, advance=1)

        # Collect all data into a DataFrame for report generation
        data = []
        data.extend([{'Category': 'Delegation Users', 'User': entry['User'], 'Object': entry['Object']} for entry in delegation_users])
        data.extend([{'Category': 'SID History Users', 'User': entry['User'], 'Object': None} for entry in sid_history_users])
        data.extend([{'Category': 'DC-Sync Users', 'User': entry['User'], 'Object': entry['Object']} for entry in dc_sync_users])
        data.extend([{'Category': 'Full Control Users', 'User': entry['User'], 'Object': entry['Object']} for entry in full_control_users])
        data.extend([{'Category': 'Service Users', 'User': entry['User'], 'Object': entry['Object']} for entry in service_users])
        data.extend([{'Category': 'No Pre-auth Users', 'User': entry['User'], 'Object': None} for entry in no_preauth_users])

        # Save and generate reports
        df_report = pd.DataFrame(data)
        save_report(df_report, args.filename + '.xlsx')
        generate_html_report(df_report, args.filename + '.html', args.domain, args.domaincontroller)

    elif args.username and args.password:
        # Regular scan with single credentials
        conn = connect_to_ad(args.domaincontroller, args.domain, args.username, args.password)
        if conn:
            with Progress("[bold yellow]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeElapsedColumn(), TimeRemainingColumn()) as progress:
                task = progress.add_task("[cyan]Scanning AD...", total=6)

                delegation_users = find_delegation_users(conn, base_dn)
                console.print(f"Delegation Users found: {len(delegation_users)}")
                progress.update(task, advance=1)

                sid_history_users = find_sid_history_users(conn, base_dn)
                console.print(f"SID History Users found: {len(sid_history_users)}")
                progress.update(task, advance=1)

                dc_sync_users = find_dc_sync_users(conn, base_dn)
                console.print(f"DC Sync Users found: {len(dc_sync_users)}")
                progress.update(task, advance=1)

                full_control_users = find_full_control_users(conn, base_dn)
                console.print(f"Full Control Users found: {len(full_control_users)}")
                progress.update(task, advance=1)

                service_users = find_service_users(conn, base_dn)
                console.print(f"Service Users found: {len(service_users)}")
                progress.update(task, advance=1)

                no_preauth_users = find_no_preauth_users(conn, base_dn)
                console.print(f"No Pre-auth Users found: {len(no_preauth_users)}")
                progress.update(task, advance=1)

            # Collect all data into a DataFrame for report generation
            data = []
            data.extend([{'Category': 'Delegation Users', 'User': entry['User'], 'Object': entry['Object']} for entry in delegation_users])
            data.extend([{'Category': 'SID History Users', 'User': entry['User'], 'Object': None} for entry in sid_history_users])
            data.extend([{'Category': 'DC-Sync Users', 'User': entry['User'], 'Object': entry['Object']} for entry in dc_sync_users])
            data.extend([{'Category': 'Full Control Users', 'User': entry['User'], 'Object': entry['Object']} for entry in full_control_users])
            data.extend([{'Category': 'Service Users', 'User': entry['User'], 'Object': entry['Object']} for entry in service_users])
            data.extend([{'Category': 'No Pre-auth Users', 'User': entry['User'], 'Object': None} for entry in no_preauth_users])

            # Save and generate reports
            df_report = pd.DataFrame(data)
            save_report(df_report, args.filename + '.xlsx')
            generate_html_report(df_report, args.filename + '.html', args.domain, args.domaincontroller)

    else:
        console.print("[red]You must use both --userfile and --random together, or provide username and password![/red]")

if __name__ == "__main__":
    main()

