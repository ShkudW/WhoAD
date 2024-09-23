import argparse
import random
from ldap3 import Server, Connection, ALL, NTLM
import pandas as pd
import sys
from rich.console import Console
from rich.progress import Progress
from rich.text import Text
import matplotlib.pyplot as plt

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

console = Console()

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
        return None
    
    return conn

# Function to randomly select credentials from the userfile
def get_random_credentials(userfile):
    with open(userfile, 'r') as f:
        lines = f.readlines()
    user_cred = random.choice(lines).strip().split(':')
    return user_cred[0], user_cred[1]  # return username and password/hash

# Functions for AD enumeration
def find_no_preauth_users(conn, base_dn):
    search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
    conn.search(base_dn, search_filter, attributes=['cn', 'userAccountControl'])
    return conn.entries

def find_sid_history_users(conn, base_dn):
    search_filter = '(sIDHistory=*)'
    conn.search(base_dn, search_filter, attributes=['cn', 'sIDHistory'])
    return conn.entries

def find_delegation_users(conn, base_dn):
    search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
    conn.search(base_dn, search_filter, attributes=['cn', 'userAccountControl'])
    return conn.entries

def find_dc_sync_users(conn, base_dn):
    search_filter = '(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
    conn.search(base_dn, search_filter, attributes=['cn', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
    return conn.entries

def find_full_control_users(conn, base_dn):
    search_filter = '(ntSecurityDescriptor=*)'
    conn.search(base_dn, search_filter, attributes=['cn', 'ntSecurityDescriptor'])
    return conn.entries

# Finding users running services in the domain (SPN)
def find_service_users(conn, base_dn):
    search_filter = '(servicePrincipalName=*)'
    conn.search(base_dn, search_filter, attributes=['cn', 'servicePrincipalName'])
    return conn.entries

# Save the report and display a final message
def save_report(df, filename):
    df.to_excel(filename, index=False)
    console.print(f"[bold green]Report saved to {filename}[/bold green]")

# Generate graphical report
def generate_graphical_report(df, filename):
    fig, ax = plt.subplots()
    ax.bar(df['Category'], df['Count'])
    plt.title('WhoAD Report Summary')
    plt.xlabel('Categories')
    plt.ylabel('Count')
    plt.savefig(f"{filename}_graph.png")
    console.print(f"[bold green]Graph saved as {filename}_graph.png[/bold green]")

# Parser creation for the regular mode
def create_standard_parser():
    parser = argparse.ArgumentParser(
        description="AD Permissions Explorer",
        epilog="""
Examples:
    python3 script.py --username admin --password my_password --domain my_domain --domaincontroller dc.my_domain.com --filename report.xlsx
    python3 script.py --userfile userfile.txt --random --domain my_domain --domaincontroller dc.my_domain.com --filename report.xlsx

If using --userfile, the file should contain entries like:
    user1:password1
    user2:HASH (for NTLM/AES256 hashes)
"""
    )
    parser.add_argument("--username", help="Username for AD login")
    parser.add_argument("--password", help="Password for AD login")
    parser.add_argument("--hash", help="NTLM or AES256 hash for AD login")
    parser.add_argument("--domain", required=True, help="Domain name")
    parser.add_argument("--domaincontroller", required=True, help="Domain controller address")
    parser.add_argument("--filename", required=True, help="Filename to save the report")
    
    return parser

# Parser creation for the userfile mode
def create_userfile_parser():
    parser = argparse.ArgumentParser(
        description="AD Permissions Explorer",
        epilog="""
Examples:
    python3 script.py --userfile userfile.txt --random --domain my_domain --domaincontroller dc.my_domain.com --filename report.xlsx
    
Userfile format example (must be a .txt file):
    user1:password1
    user2:HASH
    user3:password3
"""
    )
    parser.add_argument("--domain", required=True, help="Domain name")
    parser.add_argument("--domaincontroller", required=True, help="Domain controller address")
    parser.add_argument("--filename", required=True, help="Filename to save the report")
    parser.add_argument("--userfile", required=True, help="Path to userfile for random user selection")
    parser.add_argument("--random", action='store_true', help="Use random user from userfile for each scan")
    
    return parser

def main():
    print_colored_banner()

    # Handle help (-h) request first to avoid parsing issues
    if '-h' in sys.argv or '--help' in sys.argv:
        if '--userfile' in sys.argv:
            parser = create_userfile_parser()
        else:
            parser = create_standard_parser()
        parser.print_help()
        return

    # Check if --userfile is being used
    if '--userfile' in sys.argv:
        parser = create_userfile_parser()
    else:
        parser = create_standard_parser()

    args = parser.parse_args()

    # Handle case when --userfile is used for different credentials
    if '--userfile' in sys.argv:
        # For each task, we'll select a different set of credentials
        df_report = []
        base_dn = f"DC={args.domain.replace('.', ',DC=')}"
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning AD...", total=6)

            # 1. Random credentials for No Pre-Auth users
            user, password = get_random_credentials(args.userfile)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            if conn:
                no_preauth_users = find_no_preauth_users(conn, base_dn)
                progress.update(task, advance=1)

            # 2. Random credentials for SID History users
            user, password = get_random_credentials(args.userfile)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            if conn:
                sid_history_users = find_sid_history_users(conn, base_dn)
                progress.update(task, advance=1)

            # 3. Random credentials for Delegation users
            user, password = get_random_credentials(args.userfile)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            if conn:
                delegation_users = find_delegation_users(conn, base_dn)
                progress.update(task, advance=1)

            # 4. Random credentials for DC Sync users
            user, password = get_random_credentials(args.userfile)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            if conn:
                dc_sync_users = find_dc_sync_users(conn, base_dn)
                progress.update(task, advance=1)

            # 5. Random credentials for Full Control users
            user, password = get_random_credentials(args.userfile)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            if conn:
                full_control_users = find_full_control_users(conn, base_dn)
                progress.update(task, advance=1)

            # 6. Random credentials for Service Users
            user, password = get_random_credentials(args.userfile)
            conn = connect_to_ad(args.domaincontroller, args.domain, user, password)
            if conn:
                service_users = find_service_users(conn, base_dn)
                progress.update(task, advance=1)

            df_report = pd.DataFrame({
                'Category': ['No Pre-auth Users', 'SID History Users', 'Delegation Users', 'DC-Sync Users', 'Full Control Users', 'Service Users'],
                'Count': [len(no_preauth_users), len(sid_history_users), len(delegation_users), len(dc_sync_users), len(full_control_users), len(service_users)]
            })

        save_report(df_report, args.filename)
        generate_graphical_report(df_report, args.filename)

if __name__ == "__main__":
    main()

