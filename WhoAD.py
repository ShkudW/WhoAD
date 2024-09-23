import argparse
import random
from ldap3 import Server, Connection, ALL, NTLM
import pandas as pd
import sys
from rich.console import Console
from rich.progress import Progress
from rich.text import Text
import matplotlib.pyplot as plt


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


def print_colored_banner():
    banner_lines = BANNER_TEXT.split('\n')
    banner_text = Text()
    for line in banner_lines:
        color = random.choice(['cyan', 'magenta', 'yellow', 'green', 'red', 'blue', 'bright_cyan', 'bright_magenta'])
        banner_text.append(line + "\n", style=color)
    console.print(banner_text)


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


def find_service_users(conn, base_dn):
    search_filter = '(servicePrincipalName=*)'
    conn.search(base_dn, search_filter, attributes=['cn', 'servicePrincipalName'])
    return conn.entries


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


def create_parser(userfile_mode=False):
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
    
    if userfile_mode:
        parser.add_argument("--userfile", required=True, help="Path to userfile for random user selection")
        parser.add_argument("--random", action='store_true', help="Use random user from userfile for each scan")
    else:
        parser.add_argument("--userfile", help="Path to userfile for random user selection (use this with --random)")

    return parser

def main():
    # Print a random colored banner
    print_colored_banner()

    if '-h' in sys.argv or '--help' in sys.argv:
        if '--userfile' in sys.argv or '-userfile' in sys.argv:
            parser = create_parser(userfile_mode=True)
        else:
            parser = create_parser(userfile_mode=False)
        parser.print_help()
        return

    if '--userfile' in sys.argv:
        parser = create_parser(userfile_mode=True)
    else:
        parser = create_parser(userfile_mode=False)  # Here was the issue

    args = parser.parse_args()

    if args.random and not args.userfile:
        parser.error("The --random flag can only be used with --userfile.")
    if args.userfile and not args.random:
        parser.error("The --userfile flag must be used with --random.")

    if not args.password and not args.hash:
        parser.error("You must provide either a password or a hash.")

    if args.random:
        user, credential = get_random_user_from_file(args.userfile)
        args.username = user
        if credential.startswith('HASH'):
            args.hash = credential
            args.password = None
        else:
            args.password = credential
            args.hash = None

    conn = connect_to_ad(args.domaincontroller, args.domain, args.username, args.password, args.hash)
    
    if conn:
        base_dn = f"DC={args.domain.replace('.', ',DC=')}"
        df_report = []

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning AD...", total=6)

            no_preauth_users = find_no_preauth_users(conn, base_dn)
            progress.update(task, advance=1)
            sid_history_users = find_sid_history_users(conn, base_dn)
            progress.update(task, advance=1)
            delegation_users = find_delegation_users(conn, base_dn)
            progress.update(task, advance=1)
            dc_sync_users = find_dc_sync_users(conn, base_dn)
            progress.update(task, advance=1)
            full_control_users = find_full_control_users(conn, base_dn)
            progress.update(task, advance=1)
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

