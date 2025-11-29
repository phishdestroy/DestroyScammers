import sys
from datetime import datetime

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log(msg: str, level: str = 'info') -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    if level == 'info':
        print(f"[{timestamp}] {Colors.BLUE}[INFO]{Colors.ENDC} {msg}")
    elif level == 'success':
        print(f"[{timestamp}] {Colors.GREEN}[OK]{Colors.ENDC}   {msg}")
    elif level == 'warning':
        print(f"[{timestamp}] {Colors.YELLOW}[SKIP]{Colors.ENDC} {msg}")
    elif level == 'error':
        print(f"[{timestamp}] {Colors.RED}[ERR]{Colors.ENDC}  {msg}")
    elif level == 'critical':
        print(f"\n{Colors.BOLD}>>> {msg} <<<{Colors.ENDC}")

def banner():
    print(f"""{Colors.GREEN}
   ___  ___ ___ _  _ _____ 
  / _ \/ __|_ _| \| |_   _|
 | (_) \__ \| || .` | | |  
  \___/|___/___|_|\_| |_|  
  
  Auto-OSINT Scanner
  {Colors.ENDC}""")