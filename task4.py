from z3 import *
import re

def analyze_blacklisted_failed_logins(log_file, blacklist_file="blacklist.txt"):
    """
    Z3: Check if ∃ failed login from blacklisted IP.
    """
    # Loading blacklisted ips
    try:
        with open(blacklist_file, 'r') as f:
            blacklist = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        # Create sample blacklist written randomly 
        sample_blacklist = """203.0.113.45
198.51.100.77
192.0.2.10"""
        with open(blacklist_file, 'w') as f:
            f.write(sample_blacklist)
        print(f" Created sample blacklist: {blacklist_file}")
        blacklist = set(sample_blacklist.split())
    
    print(f" Blacklist loaded: {len(blacklist)} IPs")
    
    # Parse security logs (common formats)  checked through web
    failed_patterns = [
        r'Failed password for .* from ([\d.]+)',  # SSH auth.log
        r'Failed login attempt.*from ([\d.]+)',   # Custom
        r'invalid user .* from ([\d.]+)',         # SSH
        r'authentication failure.*from ([\d.]+)'  # Generic
    ]
    
    failed_logins = []
    
    # Read logs
    try:
        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                for pattern in failed_patterns:
                    match = re.search(pattern, line)
                    if match:
                        ip = match.group(1)
                        failed_logins.append({
                            'line': line_num,
                            'ip': ip,
                            'log_line': line.strip()
                        })
                        break
    except FileNotFoundError:
        # Create sample security log
        print(" Creating sample security log...")
        sample_log = """Dec 04 10:15:23 server sshd[1234]: Failed password for admin from 203.0.113.45 port 22
Dec 04 11:22:18 server sshd[5678]: Failed password for root from 198.51.100.77 port 22
Dec 04 14:30:45 server sshd[9012]: Accepted password for user1 from 10.0.0.5 port 22
Dec 04 16:45:12 server sshd[3456]: invalid user test from 192.168.1.100 port 22
Dec 04 18:20:33 server sshd[7890]: Failed password for admin from 203.0.113.45 port 22"""
        with open(log_file, 'w') as f:
            f.write(sample_log)
        print(f"Sample log created: {log_file}")
        return analyze_blacklisted_failed_logins(log_file, blacklist_file)
    
    print(f" Found {len(failed_logins)} failed login attempts")
    
    if not failed_logins:
        print(" No failed logins found")
        return False
    
    # Z3 Formal Verification: ∃ failed_login ∧ blacklisted_ip
    s = Solver()
    violations = []
    
    for i, login in enumerate(failed_logins):
        is_blacklisted = Bool(f"blacklisted_{i}")
        
        # Fact: IP is blacklisted?
        s.add(is_blacklisted == (login['ip'] in blacklist))
        
        # Tracking potential violations
        violations.append(is_blacklisted)
    
    # Query: Exists at least one blacklisted failed login?
    exists_violation = Or(violations)
    
    print("\n Z3 FORMAL ANALYSIS:")
    print("Query: ∃ failed_login ∧ blacklisted_ip")
    
    result = s.check()
    
    if result == sat:
        print(" SECURITY VIOLATION DETECTED!")
        m = s.model()
        
        print("\n BLACKLISTED IP FAILED LOGINS:")
        violation_count = 0
        for i, login in enumerate(failed_logins):
            var = Bool(f"blacklisted_{i}")
            if is_true(m[var]):
                violation_count += 1
                print(f"   Line {login['line']}: {login['ip']} (Blacklisted)")
                print(f"     Log: {login['log_line'][:100]}...")
                print()
        
        print(f" Total violations: {violation_count}/{len(failed_logins)}")
        return True
    else:
        print(" No blacklisted IP failed logins detected")
        return False

# executing program 
if __name__ == "__main__":
    violation_exists = analyze_blacklisted_failed_logins("security.log", "blacklist.txt")
    print(f"\n RESULT: {'VIOLATION ∃' if violation_exists else 'SECURE ∀'}"[:182][:183]) 