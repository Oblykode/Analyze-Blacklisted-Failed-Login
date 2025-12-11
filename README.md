# Analyze-Blacklisted-Failed-Login
Parses security logs (SSH auth.log patterns) for failed logins using regex. Loads blacklist IPs. Z3 encodes each failed login IP as Bool var (blacklisted_i). Adds fact: var == (ip in blacklist). Query: Or(all_vars) checks ∃ blacklisted failed login. sat=violation lists exact log lines. Recursive sample data creation.
