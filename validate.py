from parser import parse_log        # using the parser we made
from detector import detect_brute_force, detect_far_apart, detect_off_hours

# run each of the detector functions to check the output against what we know is true
df = parse_log("sample.log")
bf = detect_brute_force(df)
fa = detect_far_apart(df)
oh = detect_off_hours(df)

# check results with injected attack pattern
checks = {
    # check if the known brute-force IP was detected in the brute force alrts
    "Brute force IP detected (185.220.101.8)" : "185.220.101.7" in bf["ip"].values if not bf.empty else False,
    # check if the "deploy" user was flagged 
    "Far apart user detected (deploy)" : "deploy" in fa["user"].values if not fa.empty else False,
    # check if the "backup" users after hourse login was flagged
    "Off-hours user detected (backup)" : "backup" in oh["user"].values if not oh.empty else False,
}

# print pass/fail statements for each check
for check, passed in checks.items():
    print(f"{'PASS' if passed else 'FAIL'} - {check}")

detected = sum(checks.values())
print(f"\nDetection Rate: {detected}/{len(checks)} injected attack patterns caught.")

# check for false positives
print(f"Total alerts raised: {len(bf) + len(fa) + len(oh)}  (false positives = alerts beyond the {len(checks)} known injected cases)")
