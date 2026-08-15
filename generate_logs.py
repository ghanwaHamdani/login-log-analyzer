import random
from datetime import datetime, timedelta

# normal users, allowed IP's, and attacker IP's
USERS = ["ghanwa", "admin", "deploy", "backup", "svc_web"] 
NORMAL_IPS = ["142.150.10.4", "70.26.88.212", "24.114.5.90"]
ATTACKER_IPS = ["185.220.101.7", "45.155.204.19", "89.248.165.33"]

# fix randomness so you get same log file every time
random.seed(42) 
start = datetime(2026,8,1,0,0,0) #set day 0 of the 7 dya log
logLines = []

# this function builds one line in a real SSH auth log entry format
def log_line(ts,ip,user,success): 
    status = "Accepted" if success else "Failed"
    return f"{ts.strftime('%b %d %H:%M:%S')} host sshd[1234]: {status} password for {user} from {ip} port 51515 ssh2"

# NORMAL TRAFFIC
for day in range(7): 
    for _ in range(40): #40 normal logins per day
        ts = start + timedelta(days=day, hours=random.randint(7,22), minutes=random.randint(0,59))
        user = random.choice(USERS) 
        ip = random.choice(NORMAL_IPS)
        logLines.append(log_line(ts,ip,user,success=True)) #ensures normal logins always succeed

# ATTACK ONE: BRUTE FORCE ATTACK
burst_start = start + timedelta(days=2, hours=3, minutes=10) #occurs on day 2 at 3:10am 
for i in range(25): #25 rapid fire login attempts
    ts = burst_start + timedelta(seconds=i * 4) #each attempt happes 4 secs after the last
    logLines.append(log_line(ts,ATTACKER_IPS[0], "admin",success=False))
logLines.append(log_line(burst_start + timedelta(seconds=110),ATTACKER_IPS[0],"admin",success=True)) #only successful attempt

# ATTACK TWO: FAR APART IPS
apart_ts1 = start + timedelta(days=4,hours=14,minutes=0) 
apart_ts2 = apart_ts1 + timedelta(minutes=5)
logLines.append(log_line(apart_ts1,"70.26.88.212","deploy",success=True)) #login from local IP
logLines.append(log_line(apart_ts2,"203.0.113.44","deploy",success=True)) #login from far away IP

# ATTACK THREE: OFF-HOURS LOGIN
offhours_ts = start + timedelta(days=5,hours=3,minutes=15)
logLines.append(log_line(offhours_ts,"24.114.5.90","backup",success=True))


#shuffle all the lines to look like a real log
random.shuffle(logLines)


#write all into single log file
with open("sample.log","w") as file:
        file.write("\n".join(logLines) + "\n")

#verify it runs
print(f"Generated {len(logLines)} log lines -> sample.log")