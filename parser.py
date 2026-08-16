import re #regex library
import pandas as pd #pandas for dataframe

# a regex pattern matching one auth log line
LOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"  # this line would be the date and time
    r"host sshd\[\d+\]:\s+(?P<status>Accepted|Failed)\s+password for\s+"     # ex: "host sshd[1234]: Accepted password for"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"                     # ex: "ghanwa from 142.150.10.4"
)

def parse_log(filepath, year=2026):
    rows = []                                # holds one dict per successfully parsed log line
    with open(filepath) as file:
        for line in file:
            m = LOG_PATTERN.search(line)     # match this line with our pattern
            if not m:                        # if the line doesnt match the pattern move to next
                continue
            d = m.groupdict()                # pull out named capture groups as a dict (ex: {"month": "Aug", ...})
            ts = pd.to_datetime(f"{d['month']} {d['day']} {year} {d['time']}", format = "%b %d %Y %H:%M:%S")
            rows.append({
                "timestamp": ts,
                "user": d["user"],
                "ip": d["ip"],
                "success": d["status"] == "Accepted",
            })

    # turn list of row dicts into a dataframe, sorted chronologically
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


#validation check
if __name__ == "__main__":
    df = parse_log("sample.log")
    print(df.shape)     # prints (rows, cols)
    print(df.head())    # print first 5 rows