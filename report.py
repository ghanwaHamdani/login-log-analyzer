import argparse                     # allows use of cmd line flags
import matplotlib.pyplot as plt     # for drawing failed login chart
import pandas as pd                 # for writing alerts later
from parser import parse_log        # the parser file we made
from detector import detect_brute_force, detect_far_apart, detect_off_hours

def main():
    #set up the CLI
    ap = argparse.ArgumentParser(description = "Suspicious Login Log Analyzer")
    ap.add_argument("--log", default = "sample.log", help = "Path to log file")     # input the log path
    ap.add_argument("--out", default = "alerts.csv", help = "Output CSV")           # this is where the results get saved
    args = ap.parse_args()      # reads what flags were passed in the cmd line

    df = parse_log(args.log)                        # parse the log into a DataFrame
    print(f"Parsed {len(df)} log entries.\n")       # verify 

    # run all detection rules against the parsed data
    bf = detect_brute_force(df)
    fa = detect_far_apart(df)
    oh = detect_off_hours(df)

    # prints the summary of each alert in a nicer looking form :)
    print(f"Brute Force Alerts: {len(bf)}")

    # prints the table only if there is data in it
    if not bf.empty:        
        print(bf.to_string(index = False))
    print(f"\nFar Apart Alerts: {len(fa)}")
    if not fa.empty:
        print(fa.to_string(index = False))  
    print(f"\nOff-Hours Login Alerts: {len(oh)}")
    if not oh.empty:
        print(oh.to_string(index = False))

    # Combine all alert types into one list to save them as one CSV
    all_alerts = []
    for _, r in bf.iterrows(): #itterows() allows you to loop through the DataFrame row by row
        all_alerts.append({"type": "brute_force", "detail": dict(r)})
    for _, r in fa.iterrows():
        all_alerts.append({"type": "far_apart", "detail": dict(r)})
    for _, r in oh.iterrows():
        all_alerts.append({"type": "off_hours", "detail": dict(r)})

    # writing the alerts out to CSV
    pd.DataFrame(all_alerts).to_csv(args.out, index = False)      
    print(f"\nSaved all alerts to {args.out}")

    #create a chart for the failed logins per day
    failed = df[~df["success"]].copy()
    failed["date"] = failed["timestamp"].dt.date        # timestamp collapsed to calendar date
    counts = failed.groupby("date").size()              # number of failures on each date
    plt.figure(figsize = (8,4))                         # chart size in inches
    counts.plot(kind = "bar", color = "firebrick")      
    plt.title("Failed Login Attempts per Day")
    plt.ylabel("Failed Attempts")
    plt.tight_layout()
    plt.savefig("failed.png")
    print("saved chart to failed.png")


#run main method when file is executed directly 
if __name__ == "__main__":
    main()