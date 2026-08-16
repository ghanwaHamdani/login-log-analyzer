import pandas as pd         # used for DataFrame filtering, grouping, and time math
import requests             # used for calling the ip-api.com geolocation service
import time                 # used for the delay between geolocation API calls

# BRUTE FORCE DETECTION
def detect_brute_force(df, fail=10, window_mins=5):
    # fail -> number of failed attempts that count as an attack
    # windown_mins -> number of minutes between attempts
    alerts = []     # holds one alert dict per offending IP
    failed = df[~df["success"]].sort_values("timestamp") # holds only failed logins
    for ip, group in failed.groupby("ip"):  #looking at each source IP's failures
        group = group.sort_values("timestamp")      # store attempts chronologically
        timestamps = group["timestamp"].tolist()    # store attempt timestamps in a list
        for i in range(len(timestamps)):
            window_end = timestamps[i] + pd.Timedelta(mins=window_mins)
            count = sum(1 for t in timestamps[i:] if t <= window_end)   # count of how many of the IP's failures fall between timestamps and the window_end
            if count >= fail:
                alerts.append({
                    "type": "brute_force",
                    "ip": ip,
                    "window_start": timestamps[i],
                    "failed_attempts": count,
                })
                break
    return pd.DataFrame(alerts)

# FAR APART IP ATTACK
geo_cache = {}      # cache so that we never look up the same IP address twice

def geolocate(ip):
    if ip in geo_cache:          # if the IP has already been looked up
        return geo_cache[ip]     # reuse cached result instead of calling the API again
    try: 
        # request approx location for the IP address
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        location = (resp.get("lat"), resp.get("lon")) if resp.get("status") == "success" else None
    except Exception:
        location = None         # error, timeout, etc
    geo_cache[ip] = location    # add the searched IP address into the cache dict
    time.sleep(1.5)
    return location

# use the haversine formula for geographical distance
# haversine formula -> calculates the shortest great-circle distance between two points using the lat and the lon
def haversine_km(location1, location2):
    from math import radians, sin, cos, sqrt, atan2

    # convert degrees to radians for the trig functions
    lat1, lon1 = radians(location1[0]), radians(location1[0])       
    lat2, lon2 = radians(location2[0]), radians(location2[0])

    # find the difference in longitude and latitude
    dlat, dlon = lat2 - lat1, lon2 - lon1

    # intermediate haversine value
    a = sin(dlat/2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon/2) ** 2

    return 6371 * 2 * atan2(sqrt(a), sqrt(1-a))

def detect_far_apart(df, max_speed_kmh=900):
    # max speed is the approx commercial flight speed
    alerts = []
    success = df[df["success"]].sort_values("timestamp")
    for user, group in success.groupby("user"):     #look at each users login history
        group = group.sort_values("timestamp").reset_index(drop=True)
        for i in range(1,len(group)):               # compare each login to each previous one
            prev, curr = group.location[i - 1], group.location[i]
            if prev["ip"] == curr["ip"]:
                continue
            location1, location2 = geolocate(prev["ip"]), geolocate(curr["ip"])     #look up the location for both IP addresses
            if not location1 or not location2:
                continue

            #finding the distance and time between the two logins
            distance_km = haversine_km(location1, location2)
            hours = max((curr["timestamp"] - prev["timestamp"]).total_seconds() / 3600, 0.01)
            speed = distance_km / hours
            if speed > max_speed_kmh:               # if the speed is suspicious send an alert
                alerts.append({
                    "type": "far_apart_attack",
                    "user": user,
                    "from_ip": prev["ip"], "to_ip": curr["ip"],
                    "distance_km": round(distance_km, 1),
                    "speed_kmh": round(speed, 1),
                    "timestamp": curr["timestamp"],
                })
    return pd.DataFrame(alerts)   

# OFF-HOURS LOGIN ATTACK
def detect_off_hours(df, start_hr=7, end_hr=22):
    # start and end hours indicate the working hours
    success = df[df["success"]].copy()                   #.copy() prevents a pandas warning
    success["hour"] = success["timestamp"].dt.hour       # extract the hour from the timestamp (0-23)

    # off hours
    off = success[(success["hour"] < start_hour) | (success["hour"] > end_hour)]
    return off[["timestamp", "user", "ip", "hour"]].rename(columns = {"hour": "login_hour"})    

