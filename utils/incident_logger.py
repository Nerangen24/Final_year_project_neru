def log_incident(data):
    with open("outputs/incidents.log", "a") as f:
        f.write(str(data) + "\n")