"""
generate_dataset.py

Regenerates a synthetic, merged dataset that mirrors two public dataset styles:
  1. Smart Home IoT + Weather sensor readings (Kaggle-style smart home dataset)
  2. Synthea-style synthetic healthcare / patient records

The two sources are merged into ONE unified table with NO sensitivity labels,
so the ML pipeline (risk_scoring.py + sensitivity_classifier.py) has to derive
sensitivity itself from the fields present in each row -- exactly like real
merged multi-source data.

Run directly to (re)create data/combined_dataset.csv:
    python generate_dataset.py
"""

import csv
import os
import random
from datetime import datetime, timedelta

random.seed(42)

N_IOT = 600
N_HEALTH = 600

COLUMNS = [
    "row_id", "source_dataset", "timestamp",
    # IoT / smart home fields
    "device_id", "temperature_c", "humidity_pct", "motion_detected",
    "door_status", "power_usage_kw", "weather_condition", "pressure_hpa",
    "wind_speed_kmh", "ip_address", "gps_coordinates",
    # Healthcare fields
    "patient_name", "owner_email", "owner_ssn_like", "diagnosis",
    "insurance_provider", "billing_amount", "heart_rate_bpm",
    "blood_pressure", "medication", "physician_name", "hospital_name",
    "admission_date", "blood_type", "allergy_notes", "visit_type",
]

WEATHER = ["clear", "cloudy", "rain", "storm", "snow", "fog"]
DOOR = ["open", "closed", "locked"]
DIAGNOSES = ["hypertension", "type-2 diabetes", "influenza", "asthma",
             "fracture", "migraine", "anxiety disorder", "covid-19"]
INSURERS = ["Aetna", "UnitedHealth", "Cigna", "BlueCross", "Kaiser"]
BLOOD_TYPES = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
VISIT_TYPES = ["outpatient", "inpatient", "emergency", "telehealth"]
FIRST_NAMES = ["James", "Mary", "Robert", "Linda", "Michael", "Patricia",
               "David", "Jennifer", "Arjun", "Priya", "Wei", "Fatima"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Kumar", "Nair",
              "Chen", "Garcia", "Khan", "Davis"]


def rand_timestamp():
    start = datetime(2024, 1, 1)
    delta = timedelta(minutes=random.randint(0, 500000))
    return (start + delta).isoformat(timespec="minutes")


def rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}." \
           f"{random.randint(0,255)}.{random.randint(1,254)}"


def rand_gps():
    return f"{random.uniform(-90,90):.4f},{random.uniform(-180,180):.4f}"


def rand_ssn_like():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"


def blank_row():
    return {c: "" for c in COLUMNS}


def gen_iot_row(row_id):
    r = blank_row()
    r["row_id"] = row_id
    r["source_dataset"] = "smart_home_iot"
    r["timestamp"] = rand_timestamp()
    r["device_id"] = f"dev_{random.randint(1000,9999)}"
    r["temperature_c"] = round(random.uniform(-5, 40), 1)
    r["humidity_pct"] = round(random.uniform(20, 90), 1)
    r["motion_detected"] = random.choice(["true", "false"])
    r["door_status"] = random.choice(DOOR)
    r["power_usage_kw"] = round(random.uniform(0.1, 5.0), 2)
    r["weather_condition"] = random.choice(WEATHER)
    r["pressure_hpa"] = round(random.uniform(980, 1040), 1)
    r["wind_speed_kmh"] = round(random.uniform(0, 60), 1)
    # cross-contamination: some IoT rows carry identifying-ish fields
    if random.random() < 0.25:
        r["ip_address"] = rand_ip()
    if random.random() < 0.15:
        r["gps_coordinates"] = rand_gps()
    return r


def gen_health_row(row_id):
    r = blank_row()
    r["row_id"] = row_id
    r["source_dataset"] = "synthetic_healthcare"
    r["timestamp"] = rand_timestamp()
    name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
    r["patient_name"] = name
    r["owner_email"] = f"{name.lower().replace(' ', '.')}@example.com"
    r["owner_ssn_like"] = rand_ssn_like()
    r["diagnosis"] = random.choice(DIAGNOSES)
    r["insurance_provider"] = random.choice(INSURERS)
    r["billing_amount"] = round(random.uniform(80, 15000), 2)
    r["heart_rate_bpm"] = random.randint(55, 130)
    r["blood_pressure"] = f"{random.randint(100,160)}/{random.randint(60,100)}"
    r["medication"] = random.choice(
        ["metformin", "lisinopril", "albuterol", "ibuprofen", "sertraline", "none"])
    r["physician_name"] = f"Dr. {random.choice(LAST_NAMES)}"
    r["hospital_name"] = random.choice(
        ["City General", "St. Mary's", "Riverside Medical", "Lakeside Clinic"])
    r["admission_date"] = rand_timestamp()
    r["blood_type"] = random.choice(BLOOD_TYPES)
    r["allergy_notes"] = random.choice(["none", "penicillin", "peanuts", "latex", "none"])
    r["visit_type"] = random.choice(VISIT_TYPES)
    # some healthcare rows are missing identifiers (edge case)
    if random.random() < 0.20:
        r["owner_ssn_like"] = ""
    if random.random() < 0.15:
        r["owner_email"] = ""
    return r


def generate(path):
    rows = []
    for i in range(1, N_IOT + 1):
        rows.append(gen_iot_row(i))
    for i in range(1, N_HEALTH + 1):
        rows.append(gen_health_row(N_IOT + i))
    random.shuffle(rows)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {len(rows)} rows -> {path}")


if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "combined_dataset.csv")
    generate(out_path)
