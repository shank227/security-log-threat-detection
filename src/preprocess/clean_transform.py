#!/usr/bin/env python3
import re
import os
from datetime import datetime
import pandas as pd


# Path Setup
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RAW_DIR = os.path.join(ROOT, "data", "raw_logs")
UNSW_DIR = os.path.join(RAW_DIR, "unsw")
SSH_DIR = os.path.join(RAW_DIR, "ssh")
APACHE_DIR = os.path.join(RAW_DIR, "apache")

# Recieved Directory
PROC_DIR = os.path.join(ROOT, "data", "processed")
os.makedirs(PROC_DIR, exist_ok=True)


# Input Files
APACHE_RAW = os.path.join(APACHE_DIR, "Apache_access.log_structured.csv")
SSH_RAW = os.path.join(SSH_DIR, "OpenSSH_2k.log_structured.csv")

UNSW_TRAIN_RAW = os.path.join(UNSW_DIR, "UNSW_NB15_training-set.csv")
UNSW_TEST_RAW  = os.path.join(UNSW_DIR, "UNSW_NB15_testing-set.csv")

# Output Files
APACHE_OUT = os.path.join(PROC_DIR, "apache_clean.csv")
SSH_OUT = os.path.join(PROC_DIR, "ssh_clean.csv")

UNSW_TRAIN_OUT = os.path.join(PROC_DIR, "unsw_train_clean.csv")
UNSW_TEST_OUT  = os.path.join(PROC_DIR, "unsw_test_clean.csv")

MERGED_OUT = os.path.join(PROC_DIR, "final_merged.csv")

# Regex
IP_RE = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})')

# Helpers
def safe_read_csv(path, nrows=None):
    if not os.path.exists(path):
        print(f"[WARN] file not found: {path}")
        return None
    try:
        return pd.read_csv(path, nrows=nrows)
    except Exception as e:
        print(f"[ERROR] reading {path}: {e}")
        return None


# Clean APACHE
def clean_apache(df):
    if df is None:
        return None
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]

    # Parse timestamp: "Sun Dec 04 04:47:44 2005"
    def parse_apache_time(ts):
        try:
            return pd.to_datetime(ts, format="%a %b %d %H:%M:%S %Y")
        except:
            try:
                return pd.to_datetime(ts)
            except:
                return pd.NaT

    df["timestamp"] = df["Time"].apply(parse_apache_time)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    df["level"] = df["Level"].astype(str).str.strip().str.lower()
    df["raw_message"] = df["Content"].astype(str)

    df["source"] = "apache"
    df["ip"] = pd.NA
    df["is_login_attempt"] = 0
    df["is_success"] = pd.NA
    df["event_type"] = df["EventId"].astype(str)
    df["event_template"] = df.get("EventTemplate", pd.Series([""]*len(df))).astype(str)

    keep = ["timestamp","source","ip","event_type","level","raw_message","event_template","is_login_attempt","is_success"]
    return df[keep].copy()


# Clean SSH
def clean_ssh(df):
    if df is None:
        return None
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]

    current_year = datetime.now().year

    def build_ts(row):
        try:
            month = row.get("Date")
            day = row.get("Day")
            time = row.get("Time")
            if pd.isna(month) or pd.isna(day) or pd.isna(time):
                return pd.to_datetime(time, errors="coerce")
            date_str = f"{month} {int(day)} {current_year} {time}"
            return pd.to_datetime(date_str, format="%b %d %Y %H:%M:%S", errors="coerce")
        except:
            return pd.to_datetime(row.get("Time"), errors="coerce")

    df["timestamp"] = df.apply(build_ts, axis=1)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    df["component"] = df.get("Component", pd.Series([None]*len(df))).astype(str)
    df["pid"] = df.get("Pid", pd.NA)
    df["raw_message"] = df["Content"].astype(str)

    def extract_ip(text):
        if not isinstance(text, str):
            return pd.NA
        m = IP_RE.search(text)
        return m.group(0) if m else pd.NA

    df["ip"] = df["raw_message"].apply(extract_ip)

    text = df["raw_message"].str.lower().fillna("")
    df["is_login_attempt"] = (
        text.str.contains("invalid user") |
        text.str.contains("failed password") |
        text.str.contains("input_userauth_request")
    ).astype(int)

    df["is_success"] = (
        text.str.contains("accepted password") |
        text.str.contains("accepted publickey")
    ).astype(int)

    df["event_type"] = df.get("EventId", pd.Series([""]*len(df))).astype(str)
    df["event_template"] = df.get("EventTemplate", pd.Series([""]*len(df))).astype(str)
    
    df["source"] = "ssh"

    keep = ["timestamp","source","ip","component","pid","event_type","event_template","raw_message","is_login_attempt","is_success"]
    return df[keep].copy()


# Clean UNSW (Train or Test)
def clean_unsw(df):
    if df is None:
        return None
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]

    for c in df.columns:
        try:
            df[c] = pd.to_numeric(df[c], errors="ignore")
        except:
            pass

    if "sbytes" in df.columns and "dbytes" in df.columns:
        df["total_bytes"] = pd.to_numeric(df["sbytes"], errors="coerce").fillna(0) + pd.to_numeric(df["dbytes"], errors="coerce").fillna(0)
    else:
        df["total_bytes"] = pd.NA

    if "spkts" in df.columns and "dpkts" in df.columns:
        df["total_packets"] = pd.to_numeric(df["spkts"], errors="coerce").fillna(0) + pd.to_numeric(df["dpkts"], errors="coerce").fillna(0)
    else:
        df["total_packets"] = pd.NA

    if "label" in df.columns:
        df["label_binary"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    else:
        df["label_binary"] = df.get("attack_cat", "").apply(
            lambda x: 0 if str(x).strip().lower() in ["normal","benign"] else 1
        )

    df["event_type"] = df.get("attack_cat", pd.NA)
    df["timestamp"] = pd.NA
    df["source"] = "unsw"
    df["raw_message"] = pd.NA

    keep = ["timestamp","source","event_type","total_bytes","total_packets","raw_message","label_binary"]
    df = df[keep].copy()
    df = df.rename(columns={"label_binary":"label"})
    return df


# Main
def merge_and_align(dfs):
    dfs = [d for d in dfs if d is not None]
    if not dfs:
        return None
    all_cols = sorted(set().union(*[df.columns for df in dfs]))
    dfs = [df.reindex(columns=all_cols) for df in dfs]
    merged = pd.concat(dfs, ignore_index=True)
    return merged


# Main
def main():
    print("=== starting cleaning pipeline ===")

    print("reading Apache...")
    df_ap = safe_read_csv(APACHE_RAW)

    print("reading SSH...")
    df_ssh = safe_read_csv(SSH_RAW)

    print("reading UNSW training...")
    df_unsw_train = safe_read_csv(UNSW_TRAIN_RAW)

    print("reading UNSW testing...")
    df_unsw_test = safe_read_csv(UNSW_TEST_RAW)

    print("cleaning Apache...")
    ap_clean = clean_apache(df_ap)
    if ap_clean is not None:
        ap_clean.to_csv(APACHE_OUT, index=False)
        print(f"[OK] {APACHE_OUT}")

    print("cleaning SSH...")
    ssh_clean = clean_ssh(df_ssh)
    if ssh_clean is not None:
        ssh_clean.to_csv(SSH_OUT, index=False)
        print(f"[OK] {SSH_OUT}")

    print("cleaning UNSW TRAIN...")
    unsw_train_clean = clean_unsw(df_unsw_train)
    if unsw_train_clean is not None:
        unsw_train_clean.to_csv(UNSW_TRAIN_OUT, index=False)
        print(f"[OK] {UNSW_TRAIN_OUT}")

    print("cleaning UNSW TEST...")
    unsw_test_clean = clean_unsw(df_unsw_test)
    if unsw_test_clean is not None:
        unsw_test_clean.to_csv(UNSW_TEST_OUT, index=False)
        print(f"[OK] {UNSW_TEST_OUT}")

    print("merging Apache + SSH + UNSW TRAIN...")
    merged = merge_and_align([ap_clean, ssh_clean, unsw_train_clean])
    if merged is not None:
        merged.to_csv(MERGED_OUT, index=False)
        print(f"[OK] {MERGED_OUT}")

    print("=== cleaning pipeline finished ===")

# Main
if __name__ == "__main__":
    main()
