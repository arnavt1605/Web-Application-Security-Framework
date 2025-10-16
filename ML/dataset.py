import pandas as pd
import numpy as np

# --- Config ---
TARGET_TOTAL = 1200          # Aim for 1000–1500
RANDOM_STATE = 42
OUTPUT_PATH = "final_cleaned_downsampled_dataset.csv"

# --- Paths ---
csic_path = "csic_database.csv"     # has Method, URL, CLASS (0=benign, 1=malicious)
sqli_path = "sqli.csv"              # has Sentence, Label (mostly/all 1)
xss_path  = "XSS_dataset.csv"       # has Sentence, Label (0/1)

rng = np.random.default_rng(RANDOM_STATE)

def safe_sample(df, n, seed=RANDOM_STATE):
    if len(df) <= n:
        return df.copy()
    return df.sample(n=n, random_state=seed)

# --- CSIC ---
df_csic = pd.read_csv(csic_path)
# Standardize columns
if not {"Method","URL","CLASS"}.issubset(df_csic.columns):
    raise ValueError("CSIC CSV must contain Method, URL, CLASS columns")
df_csic = df_csic.copy()
df_csic["label"] = df_csic["CLASS"].astype(int)
df_csic["payload"] = df_csic["Method"].fillna("").astype(str) + " " + df_csic["URL"].fillna("").astype(str)
csic_benign = df_csic[df_csic["label"] == 0][["payload","label"]].dropna(subset=["payload"])
csic_mal    = df_csic[df_csic["label"] == 1][["payload","label"]].dropna(subset=["payload"])

# --- SQLi (malicious-only) ---
# Known to be UTF-16 in many public versions
df_sqli = pd.read_csv(sqli_path, encoding="utf-16")
if not {"Sentence","Label"}.issubset(df_sqli.columns):
    raise ValueError("SQLi CSV must contain Sentence, Label columns")
df_sqli = df_sqli.rename(columns={"Sentence":"payload","Label":"label"})
df_sqli["label"] = df_sqli["label"].astype(int)
sqli_mal = df_sqli[df_sqli["label"] == 1][["payload","label"]].dropna(subset=["payload"])

# --- XSS (has benign and malicious) ---
# Use utf-8-sig to handle potential BOM and unnamed index col
df_xss = pd.read_csv(xss_path, encoding="utf-8-sig")
if "Sentence" not in df_xss.columns and "payload" not in df_xss.columns:
    # If first column is unnamed (index), drop it defensively
    if df_xss.columns[0].startswith("Unnamed") or df_xss.columns[0] == "":
        df_xss = df_xss.drop(columns=[df_xss.columns[0]])
# After potential drop, ensure expected columns
if "Sentence" in df_xss.columns:
    df_xss = df_xss.rename(columns={"Sentence":"payload"})
if "Label" not in df_xss.columns or "payload" not in df_xss.columns:
    raise ValueError("XSS CSV must contain Sentence and Label columns (after BOM handling)")
df_xss["label"] = df_xss["Label"].astype(int)
xss_benign = df_xss[df_xss["label"] == 0][["payload","label"]].dropna(subset=["payload"])
xss_mal    = df_xss[df_xss["label"] == 1][["payload","label"]].dropna(subset=["payload"])

# --- Target sizing ---
# Prefer class balance and total ~ TARGET_TOTAL, with graceful fallback if data is limited.
target_per_class = TARGET_TOTAL // 2

# Benign pool: CSIC first, then optionally top-up from XSS benign if needed
benign_pool = []
take_csic_benign = min(len(csic_benign), target_per_class)
benign_pool.append(safe_sample(csic_benign, take_csic_benign, RANDOM_STATE))

remaining_benign_needed = target_per_class - take_csic_benign
if remaining_benign_needed > 0 and len(xss_benign) > 0:
    take_xss_benign = min(len(xss_benign), remaining_benign_needed)
    if take_xss_benign > 0:
        benign_pool.append(safe_sample(xss_benign, take_xss_benign, RANDOM_STATE))
        remaining_benign_needed -= take_xss_benign

# If still short on benign, reduce the target to what we actually have
actual_benign = pd.concat(benign_pool, ignore_index=True) if benign_pool else pd.DataFrame(columns=["payload","label"])
if len(actual_benign) < target_per_class:
    target_per_class = len(actual_benign)

# Malicious pool: distribute evenly across CSIC, SQLi, XSS given availability
mal_targets = {"csic": 0, "sqli": 0, "xss": 0}
avail = {"csic": len(csic_mal), "sqli": len(sqli_mal), "xss": len(xss_mal)}
# Start with equal split
base = target_per_class // 3
rem = target_per_class - 3*base
order = ["csic","sqli","xss"]
for i in range(3):
    mal_targets[order[i]] = base + (1 if i < rem else 0)

# Adjust down if a source lacks enough, and redistribute leftovers
def redistribute(mal_targets, avail):
    # First cap to availability
    leftover = 0
    for k in mal_targets:
        if mal_targets[k] > avail[k]:
            leftover += mal_targets[k] - avail[k]
            mal_targets[k] = avail[k]
    if leftover == 0:
        return mal_targets
    # Try to allocate leftover to other sources with capacity
    for k in mal_targets:
        capacity = avail[k] - mal_targets[k]
        if capacity <= 0:
            continue
        take = min(capacity, leftover)
        mal_targets[k] += take
        leftover -= take
        if leftover == 0:
            break
    # If still leftover > 0, we cannot hit target_per_class; that will be handled by final sizing
    return mal_targets

mal_targets = redistribute(mal_targets, avail)
actual_mal_requested = sum(mal_targets.values())

# If we still fall short of target_per_class malicious due to availability, shrink target_per_class to what we can provide
target_per_class = min(target_per_class, actual_mal_requested, len(actual_benign))

# Rescale malicious targets proportionally to match final target_per_class after potential shrink
if sum(mal_targets.values()) != target_per_class and sum(mal_targets.values()) > 0:
    scale = target_per_class / sum(mal_targets.values())
    # Compute provisional scaled targets and fix rounding
    scaled = {k: int(np.floor(mal_targets[k] * scale)) for k in mal_targets}
    # Distribute rounding remainder
    remainder = target_per_class - sum(scaled.values())
    # Assign remainder to sources with highest fractional part and available capacity
    fracs = sorted(
        [(k, (mal_targets[k] * scale) - scaled[k]) for k in mal_targets],
        key=lambda x: x[1],
        reverse=True
    )
    for k, _ in fracs:
        if remainder == 0:
            break
        if scaled[k] < avail[k]:
            scaled[k] += 1
            remainder -= 1
    mal_targets = scaled

# --- Sampling ---
mal_pool = []
if mal_targets["csic"] > 0:
    mal_pool.append(safe_sample(csic_mal,  mal_targets["csic"], RANDOM_STATE))
if mal_targets["sqli"] > 0:
    mal_pool.append(safe_sample(sqli_mal,  mal_targets["sqli"], RANDOM_STATE))
if mal_targets["xss"] > 0:
    mal_pool.append(safe_sample(xss_mal,   mal_targets["xss"], RANDOM_STATE))

actual_mal = pd.concat(mal_pool, ignore_index=True) if mal_pool else pd.DataFrame(columns=["payload","label"])
actual_benign = safe_sample(actual_benign, target_per_class, RANDOM_STATE)

# --- Combine, clean, shuffle ---
final_df = pd.concat([actual_benign, actual_mal], ignore_index=True)
final_df["payload"] = final_df["payload"].astype(str).str.strip()
final_df = final_df.dropna(subset=["payload"])
final_df = final_df.drop_duplicates(subset=["payload"]).sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

# If dedup dropped rows, optionally trim to <= 1500
if len(final_df) > 1500:
    final_df = final_df.sample(n=1500, random_state=RANDOM_STATE).reset_index(drop=True)

# Save
final_df.to_csv(OUTPUT_PATH, index=False)

# --- Diagnostics ---
def count_source_contrib(df):
    # Heuristic tags for source attribution
    # We only know which subset contributed by comparing to pools
    tags = []
    pools = {
        "csic_benign": set(map(tuple, csic_benign.itertuples(index=False, name=None))) if len(csic_benign) else set(),
        "csic_mal":    set(map(tuple, csic_mal.itertuples(index=False, name=None)))    if len(csic_mal) else set(),
        "sqli_mal":    set(map(tuple, sqli_mal.itertuples(index=False, name=None)))    if len(sqli_mal) else set(),
        "xss_benign":  set(map(tuple, xss_benign.itertuples(index=False, name=None)))  if len(xss_benign) else set(),
        "xss_mal":     set(map(tuple, xss_mal.itertuples(index=False, name=None)))     if len(xss_mal) else set(),
    }
    counts = {k:0 for k in pools}
    for row in df[["payload","label"]].itertuples(index=False, name=None):
        for k in pools:
            if row in pools[k]:
                counts[k] += 1
                break
    return counts

print("✅ Dataset ready.")
print("Class counts:\n", final_df["label"].value_counts(dropna=False))
print("Total rows:", len(final_df))
print("Source contributions:", count_source_contrib(final_df))
