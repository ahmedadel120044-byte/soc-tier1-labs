import pandas as pd


def clean_logs(raw_logs: list) -> pd.DataFrame:
  if not raw_logs:
    return pd.DataFrame(
        columns=["EventID", "Timestamp", "User Name", "Workstation", "IP"]
    )

  df = pd.DataFrame(raw_logs)

  df["IP"] = df["IP"].fillna("0.0.0.0").replace("", "0.0.0.0")
  df["User Name"] = (
      df["User Name"].fillna("UNKNOWN").replace("", "UNKNOWN")
  )
  df["Workstation"] = (
      df["Workstation"].fillna("UNKNOWN").replace("", "UNKNOWN")
  )
  df["EventID"] = df["EventID"].fillna("UNKNOWN").replace("", "UNKNOWN")

  df["IP"] = df["IP"].astype(str).str.strip()

  df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
  df = df.dropna(subset=["Timestamp"])

  df = df.sort_values(by="Timestamp").reset_index(drop=True)

  return df