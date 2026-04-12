"""
============================================================
Script khám phá dữ liệu AIT-ADS
Đồ án tốt nghiệp: Nâng cao hiệu quả tổng hợp cảnh báo
============================================================
Mục đích:
  1. Thống kê tổng quan (số alert, phân bố theo scenario/nguồn)
  2. Liệt kê tất cả trường (key) và phân loại kiểu dữ liệu
  3. Phân tích chuyên sâu các trường chuỗi — tìm ứng viên
     cho cải tiến alert_sim++
  4. Xuất biểu đồ để đưa vào báo cáo

Lưu ý: File Wazuh rất lớn (~500MB mỗi scenario), script đọc
từng dòng để không tràn RAM.
============================================================
"""

import json
import os
import csv
from collections import Counter, defaultdict
from datetime import datetime

# =============================================================
# CẤU HÌNH — Chỉnh đường dẫn nếu cần
# =============================================================
DATA_DIR = "data"  # Thư mục chứa file JSON và labels.csv
OUTPUT_DIR = "explore_output"

# Danh sách 8 scenario
SCENARIOS = [
    "fox", "harrison", "russellmitchell", "santos",
    "shaw", "wardbeck", "wheeler", "wilson"
]

MAX_ALERTS_PER_FILE = None

# =============================================================
# HÀM TIỆN ÍCH
# =============================================================

def ensure_dir(path):
    """Tạo thư mục nếu chưa có"""
    os.makedirs(path, exist_ok=True)


def flatten_keys(obj, prefix=""):
    """
    Trải phẳng dict lồng nhau thành danh sách key dạng "a.b.c"
    Ví dụ: {"rule": {"id": "123"}} → ["rule.id"]
    """
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                keys.extend(flatten_keys(v, new_key))
            elif isinstance(v, list):
                keys.append(new_key)
                # Nếu list chứa dict, đệ quy vào phần tử đầu
                if v and isinstance(v[0], dict):
                    keys.extend(flatten_keys(v[0], f"{new_key}[]"))
            else:
                keys.append(new_key)
    return keys


def get_leaf_values(obj, prefix=""):
    """
    Trích xuất tất cả giá trị lá (không phải dict/list)
    Trả về dict: {"a.b.c": giá_trị}
    """
    values = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                values.update(get_leaf_values(v, new_key))
            elif isinstance(v, list):
                # Gộp list thành chuỗi để phân tích
                if v and not isinstance(v[0], dict):
                    values[new_key] = str(v)
                elif v and isinstance(v[0], dict):
                    for item in v:
                        values.update(get_leaf_values(item, f"{new_key}[]"))
            else:
                values[new_key] = v
    return values


def classify_value(val):
    """Phân loại kiểu dữ liệu của một giá trị"""
    if val is None:
        return "null"
    elif isinstance(val, bool):
        return "boolean"
    elif isinstance(val, (int, float)):
        return "number"
    elif isinstance(val, str):
        if len(val) <= 20:
            return "string_short"
        else:
            return "string_long"
    elif isinstance(val, list):
        return "list"
    elif isinstance(val, dict):
        return "dict"
    else:
        return "other"


def read_json_lines(filepath, max_lines=None):
    """
    Đọc file JSON Lines từng dòng (tiết kiệm RAM)
    Mỗi dòng là một JSON object
    """
    count = 0
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                yield alert
                count += 1
                if max_lines and count >= max_lines:
                    break
            except json.JSONDecodeError:
                continue


# =============================================================
# PHẦN 1: THỐNG KÊ TỔNG QUAN
# =============================================================

def count_alerts():
    """Đếm số alert theo scenario và nguồn"""
    print("\n" + "=" * 60)
    print("PHẦN 1: THỐNG KÊ TỔNG QUAN")
    print("=" * 60)

    results = {}
    total_aminer = 0
    total_wazuh = 0

    for scenario in SCENARIOS:
        aminer_file = os.path.join(DATA_DIR, f"{scenario}_aminer.json")
        wazuh_file = os.path.join(DATA_DIR, f"{scenario}_wazuh.json")

        # Đếm dòng = đếm alert (JSON Lines format)
        aminer_count = 0
        if os.path.exists(aminer_file):
            with open(aminer_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        aminer_count += 1

        wazuh_count = 0
        if os.path.exists(wazuh_file):
            with open(wazuh_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        wazuh_count += 1

        total = aminer_count + wazuh_count
        results[scenario] = {
            "aminer": aminer_count,
            "wazuh": wazuh_count,
            "total": total
        }
        total_aminer += aminer_count
        total_wazuh += wazuh_count

        print(f"  {scenario:20s} | AMiner: {aminer_count:>8,} | "
              f"Wazuh+Suricata: {wazuh_count:>10,} | "
              f"Tổng: {total:>10,}")

    grand_total = total_aminer + total_wazuh
    print(f"  {'TỔNG CỘNG':20s} | AMiner: {total_aminer:>8,} | "
          f"Wazuh+Suricata: {total_wazuh:>10,} | "
          f"Tổng: {grand_total:>10,}")

    return results


# =============================================================
# PHẦN 2: PHÂN TÍCH CẤU TRÚC TRƯỜNG (KEY)
# =============================================================

def analyze_fields(source_name, filepath, sample_size=5000):
    """
    Phân tích cấu trúc trường từ một file alert
    - Liệt kê tất cả key (trải phẳng)
    - Phân loại kiểu dữ liệu
    - Đếm tần suất xuất hiện
    """
    print(f"\n  Đang phân tích {source_name} từ {os.path.basename(filepath)}...")

    key_counter = Counter()       # Đếm key xuất hiện bao nhiêu alert
    key_types = defaultdict(Counter)  # Kiểu dữ liệu của mỗi key
    key_samples = defaultdict(list)   # Giá trị mẫu
    total = 0

    for alert in read_json_lines(filepath, max_lines=sample_size):
        total += 1
        leaves = get_leaf_values(alert)
        for key, val in leaves.items():
            key_counter[key] += 1
            vtype = classify_value(val)
            key_types[key][vtype] += 1
            # Lưu tối đa 5 giá trị mẫu unique
            if len(key_samples[key]) < 5:
                val_str = str(val)[:100]  # Cắt ngắn để hiển thị
                if val_str not in key_samples[key]:
                    key_samples[key].append(val_str)

    print(f"    Đã đọc {total:,} alert, tìm thấy {len(key_counter)} trường unique")

    return {
        "total_alerts": total,
        "key_counter": key_counter,
        "key_types": key_types,
        "key_samples": key_samples
    }


def print_field_summary(analysis, source_name):
    """In bảng tóm tắt trường"""
    print(f"\n  --- Bảng trường cho {source_name} ---")
    print(f"  {'Trường':<45s} | {'Tần suất':>8s} | {'Kiểu chính':<15s} | Mẫu")
    print(f"  {'-'*45}-+-{'-'*8}-+-{'-'*15}-+-{'-'*40}")

    total = analysis["total_alerts"]
    sorted_keys = sorted(analysis["key_counter"].items(),
                         key=lambda x: -x[1])

    for key, count in sorted_keys:
        # Kiểu phổ biến nhất
        main_type = analysis["key_types"][key].most_common(1)[0][0]
        # Mẫu đầu tiên
        sample = analysis["key_samples"][key][0] if analysis["key_samples"][key] else ""
        sample = sample[:40]  # Cắt ngắn

        pct = count / total * 100
        print(f"  {key:<45s} | {pct:>7.1f}% | {main_type:<15s} | {sample}")


# =============================================================
# PHẦN 3: PHÂN TÍCH SÂU TRƯỜNG CHUỖI
# (Đây là phần QUAN TRỌNG NHẤT cho đề tài alert_sim++)
# =============================================================

def analyze_string_fields(source_name, filepath, sample_size=10000):
    """
    Phân tích chuyên sâu các trường kiểu chuỗi:
    - Phân phối độ dài
    - Số giá trị unique
    - Top giá trị phổ biến
    - Đánh giá tiềm năng cho string similarity
    """
    print(f"\n  Đang phân tích chuỗi từ {source_name}...")

    # Thu thập giá trị chuỗi theo key
    string_data = defaultdict(list)
    total = 0

    for alert in read_json_lines(filepath, max_lines=sample_size):
        total += 1
        leaves = get_leaf_values(alert)
        for key, val in leaves.items():
            if isinstance(val, str) and len(val) > 5:
                string_data[key].append(val)

    print(f"    Đã đọc {total:,} alert")

    # Phân tích từng trường chuỗi
    results = []
    for key, values in string_data.items():
        if len(values) < 10:  # Bỏ qua trường quá hiếm
            continue

        lengths = [len(v) for v in values]
        unique_vals = set(values)
        unique_count = len(unique_vals)
        total_count = len(values)
        unique_ratio = unique_count / total_count

        # Top 5 giá trị phổ biến nhất
        val_counter = Counter(values)
        top5 = val_counter.most_common(5)

        avg_len = sum(lengths) / len(lengths)
        min_len = min(lengths)
        max_len = max(lengths)

        results.append({
            "key": key,
            "count": total_count,
            "unique": unique_count,
            "unique_ratio": unique_ratio,
            "avg_len": avg_len,
            "min_len": min_len,
            "max_len": max_len,
            "top5": top5,
            "is_candidate": (
                avg_len > 20 and
                unique_ratio > 0.05 and
                unique_count > 5
            )
        })

    # Sắp xếp: ứng viên lên đầu, theo avg_len giảm dần
    results.sort(key=lambda x: (-x["is_candidate"], -x["avg_len"]))

    return results


def print_string_analysis(results, source_name):
    """In kết quả phân tích chuỗi"""
    print(f"\n  {'='*60}")
    print(f"  TRƯỜNG CHUỖI — {source_name}")
    print(f"  {'='*60}")

    candidates = [r for r in results if r["is_candidate"]]
    non_candidates = [r for r in results if not r["is_candidate"]]

    if candidates:
        print(f"\n  *** ỨNG VIÊN CHO ALERT_SIM++ ({len(candidates)} trường) ***")
        print(f"  (Tiêu chí: độ dài TB > 20, tỉ lệ unique > 5%, "
              f"số unique > 5)")
        print()

        for r in candidates:
            print(f"  [{r['key']}]")
            print(f"    Số giá trị: {r['count']:,} | "
                  f"Unique: {r['unique']:,} ({r['unique_ratio']:.1%}) | "
                  f"Độ dài: {r['min_len']}–{r['max_len']} "
                  f"(TB: {r['avg_len']:.0f})")
            print(f"    Top 5 phổ biến nhất:")
            for val, cnt in r["top5"]:
                val_display = val[:80] + "..." if len(val) > 80 else val
                print(f"      ({cnt:>5,}x) {val_display}")
            print()

    if non_candidates:
        print(f"\n  Trường chuỗi KHÔNG phù hợp ({len(non_candidates)}):")
        for r in non_candidates[:10]:  # Chỉ hiện 10 đầu
            print(f"    {r['key']:<40s} | unique_ratio={r['unique_ratio']:.1%} "
                  f"| avg_len={r['avg_len']:.0f}")

    return candidates


# =============================================================
# PHẦN 4: PHÂN TÍCH LABELS
# =============================================================

def analyze_labels():
    """Phân tích file labels.csv"""
    print("\n" + "=" * 60)
    print("PHẦN 4: PHÂN TÍCH LABELS")
    print("=" * 60)

    labels_file = os.path.join(DATA_DIR, "labels.csv")
    attacks_per_scenario = defaultdict(list)
    all_attacks = set()

    with open(labels_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            scenario = row["scenario"]
            attack = row["attack"]
            start = float(row["start"])
            end = float(row["end"])
            duration = end - start

            attacks_per_scenario[scenario].append({
                "attack": attack,
                "start": datetime.fromtimestamp(start),
                "end": datetime.fromtimestamp(end),
                "duration_sec": duration
            })
            all_attacks.add(attack)

    print(f"\n  Số scenario: {len(attacks_per_scenario)}")
    print(f"  Các loại attack phase: {sorted(all_attacks)}")
    print()

    for scenario, attacks in sorted(attacks_per_scenario.items()):
        print(f"  [{scenario}]")
        for a in attacks:
            mins = a["duration_sec"] / 60
            print(f"    {a['attack']:<25s} | "
                  f"{a['start'].strftime('%Y-%m-%d %H:%M')} → "
                  f"{a['end'].strftime('%Y-%m-%d %H:%M')} "
                  f"({mins:.1f} phút)")
        print()


# =============================================================
# PHẦN 5: TẠO BIỂU ĐỒ
# =============================================================

def create_charts(alert_counts):
    """Tạo biểu đồ tổng quan"""
    try:
        import matplotlib
        matplotlib.use("Agg")  # Không cần GUI
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n  [CẢNH BÁO] Chưa cài matplotlib. Chạy: pip install matplotlib")
        print("  Bỏ qua phần tạo biểu đồ.")
        return

    ensure_dir(OUTPUT_DIR)
    plt.rcParams["font.size"] = 11

    # --- Biểu đồ 1: Số alert theo scenario ---
    fig, ax = plt.subplots(figsize=(12, 6))
    scenarios = list(alert_counts.keys())
    aminer_vals = [alert_counts[s]["aminer"] for s in scenarios]
    wazuh_vals = [alert_counts[s]["wazuh"] for s in scenarios]

    x = range(len(scenarios))
    width = 0.35
    bars1 = ax.bar([i - width/2 for i in x], aminer_vals, width,
                   label="AMiner", color="#2196F3")
    bars2 = ax.bar([i + width/2 for i in x], wazuh_vals, width,
                   label="Wazuh + Suricata", color="#FF9800")

    ax.set_xlabel("Scenario")
    ax.set_ylabel("Number of Alerts")
    ax.set_title("AIT-ADS: Alert Distribution by Scenario and Source")
    ax.set_xticks(list(x))
    ax.set_xticklabels(scenarios, rotation=30, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    # Thêm số trên mỗi cột
    for bar in bars2:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f"{int(height):,}", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    chart_path = os.path.join(OUTPUT_DIR, "chart1_alerts_by_scenario.png")
    plt.savefig(chart_path, dpi=150)
    plt.close()
    print(f"  Đã lưu: {chart_path}")

    # --- Biểu đồ 2: Tỉ lệ nguồn alert (pie) ---
    fig, ax = plt.subplots(figsize=(8, 6))
    total_aminer = sum(alert_counts[s]["aminer"] for s in scenarios)
    total_wazuh = sum(alert_counts[s]["wazuh"] for s in scenarios)

    ax.pie(
        [total_aminer, total_wazuh],
        labels=[f"AMiner\n({total_aminer:,})",
                f"Wazuh + Suricata\n({total_wazuh:,})"],
        autopct="%1.1f%%",
        colors=["#2196F3", "#FF9800"],
        startangle=90
    )
    ax.set_title("AIT-ADS: Alert Source Distribution")

    plt.tight_layout()
    chart_path = os.path.join(OUTPUT_DIR, "chart2_source_distribution.png")
    plt.savefig(chart_path, dpi=150)
    plt.close()
    print(f"  Đã lưu: {chart_path}")


# =============================================================
# PHẦN 6: LƯU KẾT QUẢ RA FILE
# =============================================================

def save_results(alert_counts, aminer_analysis, wazuh_analysis,
                 aminer_strings, wazuh_strings):
    """Lưu toàn bộ kết quả ra file text"""
    ensure_dir(OUTPUT_DIR)
    report_path = os.path.join(OUTPUT_DIR, "exploration_report.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("BÁO CÁO KHÁM PHÁ DỮ LIỆU AIT-ADS\n")
        f.write(f"Ngày tạo: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write("=" * 70 + "\n\n")

        # Thống kê tổng quan
        f.write("1. THỐNG KÊ TỔNG QUAN\n")
        f.write("-" * 40 + "\n")
        for scenario, counts in alert_counts.items():
            f.write(f"  {scenario}: AMiner={counts['aminer']:,} | "
                    f"Wazuh={counts['wazuh']:,} | "
                    f"Tổng={counts['total']:,}\n")
        f.write("\n")

        # Trường AMiner
        f.write("2. CẤU TRÚC TRƯỜNG - AMINER\n")
        f.write("-" * 40 + "\n")
        for key, count in sorted(aminer_analysis["key_counter"].items(),
                                  key=lambda x: -x[1]):
            main_type = aminer_analysis["key_types"][key].most_common(1)[0][0]
            pct = count / aminer_analysis["total_alerts"] * 100
            f.write(f"  {key}: {pct:.1f}% | {main_type}\n")
        f.write("\n")

        # Trường Wazuh
        f.write("3. CẤU TRÚC TRƯỜNG - WAZUH\n")
        f.write("-" * 40 + "\n")
        for key, count in sorted(wazuh_analysis["key_counter"].items(),
                                  key=lambda x: -x[1]):
            main_type = wazuh_analysis["key_types"][key].most_common(1)[0][0]
            pct = count / wazuh_analysis["total_alerts"] * 100
            f.write(f"  {key}: {pct:.1f}% | {main_type}\n")
        f.write("\n")

        # Ứng viên chuỗi
        f.write("4. ỨNG VIÊN TRƯỜNG CHUỖI CHO ALERT_SIM++\n")
        f.write("-" * 40 + "\n")
        f.write("\n  AMiner:\n")
        for c in aminer_strings:
            f.write(f"    {c['key']}: unique={c['unique']}, "
                    f"ratio={c['unique_ratio']:.1%}, "
                    f"avg_len={c['avg_len']:.0f}\n")
        f.write("\n  Wazuh:\n")
        for c in wazuh_strings:
            f.write(f"    {c['key']}: unique={c['unique']}, "
                    f"ratio={c['unique_ratio']:.1%}, "
                    f"avg_len={c['avg_len']:.0f}\n")

    print(f"\n  Đã lưu báo cáo: {report_path}")


# =============================================================
# CHƯƠNG TRÌNH CHÍNH
# =============================================================

def main():
    print("╔════════════════════════════════════════════════════╗")
    print("║  KHÁM PHÁ DỮ LIỆU AIT-ADS                       ║")
    print("║  Đồ án: Nâng cao hiệu quả tổng hợp cảnh báo     ║")
    print("╚════════════════════════════════════════════════════╝")

    if MAX_ALERTS_PER_FILE:
        print(f"\n[CHẾ ĐỘ THỬ NGHIỆM] Chỉ đọc {MAX_ALERTS_PER_FILE:,} "
              f"alert/file. Đặt MAX_ALERTS_PER_FILE = None để đọc hết.")

    # --- Phần 1: Đếm alert ---
    alert_counts = count_alerts()

    # --- Phần 2: Phân tích cấu trúc trường ---
    # Chỉ phân tích 1 scenario mẫu (fox) để nhanh
    # Cấu trúc giống nhau giữa các scenario
    print("\n" + "=" * 60)
    print("PHẦN 2: PHÂN TÍCH CẤU TRÚC TRƯỜNG (mẫu: fox)")
    print("=" * 60)

    aminer_file = os.path.join(DATA_DIR, "fox_aminer.json")
    wazuh_file = os.path.join(DATA_DIR, "fox_wazuh.json")

    sample = MAX_ALERTS_PER_FILE or 5000
    aminer_analysis = analyze_fields("AMiner", aminer_file, sample_size=sample)
    print_field_summary(aminer_analysis, "AMiner")

    wazuh_analysis = analyze_fields("Wazuh", wazuh_file, sample_size=sample)
    print_field_summary(wazuh_analysis, "Wazuh + Suricata")

    # --- Phần 3: Phân tích chuỗi chuyên sâu ---
    print("\n" + "=" * 60)
    print("PHẦN 3: PHÂN TÍCH CHUỖI — TÌM ỨNG VIÊN CHO ALERT_SIM++")
    print("=" * 60)

    sample_str = MAX_ALERTS_PER_FILE or 10000
    aminer_str_results = analyze_string_fields(
        "AMiner", aminer_file, sample_size=sample_str)
    aminer_candidates = print_string_analysis(aminer_str_results, "AMiner")

    wazuh_str_results = analyze_string_fields(
        "Wazuh", wazuh_file, sample_size=sample_str)
    wazuh_candidates = print_string_analysis(wazuh_str_results, "Wazuh")

    # --- Phần 4: Labels ---
    analyze_labels()

    # --- Phần 5: Biểu đồ ---
    print("\n" + "=" * 60)
    print("PHẦN 5: TẠO BIỂU ĐỒ")
    print("=" * 60)
    create_charts(alert_counts)

    # --- Phần 6: Lưu kết quả ---
    print("\n" + "=" * 60)
    print("PHẦN 6: LƯU KẾT QUẢ")
    print("=" * 60)
    save_results(
        alert_counts, aminer_analysis, wazuh_analysis,
        aminer_candidates or [], wazuh_candidates or []
    )

    # --- Tóm tắt cuối ---
    print("\n" + "=" * 60)
    print("HOÀN TẤT! Kiểm tra thư mục:", OUTPUT_DIR)
    print("=" * 60)
    print("Các file đã tạo:")
    if os.path.exists(OUTPUT_DIR):
        for f_name in os.listdir(OUTPUT_DIR):
            size = os.path.getsize(os.path.join(OUTPUT_DIR, f_name))
            print(f"  {f_name} ({size:,} bytes)")


if __name__ == "__main__":
    main()
