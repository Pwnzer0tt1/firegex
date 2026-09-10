import sys

import matplotlib.pyplot as plt
import numpy as np
import csv
from matplotlib.ticker import MaxNLocator
from matplotlib import cm

plt.style.use("fivethirtyeight")
colors = cm.Set1.colors  # Use a different strong color palette
plt.rcParams["figure.facecolor"] = "white"
plt.rcParams["axes.edgecolor"] = "white"
plt.rcParams["axes.linewidth"] = 1.5
plt.rcParams["legend.facecolor"] = "white"

def line_chart(files, output, title, ystep=300, ylim_to_data=False):
    """One throughput-against-pattern-count chart.

    `files` is a list of `(label, csv)`, or `(label, csv, style)` where `style` is passed
    to `plot` — that is how a line that is not the same *kind* of measurement as the
    others says so.

    Every chart on this page is the same plot of the same measurement, so they are drawn
    by one function: a second copy of the styling is a second chart that can disagree
    with the first about what a line means.
    """
    series = []
    for entry in files:
        label, file = entry[0], entry[1]
        style = entry[2] if len(entry) > 2 else {}
        with open(file, "r") as csvfile:
            series.append((label, [list(map(float, row)) for row in csv.reader(csvfile)], style))

    # fivethirtyeight cycles six colours. Past that, two lines get the same one and the
    # legend quietly stops being a legend — so take a longer palette when there are more
    # series than colours rather than finding out by looking at the picture.
    cycle = plt.rcParams["axes.prop_cycle"].by_key().get("color", [])
    palette = cycle if len(series) <= len(cycle) else [
        cm.tab10(i / 10) for i in range(len(series))
    ]

    fig, ax = plt.subplots()
    ax.set_facecolor("white")
    for i, (label, data, style) in enumerate(series):
        ax.plot([int(d[0]) for d in data], [d[1] for d in data], label=label,
                color=palette[i % len(palette)], **style)
    data_dict = {label: data for label, data, _ in series}

    ax.set_xlabel("N. of regex", fontname="Roboto", fontsize=12)
    ax.set_ylabel("Throughput [MB/s]", fontname="Roboto", fontsize=12)
    ax.legend(
        title_fontsize=12, loc="upper center", bbox_to_anchor=(0.5, -0.1),
        frameon=True, shadow=True, borderpad=1, fontsize=10, fancybox=True,
        ncol=min(len(data_dict), 4),
    )
    widest = max(len(d) for d in data_dict.values())
    ax.set_xticks(np.arange(0, widest, step=3))
    if ylim_to_data:
        ys = [d[1] for data in data_dict.values() for d in data]
        pad = (max(ys) - min(ys)) * 0.1
        ax.set_ylim(min(ys) - pad, max(ys) + pad)
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    else:
        ax.set_yticks(np.arange(0, max(d[1] for data in data_dict.values() for d in data), step=ystep))
    plt.subplots_adjust(bottom=0.2)
    ax.set_title(title, fontweight="bold", fontname="Roboto", pad=20)
    fig.set_size_inches(12, 8)
    plt.savefig(output, dpi=300, bbox_inches="tight")
    plt.close()


# --- measured on the current machine, all in one sitting ---------------------
# These are the only lines on this page that may be read against each other. Every one of
# them was produced by the same command on the same host on the same day, with the filter
# in the path for every packet (`fail_open=False`), which is what makes the comparison a
# comparison of firegex rather than of two Linux kernels.
#
# One pass per version — the better of two where two were taken. Repeating a pass without
# restarting the instance lands within ~3%; repeating it across a restart moved by up to
# ~30%, which is wider than the gaps between the NFQUEUE versions. Read the charts for the
# shape (flat in the number of patterns) and the tables in the README for the levels; they
# do not support ranking one version above another. The gap between the two *layers* is
# several times that uncertainty, and is a result.
#
# Split by thread count rather than drawn together. Seven lines on one pair of axes, where
# the thread count moved a line as much as the version did, was a chart you had to decode
# instead of read; one chart per thread count answers "which version" without also asking
# "at how many threads".
for threads in ("1T", "8T"):
    line_chart(
        [
            (f"3.5.3 NFQUEUE {threads}", f"results/3.5.3-{threads}.csv"),
            (f"4.0.5 NFQUEUE {threads}", f"results/4.0.5-{threads}.csv"),
            (f"5.0.0 NFQUEUE {threads}", f"results/5.0.0-nfqueue-{threads}.csv"),
            # Dashed, because it is the other network layer rather than another version:
            # the same filter and the same traffic, put in the path a different way.
            (f"5.0.0 Proxy {threads}", f"results/5.0.0-proxy-{threads}.csv",
             {"linestyle": "--"}),
        ],
        f"results/Benchmark-{threads}.svg",
        f"Firegex — regex filter, {'one thread' if threads == '1T' else 'eight threads'}",
        ystep=1000,
    )

# --- archived, from 2025 -----------------------------------------------------
# Everything below regenerates the charts that were committed with the numbers they were
# measured from. They are kept as they were written, and behind a flag: matplotlib has
# moved on since, so simply running this script used to rewrite six committed SVGs with
# re-renders in a different font — a diff nobody asked for, in files nobody had new data
# for. Pass --archived to redraw them on purpose.
if "--archived" not in sys.argv:
    print("current charts written. Pass --archived to also redraw the 2025 ones.")
    raise SystemExit(0)

files = [
    ("2.5.1 1T", "results/2.5.1-1T.csv"),
    ("2.5.1 8T", "results/2.5.1-8T.csv"),
    ("2.3.3 1T", "results/2.3.3-1T.csv"),
    ("2.3.3 8T", "results/2.3.3-8T.csv"),
    ("2.4.0 1T", "results/2.4.0-1T.csv"),
    ("2.4.0 8T", "results/2.4.0-8T.csv"),
]

output = "results/Benchmark-chart.svg"

data_dict = {}

for label, file in files:
    with open(file, "r") as csvfile:
        reader = csv.reader(csvfile)
        data = [list(map(float, row)) for row in reader]
        data_dict[label] = data

fig, ax = plt.subplots()
ax.set_facecolor("white")

for label in data_dict.keys():
    data = data_dict[label]
    ax.plot(
        list(map(lambda d: int(d[0]), data)),
        list(map(lambda d: d[1], data)),
        label=label,
    )

ax.set_xlabel("N. of regex", fontname="Roboto", fontsize=12)
ax.set_ylabel("Throughput [MB/s]", fontname="Roboto", fontsize=12)
ax.legend(prop={"family": "Roboto", "size": 10})
ax.legend(
    title_fontsize=12,
    loc="upper center",
    bbox_to_anchor=(0.5, -0.1),
    frameon=True,
    shadow=True,
    borderpad=1,
    fontsize=10,
    fancybox=True,
    ncol=len(data_dict.keys()),  # Make the legend horizontal
)
ax.set_xticks(np.arange(0, max(map(lambda d: int(d[0]), data)), step=3))
ax.set_yticks(np.arange(0, max(map(lambda d: d[1], data)), step=300))
plt.subplots_adjust(bottom=0.2)  # Adjust the bottom margin to make space for the legend
ax.set_title("Firegex benchmark (nfregex)", fontweight="bold", fontname="Roboto", pad=20)
fig.set_size_inches(12, 8)  # Set the figure size to make the image larger

# plt.show()
plt.savefig(output, dpi=300, bbox_inches="tight")
plt.close()

files = [
    ("2.5.1 1T", "results/2.5.1-1T-withload.csv"),
    ("2.5.1 8T", "results/2.5.1-8T-withload.csv"),
]

output = "results/Benchmark-chart-with-load.svg"

data_dict = {}

for label, file in files:
    with open(file, "r") as csvfile:
        reader = csv.reader(csvfile)
        data = [list(map(float, row)) for row in reader]
        data_dict[label] = data

fig, ax = plt.subplots()
ax.set_facecolor("white")

for label in data_dict.keys():
    data = data_dict[label]
    ax.plot(
        list(map(lambda d: int(d[0]), data)),
        list(map(lambda d: d[1], data)),
        label=label,
    )

ax.set_xlabel("N. of regex", fontname="Roboto", fontsize=12)
ax.set_ylabel("Throughput [MB/s]", fontname="Roboto", fontsize=12)
ax.legend(prop={"family": "Roboto", "size": 10})
ax.legend(
    title_fontsize=12,
    loc="upper center",
    bbox_to_anchor=(0.5, -0.1),
    frameon=True,
    shadow=True,
    borderpad=1,
    fontsize=10,
    fancybox=True,
    ncol=len(data_dict.keys()),
)
ax.set_xticks(np.arange(0, max(map(lambda d: int(d[0]), data)), step=3))
ax.set_yticks(np.arange(0, max(map(lambda d: d[1], data)), step=150))
plt.subplots_adjust(bottom=0.2)
ax.set_title("Load test firegex (nfregex)", fontweight="bold", fontname="Roboto", pad=20)
fig.set_size_inches(12, 8)

# Calculate the minimum and maximum y values across all data
all_y_values = [d[1] for data in data_dict.values() for d in data]
y_min, y_max = min(all_y_values), max(all_y_values)

# Set the y-axis limits to skip unused parts
ax.set_ylim(y_min - (y_max - y_min) * 0.1, y_max + (y_max - y_min) * 0.1)

# Ensure y-ticks are integers if applicable
ax.yaxis.set_major_locator(MaxNLocator(integer=True))

# plt.show()
plt.savefig(output, dpi=300, bbox_inches="tight")
plt.close()

files_nfproxy = [
    ("NfProxy 1T", "results/comparemark_nfproxy_1T.csv"),
    ("NfProxy 8T", "results/comparemark_nfproxy_8T.csv"),
]

output_whisker = "results/whisker_nfproxy.svg"
output_histogram = "results/istogramma_nfproxy.svg"

# Read and process data for nfproxy
data_nfproxy = {}
for label, file in files_nfproxy:
    with open(file, "r") as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header
        data = [(float(row[0]), float(row[1])) for row in reader]
        data_nfproxy[label + " no filter"] = [ele[0] for ele in data]
        data_nfproxy[label + " test"] = [ele[1] for ele in data]

# Generate whisker plot for nfproxy
fig, ax = plt.subplots()
ax.set_facecolor("white")

y_max = max([max(data) for data in data_nfproxy.values()])
y_min = min([min(data) for data in data_nfproxy.values()])

for i, (label, data) in enumerate(data_nfproxy.items()):
    ax.boxplot(
        data,
        positions=[list(data_nfproxy.keys()).index(label)],
        tick_labels=[label],
        boxprops=dict(color="black", facecolor=colors[i % len(colors)], linewidth=1.3),
        whiskerprops=dict(color="black", linewidth=1.3),
        capprops=dict(color="black", linewidth=1.3),
        medianprops=dict(color="black", linewidth=1.3),
        patch_artist=True,  # Enable filling the box with color
        widths=0.35,  # Increase the width of the boxes
    )

ax.set_yticks(
    np.arange(0, int(y_max) + 100, step=100)
)  # Ensure the range includes y_max

# Set the y-axis limits to skip unused parts
ax.set_ylim(y_min - (y_max - y_min) * 0.1, y_max + (y_max - y_min) * 0.1)

ax.set_title("NFProxy Benchmarks", fontweight="bold", fontname="Roboto", pad=20)
ax.set_ylabel("Throughput [MB/s]", fontname="Roboto", fontsize=12)
fig.set_size_inches(12, 8)

# plt.show()
plt.savefig(output_whisker, dpi=300)
plt.close()

# Generate bar chart with average data for nfproxy
average_data = {label: np.mean(data) for label, data in data_nfproxy.items()}

fig, ax = plt.subplots()
ax.set_facecolor("white")
y_max = max(average_data.values())

bars = ax.bar(
    average_data.keys(),
    average_data.values(),
    color=[colors[i % len(colors)] for i in range(len(average_data))],
    edgecolor="black",
    width=0.4,  # Make the bars narrower
)

ax.set_yticks(
    np.arange(0, int(y_max) + 100, step=100)
)  # Ensure the range includes y_max
ax.set_title("NFProxy Benchmarks", fontweight="bold", fontname="Roboto", pad=20)
ax.set_ylabel("Average Throughput [MB/s]", fontname="Roboto", fontsize=12)
ax.set_xticklabels(average_data.keys(), fontname="Roboto", fontsize=12)

# Annotate bars with their values
for bar in bars:
    height = bar.get_height()
    ax.annotate(
        f"{height:.2f}",
        xy=(bar.get_x() + bar.get_width() / 2, height),
        xytext=(0, 3),  # Offset text above the bar
        textcoords="offset points",
        ha="center",
        va="bottom",
        fontsize=10,
        fontname="Roboto",
    )

fig.set_size_inches(12, 8)
plt.tight_layout()

# plt.show()
plt.savefig(output_histogram, dpi=300, bbox_inches="tight")
plt.close()

files_nfregex = [
    ("NfRegex 1T", "results/comparemark_nfregex_1T.csv"),
    ("NfRegex 8T", "results/comparemark_nfregex_8T.csv"),
]

output_whisker = "results/whisker_compare.svg"
output_histogram = "results/istrogramma_compare.svg"

# Read and process data for nfregex
data_nfregex = {}
for label, file in files_nfregex:
    with open(file, "r") as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header
        data = [(float(row[0]), float(row[1])) for row in reader]
        data_nfregex[label + " no filter"] = [ele[0] for ele in data]
        data_nfregex[label + " test"] = [ele[1] for ele in data]

# Combine nfproxy and nfregex data
combined_data = {**data_nfproxy, **data_nfregex}

# Generate whisker plot for combined data
fig, ax = plt.subplots()
ax.set_facecolor("white")

y_max = max([max(data) for data in combined_data.values()])
y_min = min([min(data) for data in combined_data.values()])

for i, (label, data) in enumerate(combined_data.items()):
    ax.boxplot(
        data,
        positions=[list(combined_data.keys()).index(label)],
        boxprops=dict(color="black", facecolor=colors[i % len(colors)], linewidth=1.3),
        whiskerprops=dict(color="black", linewidth=1.3),
        capprops=dict(color="black", linewidth=1.3),
        medianprops=dict(color="black", linewidth=1.3),
        patch_artist=True,  # Enable filling the box with color
        widths=0.6,  # Increase the width of the boxes
    )

ax.set_xticks(range(len(combined_data.keys())))
ax.set_xticklabels(combined_data.keys(), fontname="Roboto", fontsize=10)
ax.set_yticks(
    np.arange(0, int(y_max) + 100, step=250)
)  # Ensure the range includes y_max
plt.subplots_adjust(bottom=0.12)

# Set the y-axis limits to skip unused parts
ax.set_ylim(y_min - (y_max - y_min) * 0.1, y_max + (y_max - y_min) * 0.1)

ax.set_title(
    "Combined Benchmarks (NFProxy vs NFRegex)",
    fontweight="bold",
    fontname="Roboto",
    pad=20,
)
ax.set_ylabel("Throughput [MB/s]", fontname="Roboto", fontsize=12)
fig.set_size_inches(14, 8)

# plt.show()
plt.savefig(output_whisker, dpi=300, bbox_inches="tight")
plt.close()

# Generate bar chart with average data for combined data
average_combined_data = {label: np.mean(data) for label, data in combined_data.items()}

fig, ax = plt.subplots()
ax.set_facecolor("white")
y_max = max(average_combined_data.values())

bars = ax.bar(
    average_combined_data.keys(),
    average_combined_data.values(),
    color=[
        colors[0 if "nfregex" in ele.lower() else 1] for ele in average_combined_data
    ],
    edgecolor="black",
    width=0.4,  # Make the bars narrower
)

ax.set_xticks(range(len(average_combined_data.keys())))
ax.set_xticklabels(average_combined_data.keys(), fontname="Roboto", fontsize=10)
ax.set_yticks(
    np.arange(0, int(y_max) + 100, step=200)
)  # Ensure the range includes y_max
ax.set_title(
    "Combined Benchmarks (NFProxy vs NFRegex)",
    fontweight="bold",
    fontname="Roboto",
    pad=20,
)
ax.set_ylabel("Average Throughput [MB/s]", fontname="Roboto", fontsize=12)

# Annotate bars with their values
for bar in bars:
    height = bar.get_height()
    ax.annotate(
        f"{height:.2f}",
        xy=(bar.get_x() + bar.get_width() / 2, height),
        xytext=(0, 3),  # Offset text above the bar
        textcoords="offset points",
        ha="center",
        va="bottom",
        fontsize=10,
        fontname="Roboto",
    )

fig.set_size_inches(14, 8)
plt.tight_layout()

# plt.show()
plt.savefig(output_histogram, dpi=300, bbox_inches="tight")
plt.close()
